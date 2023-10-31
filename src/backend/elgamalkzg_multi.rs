use crate::commit::kzg::Powers;
use crate::dleq::Proof as DleqProof;
use crate::encrypt::elgamal::{Cipher, ExponentialElgamal as Elgamal};
use crate::encrypt::EncryptionEngine;
use crate::hash::Hasher;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_ff::PrimeField;
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::evaluations::univariate::Evaluations;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly_commit::DenseUVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::ops::{Add, Div, Neg, Sub};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand};
use digest::Digest;

pub struct PublicProofInput<C: Pairing> {
    evaluations: Evaluations<C::ScalarField>,
    encryptions: Vec<Cipher<C::G1>>,
    random_encryption_points: Vec<C::G1Affine>,
    domain: GeneralEvaluationDomain<C::ScalarField>,
}

impl<C: Pairing> PublicProofInput<C> {
    pub fn new<R: Rng>(
        data: Vec<C::ScalarField>,
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        rng: &mut R,
    ) -> Self {
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(data.len()).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let rands: Vec<C::ScalarField> = (0..evaluations.evals.len())
            .map(|_| C::ScalarField::rand(rng))
            .collect();
        let random_encryption_points: Vec<C::G1Affine> = rands
            .iter()
            .map(|r| (C::G1Affine::generator() * r).into_affine())
            .collect();

        let encryptions: Vec<Cipher<C::G1>> = evaluations
            .evals
            .iter()
            .zip(&rands)
            .map(|(eval, rand)| {
                <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
                    eval,
                    encryption_pk,
                    rand,
                )
            })
            .collect();

        Self {
            evaluations,
            encryptions,
            random_encryption_points,
            domain,
        }
    }

    pub fn interpolate(&self) -> DensePolynomial<C::ScalarField> {
        self.evaluations.interpolate_by_ref()
    }
}

pub struct Proof<C: Pairing, P, D> {
    challenge_eval_commitment: C::G1Affine,
    challenge_opening_proof: C::G1Affine,
    dleq_proof: DleqProof<C::G1, D>,
    _poly: PhantomData<P>,
    _digest: PhantomData<D>,
}

impl<C, P, D> Proof<C, P, D>
where
    C: Pairing,
    C::G1Affine: Neg<Output = C::G1Affine>,
    C::G2Affine: Neg<Output = C::G2Affine>,
    P: DenseUVPolynomial<C::ScalarField>,
    D: Digest,
    for<'a> &'a P: Add<&'a P, Output = P>,
    for<'a> &'a P: Sub<&'a P, Output = P>,
    for<'a> &'a P: Div<&'a P, Output = P>,
{
    pub fn new<R: Rng>(
        f_poly: &P,
        input: &PublicProofInput<C>,
        encryption_sk: &C::ScalarField,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let mut hasher = Hasher::<D>::new();
        input
            .encryptions
            .iter()
            .for_each(|enc| hasher.update(&enc.c1()));
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());
        let challenge_eval = f_poly.evaluate(&challenge);

        let d_poly = P::from_coefficients_slice(&[-challenge, C::ScalarField::one()]);
        let q_poly = &(f_poly + &P::from_coefficients_slice(&[-challenge_eval])) / &d_poly;
        let challenge_opening_proof = powers.commit_g1(&q_poly).into();
        let challenge_eval_commitment = (C::G1Affine::generator() * challenge_eval).into_affine();

        let lagrange_evaluations = input.domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 =
            Msm::msm_unchecked(&input.random_encryption_points, &lagrange_evaluations);

        let dleq_proof = DleqProof::new(
            encryption_sk,
            q_point.into_affine(),
            C::G1Affine::generator(),
            rng,
        );

        Self {
            challenge_eval_commitment,
            challenge_opening_proof,
            dleq_proof,
            _poly: PhantomData,
            _digest: PhantomData,
        }
    }

    pub fn verify(
        &self,
        com_f_poly: C::G1,
        input: &PublicProofInput<C>,
        encryption_pk: C::G1Affine,
        powers: &Powers<C>,
    ) -> bool {
        let mut hasher = Hasher::<D>::new();
        let c1_points: Vec<C::G1Affine> = input
            .encryptions
            .iter()
            .map(|enc| {
                let c1 = enc.c1();
                hasher.update(&c1);
                c1
            })
            .collect();
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());

        let lagrange_evaluations = input.domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 =
            Msm::msm_unchecked(&input.random_encryption_points, &lagrange_evaluations);

        let ct_point: C::G1 = Msm::msm_unchecked(&c1_points, &lagrange_evaluations);

        let neg_challenge_eval_commitment = self.challenge_eval_commitment.neg();
        let q_star = ct_point + neg_challenge_eval_commitment;

        let dleq_check = self.dleq_proof.verify(
            q_point.into(),
            q_star,
            C::G1Affine::generator(),
            encryption_pk.into(),
        );

        let neg_g_challenge = (C::G2Affine::generator() * challenge).into_affine().neg();

        let lhs_pairing = C::pairing(
            com_f_poly + neg_challenge_eval_commitment,
            C::G2Affine::generator(),
        );
        let rhs_pairing = C::pairing(self.challenge_opening_proof, powers.g2[1] + neg_g_challenge);

        let pairing_check = lhs_pairing == rhs_pairing;

        dleq_check && pairing_check
    }
}
