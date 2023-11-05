use crate::commit::kzg::Powers;
use crate::dleq::Proof as DleqProof;
use crate::encrypt::elgamal::{Cipher, ExponentialElgamal as Elgamal, SplitScalar};
use crate::encrypt::EncryptionEngine;
use crate::hash::Hasher;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_ff::PrimeField;
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::EvaluationDomain;
use ark_poly_commit::DenseUVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::ops::{Add, Div, Neg, Sub};
use ark_std::rand::Rng;
use ark_std::One;
use digest::Digest;

pub struct PublicProofInput<const N: usize, C: Pairing> {
    pub ciphers: Vec<Cipher<C::G1>>,
    pub short_ciphers: Vec<[Cipher<C::G1>; N]>,
    pub random_encryption_points: Vec<C::G1Affine>,
    pub domain: GeneralEvaluationDomain<C::ScalarField>,
}

impl<const N: usize, C: Pairing> PublicProofInput<N, C> {
    pub fn new<R: Rng>(
        evaluations: &[C::ScalarField],
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        rng: &mut R,
    ) -> Self {
        let domain = GeneralEvaluationDomain::new(evaluations.len()).unwrap();

        let mut random_encryption_points = Vec::with_capacity(evaluations.len());
        let mut ciphers = Vec::with_capacity(evaluations.len());
        let mut short_ciphers = Vec::with_capacity(evaluations.len());

        for eval in evaluations {
            let split_eval = SplitScalar::from(*eval);
            let (sc, rand) = split_eval.encrypt::<Elgamal<C::G1>, _>(encryption_pk, rng);
            let cipher = <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
                eval,
                encryption_pk,
                &rand,
            );
            random_encryption_points.push((C::G1Affine::generator() * rand).into_affine());
            ciphers.push(cipher);
            short_ciphers.push(sc);
        }

        Self {
            ciphers,
            short_ciphers,
            random_encryption_points,
            domain,
        }
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
        domain: &GeneralEvaluationDomain<C::ScalarField>,
        ciphers: &[Cipher<C::G1>],
        random_encryption_points: &[C::G1Affine],
        encryption_sk: &C::ScalarField,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let mut hasher = Hasher::<D>::new();
        ciphers
            .iter()
            .for_each(|cipher| hasher.update(&cipher.c1()));
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());
        let challenge_eval = f_poly.evaluate(&challenge);

        let d_poly = P::from_coefficients_slice(&[-challenge, C::ScalarField::one()]);
        let q_poly = &(f_poly + &P::from_coefficients_slice(&[-challenge_eval])) / &d_poly;
        let challenge_opening_proof = powers.commit_g1(&q_poly).into();
        let challenge_eval_commitment = (C::G1Affine::generator() * challenge_eval).into_affine();

        let lagrange_evaluations = domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 = Msm::msm_unchecked(random_encryption_points, &lagrange_evaluations);

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
        domain: &GeneralEvaluationDomain<C::ScalarField>,
        ciphers: &[Cipher<C::G1>],
        random_encryption_points: &[C::G1Affine],
        encryption_pk: C::G1Affine,
        powers: &Powers<C>,
    ) -> bool {
        let mut hasher = Hasher::<D>::new();
        let c1_points: Vec<C::G1Affine> = ciphers
            .iter()
            .map(|cipher| {
                let c1 = cipher.c1();
                hasher.update(&c1);
                c1
            })
            .collect();
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());

        let lagrange_evaluations = domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 = Msm::msm_unchecked(random_encryption_points, &lagrange_evaluations);

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

#[cfg(test)]
mod test {
    use crate::commit::kzg::Powers;
    use crate::tests::{BlsCurve, KzgElgamalProof, PublicProofInput, Scalar, UniPoly};
    use ark_ec::pairing::Pairing;
    use ark_ec::{CurveGroup, Group};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
    use ark_std::{test_rng, UniformRand};

    const D: usize = 32;

    #[test]
    fn flow() {
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng);
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, D);

        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        let data: Vec<Scalar> = (0..D).map(|_| Scalar::rand(rng)).collect();
        let domain = GeneralEvaluationDomain::new(data.len()).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        let input = PublicProofInput::new(&evaluations.evals, &encryption_pk, rng);
        let proof = KzgElgamalProof::new(
            &f_poly,
            &input.domain,
            &input.ciphers,
            &input.random_encryption_points,
            &encryption_sk,
            &powers,
            rng,
        );
        assert!(proof.verify(
            com_f_poly,
            &input.domain,
            &input.ciphers,
            &input.random_encryption_points,
            encryption_pk,
            &powers
        ));

        for (cipher, short_cipher) in input.ciphers.iter().zip(&input.short_ciphers) {
            assert!(cipher.check_encrypted_sum(short_cipher));
        }
    }
}
