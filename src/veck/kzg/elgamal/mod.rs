mod encryption;
pub use encryption::EncryptionProof;

use crate::commit::kzg::{Kzg, Powers};
use crate::dleq::Proof as DleqProof;
use crate::hash::Hasher;
use crate::Error as CrateError;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_ff::PrimeField;
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly::Polynomial;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use digest::Digest;

use thiserror::Error as ErrorT;

#[derive(Debug, ErrorT, PartialEq)]
pub enum Error {
    #[error("invalid DLEQ proof for split encryption points")]
    InvalidDleqProof,
    #[error("invalid KZG proof")]
    InvalidKzgProof,
    #[error("invalid subset polynomial proof")]
    InvalidSubsetPolynomial,
    #[error("invalid split scalar verification")]
    InvalidSplitScalars,
    #[error("invalid range proofs")]
    InvalidRangeProofs,
}

pub struct Proof<const N: usize, C: Pairing, D: Clone + Digest> {
    pub encryption_proof: EncryptionProof<N, C, D>,
    pub challenge_eval_commitment: C::G1Affine,
    pub challenge_opening_proof: C::G1Affine,
    pub dleq_proof: DleqProof<C::G1, D>,
    pub com_f_q_poly: C::G1Affine,
    _poly: PhantomData<DensePolynomial<C::ScalarField>>,
    _digest: PhantomData<D>,
}

impl<const N: usize, C, D> Proof<N, C, D>
where
    C: Pairing,
    D: Digest + Clone + Send + Sync,
{
    pub fn new<R: Rng>(
        f_poly: &DensePolynomial<C::ScalarField>,
        f_s_poly: &DensePolynomial<C::ScalarField>,
        encryption_sk: &C::ScalarField,
        encryption_proof: EncryptionProof<N, C, D>,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Result<Self, CrateError> {
        let mut hasher = Hasher::<D>::new();
        encryption_proof
            .ciphers
            .iter()
            .for_each(|cipher| hasher.update(&cipher.c1()));

        let domain_size = encryption_proof.ciphers.len();
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(domain_size)
            .ok_or(CrateError::InvalidFftDomain(domain_size))?;

        // challenge and KZG proof
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());
        let challenge_eval = f_s_poly.evaluate(&challenge);
        let challenge_opening_proof = Kzg::proof(f_s_poly, challenge, challenge_eval, powers);
        let challenge_eval_commitment = (C::G1Affine::generator() * challenge_eval).into_affine();

        // NOTE According to the docs this should always return Some((q, rem)), so unwrap is fine
        // https://docs.rs/ark-poly/latest/src/ark_poly/polynomial/univariate/dense.rs.html#144
        let f_q_poly = (f_poly - f_s_poly)
            .divide_by_vanishing_poly(domain)
            .unwrap()
            .0;
        // subset polynomial KZG commitment
        let com_f_q_poly = powers.commit_g1(&f_q_poly).into();

        // DLEQ proof
        let lagrange_evaluations = &domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 = Msm::msm_unchecked(
            &encryption_proof.random_encryption_points,
            lagrange_evaluations,
        );

        let dleq_proof = DleqProof::new(
            encryption_sk,
            q_point.into_affine(),
            C::G1Affine::generator(),
            rng,
        );

        Ok(Self {
            encryption_proof,
            challenge_eval_commitment,
            challenge_opening_proof,
            dleq_proof,
            com_f_q_poly,
            _poly: PhantomData,
            _digest: PhantomData,
        })
    }

    pub fn verify(
        &self,
        com_f_poly: C::G1,
        com_f_s_poly: C::G1,
        encryption_pk: C::G1Affine,
        powers: &Powers<C>,
    ) -> Result<(), CrateError> {
        let mut hasher = Hasher::<D>::new();
        let c1_points: Vec<C::G1Affine> = self
            .encryption_proof
            .ciphers
            .iter()
            .map(|cipher| {
                let c1 = cipher.c1();
                hasher.update(&c1);
                c1
            })
            .collect();
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());
        let domain_size = self.encryption_proof.ciphers.len();
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(domain_size)
            .ok_or(CrateError::InvalidFftDomain(domain_size))?;

        // polynomial division check via vanishing polynomial
        let vanishing_poly = DensePolynomial::from(domain.vanishing_polynomial());
        let com_vanishing_poly = powers.commit_g2(&vanishing_poly);
        let subset_pairing_check = Kzg::<C>::pairing_check(
            com_f_poly - com_f_s_poly,
            self.com_f_q_poly.into_group(),
            com_vanishing_poly,
        );

        // DLEQ check
        let lagrange_evaluations = &domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 = Msm::msm_unchecked(
            &self.encryption_proof.random_encryption_points,
            lagrange_evaluations,
        ); // Q
        let ct_point: C::G1 = Msm::msm_unchecked(&c1_points, lagrange_evaluations); // C_t

        let q_star = ct_point - self.challenge_eval_commitment; // Q* = C_t / C_alpha
        let dleq_check = self.dleq_proof.verify(
            q_point.into(),
            q_star,
            C::G1Affine::generator(),
            encryption_pk.into(),
        );

        // KZG pairing check
        let point = C::G2Affine::generator() * challenge;
        let kzg_check = Kzg::verify(
            self.challenge_opening_proof,
            com_f_s_poly.into(),
            point,
            self.challenge_eval_commitment.into_group(),
            powers,
        );

        // check that split scalars are in a brute-forceable range

        if !dleq_check {
            Err(Error::InvalidDleqProof.into())
        } else if !kzg_check {
            Err(Error::InvalidKzgProof.into())
        } else if !subset_pairing_check {
            Err(Error::InvalidSubsetPolynomial.into())
        //} else if !self.encryption_proof.verify_split_scalars() {
        //    Err(Error::InvalidSplitScalars.into())
        //} else if !self.encryption_proof.verify_range_proofs(powers) {
        //    Err(Error::InvalidRangeProofs.into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::encrypt::elgamal::MAX_BITS;
    use crate::tests::*;
    use ark_ec::Group;
    use ark_poly::Evaluations;
    use ark_std::{test_rng, UniformRand};

    const DATA_SIZE: usize = 16;
    const SUBSET_SIZE: usize = 8;

    type ElgamalEncryptionProof = EncryptionProof<{ N }, TestCurve, TestHash>;
    type KzgElgamalProof = Proof<{ N }, TestCurve, TestHash>;

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<TestCurve>::unsafe_setup(tau, (DATA_SIZE + 1).max(MAX_BITS * 4)); // generate powers of tau size DATA_SIZE

        // Server's (elphemeral?) encryption key for this session
        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        // Generate random data and public inputs (encrypted data, etc)
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let encryption_proof = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);

        assert!(encryption_proof.verify_range_proofs(&powers));

        let domain = GeneralEvaluationDomain::new(data.len()).expect("valid domain");
        let index_map = crate::veck::index_map(domain);

        // Interpolate original polynomial and compute its KZG commitment.
        // This is performed only once by the server
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        // get subdomain with size suitable for interpolating a polynomial with SUBSET_SIZE
        // coefficients
        let subdomain = GeneralEvaluationDomain::new(SUBSET_SIZE).unwrap();
        let subset_indices = crate::veck::subset_indices(&index_map, &subdomain);
        let subset_evaluations =
            crate::veck::subset_evals(&evaluations, &subset_indices, subdomain);
        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let sub_encryption_proof = encryption_proof.subset(&subset_indices);

        let proof = KzgElgamalProof::new(
            &f_poly,
            &f_s_poly,
            &encryption_sk,
            sub_encryption_proof,
            &powers,
            rng,
        )
        .unwrap();
        assert!(proof
            .verify(com_f_poly, com_f_s_poly, encryption_pk, &powers)
            .is_ok());
    }
}
