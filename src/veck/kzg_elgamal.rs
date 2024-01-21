use crate::commit::kzg::{Kzg, Powers};
use crate::dleq::Proof as DleqProof;
use crate::encrypt::elgamal::{Cipher, ExponentialElgamal as Elgamal, SplitScalar, MAX_BITS};
use crate::encrypt::EncryptionEngine;
use crate::hash::Hasher;
use crate::range_proof::RangeProof;
use crate::Error;
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
pub enum KzgElgamalError {
    #[error("invalid DLEQ proof for split encryption points")]
    InvalidDleqProof,
    #[error("invalid KZG proof")]
    InvalidKzgProof,
    #[error("invalid subset polynomial proof")]
    InvalidSubsetPolynomial,
    #[error("invalid split scalar verification")]
    InvalidSplitScalars,
}

/// A publicly verifiable proof based on the Elgamal encryption scheme.
pub struct EncryptionProof<const N: usize, C: Pairing, D: Clone + Digest> {
    /// The actual Elgamal ciphertexts of the encrypted data points.
    pub ciphers: Vec<Cipher<C::G1>>,
    /// Each ciphertext is split into a set of scalars that, once decrypted, can reconstruct the
    /// original data point. Since we use the exponential Elgamal encryption scheme, these "short"
    /// ciphertexts are needed to encrypt split data points in the bruteforceable range: 2^32.
    pub short_ciphers: Vec<[Cipher<C::G1>; N]>,
    /// Each "short" ciphertext requires a range proof proving that the encrypted value is in the
    /// bruteforceable range.
    pub range_proofs: Vec<[RangeProof<C, D>; N]>,
    /// Random encryption points used to encrypt the original data points. These are the `h^r`
    /// values in the exponential Elgamal scheme: `e = g^m * h^r`, where `e` is the ciphertext, `m`
    /// is the plaintext.
    pub random_encryption_points: Vec<C::G1Affine>,
}

impl<const N: usize, C: Pairing, D: Clone + Digest> EncryptionProof<N, C, D> {
    pub fn new<R: Rng>(
        evaluations: &[C::ScalarField],
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let mut random_encryption_points = Vec::with_capacity(evaluations.len());
        let mut ciphers = Vec::with_capacity(evaluations.len());
        let mut short_ciphers = Vec::with_capacity(evaluations.len());
        let mut range_proofs = Vec::with_capacity(evaluations.len());

        for eval in evaluations {
            let split_eval = SplitScalar::from(*eval);
            let rp = split_eval.splits().map(|s| {
                RangeProof::new(s, MAX_BITS, powers, rng).expect("invalid range proof input")
            });
            let (sc, rand) = split_eval.encrypt::<Elgamal<C::G1>, _>(encryption_pk, rng);
            let cipher = <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
                eval,
                encryption_pk,
                &rand,
            );
            random_encryption_points.push((C::G1Affine::generator() * rand).into_affine());
            ciphers.push(cipher);
            short_ciphers.push(sc);
            range_proofs.push(rp);
        }

        Self {
            ciphers,
            short_ciphers,
            range_proofs,
            random_encryption_points,
        }
    }

    /// Generates a subset from the total encrypted data.
    ///
    /// Clients might not be interested in the whole dataset, thus the server may generate a subset
    /// encryption proof to reduce proof verification costs.
    pub fn subset(&self, indices: &[usize]) -> Self {
        let size = indices.len();
        let mut ciphers = Vec::with_capacity(size);
        let mut short_ciphers = Vec::with_capacity(size);
        let mut random_encryption_points = Vec::with_capacity(size);
        let mut range_proofs = Vec::with_capacity(size);
        for &index in indices {
            ciphers.push(self.ciphers[index]);
            short_ciphers.push(self.short_ciphers[index]);
            random_encryption_points.push(self.random_encryption_points[index]);
            range_proofs.push(self.range_proofs[index].clone());
        }

        Self {
            ciphers,
            short_ciphers,
            range_proofs,
            random_encryption_points,
        }
    }

    /// Checks that the sum of split scalars evaluate to the encrypted value via the homomorphic
    /// properties of Elgamal encryption.
    pub fn verify_split_scalars(&self) -> bool {
        for (cipher, short_cipher) in self.ciphers.iter().zip(&self.short_ciphers) {
            if !cipher.check_encrypted_sum(short_cipher) {
                return false;
            }
        }
        true
    }

    // TODO range proofs and short ciphers are not "connected" by anything?
    // TODO parallelize
    pub fn verify_range_proofs(&self, powers: &Powers<C>) -> bool {
        for rps in self.range_proofs.iter() {
            if !rps.iter().all(|rp| rp.verify(MAX_BITS, powers).is_ok()) {
                return false;
            }
        }
        true
    }
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
    D: Digest + Clone,
{
    pub fn new<R: Rng>(
        f_poly: &DensePolynomial<C::ScalarField>,
        f_s_poly: &DensePolynomial<C::ScalarField>,
        encryption_sk: &C::ScalarField,
        encryption_proof: EncryptionProof<N, C, D>,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let mut hasher = Hasher::<D>::new();
        encryption_proof
            .ciphers
            .iter()
            .for_each(|cipher| hasher.update(&cipher.c1()));

        let domain_size = encryption_proof.ciphers.len();
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(domain_size)
            .ok_or(Error::InvalidFftDomain(domain_size))?;

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
    ) -> Result<(), Error> {
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
            .ok_or(Error::InvalidFftDomain(domain_size))?;

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

        // check split scalar encryption validity
        // check that split scalars are in a brute-forceable range

        if !dleq_check {
            Err(KzgElgamalError::InvalidDleqProof.into())
        } else if !kzg_check {
            Err(KzgElgamalError::InvalidKzgProof.into())
        } else if !subset_pairing_check {
            Err(KzgElgamalError::InvalidSubsetPolynomial.into())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::commit::kzg::Powers;
    use crate::encrypt::elgamal::MAX_BITS;
    use crate::tests::*;
    use ark_ec::pairing::Pairing;
    use ark_ec::{CurveGroup, Group};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
    use ark_std::{test_rng, UniformRand};

    const DATA_SIZE: usize = 16;
    const SUBSET_SIZE: usize = 8;

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, (DATA_SIZE + 1).max(MAX_BITS * 4)); // generate powers of tau size DATA_SIZE

        // Server's (elphemeral?) encryption key for this session
        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        // Generate random data and public inputs (encrypted data, etc)
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let encryption_proof = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);

        encryption_proof
            .range_proofs
            .iter()
            .for_each(|rps| assert!(rps.iter().all(|rp| rp.verify(MAX_BITS, &powers).is_ok())));

        let domain = GeneralEvaluationDomain::new(data.len()).expect("valid domain");
        let index_map = super::super::index_map(domain);

        // Interpolate original polynomial and compute its KZG commitment.
        // This is performed only once by the server
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        // get subdomain with size suitable for interpolating a polynomial with SUBSET_SIZE
        // coefficients
        let subdomain = GeneralEvaluationDomain::new(SUBSET_SIZE).unwrap();
        let subset_indices = super::super::subset_indices(&index_map, &subdomain);
        let subset_evaluations =
            super::super::subset_evals(&evaluations, &subset_indices, subdomain);
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
