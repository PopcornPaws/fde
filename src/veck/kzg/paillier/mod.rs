mod encrypt;
mod random;
mod server;
mod utils;
pub use random::RandomParameters;
pub use server::Server;
use utils::{challenge, modular_inverse, pow_mult_mod};

use crate::commit::kzg::Powers;
use crate::Error as CrateError;
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_ff::fields::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::One;
use digest::Digest;
use num_bigint::BigUint;

use thiserror::Error as ErrorT;

const N_BITS: u64 = 1024;

#[derive(ErrorT, Debug, PartialEq)]
pub enum Error {
    #[error("invalid encrypted value, has no modular inverse")]
    InvalidEncryptedValue,
    #[error("computed challenge does not match the expected one")]
    ChallengeMismatch,
    #[error("pairing check failed for subset polynomial")]
    PairingMismatch,
}

pub struct Proof<C: Pairing, D> {
    pub challenge: BigUint,
    pub ct_vec: Vec<BigUint>,
    pub w_vec: Vec<BigUint>,
    pub z_vec: Vec<BigUint>,
    pub com_q_poly: C::G1,
    _digest: PhantomData<D>,
    _curve: PhantomData<C>,
}

impl<C: Pairing, D: Digest> Proof<C, D> {
    #[allow(clippy::too_many_arguments)]
    pub fn new<R: Rng>(
        values: &[BigUint],
        f_poly: &DensePolynomial<C::ScalarField>,
        f_s_poly: &DensePolynomial<C::ScalarField>,
        com_f_poly: &C::G1,
        com_f_s_poly: &C::G1,
        domain: &GeneralEvaluationDomain<C::ScalarField>,
        domain_s: &GeneralEvaluationDomain<C::ScalarField>,
        pubkey: &BigUint,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let vanishing_poly = DensePolynomial::from(domain_s.vanishing_polynomial());
        let q_poly = &(f_poly - f_s_poly) / &vanishing_poly;
        let q_poly_evals = q_poly.evaluate_over_domain_by_ref(*domain);
        let com_q_poly = powers.commit_scalars_g1(&q_poly_evals.evals);

        let random_params = RandomParameters::new(values.len(), rng);
        let ct_vec = encrypt::batch(values, pubkey, &random_params.u_vec);
        let t_vec = encrypt::batch(&random_params.r_vec, pubkey, &random_params.s_vec);
        let r_scalar_vec: Vec<C::ScalarField> = random_params
            .r_vec
            .iter()
            .map(|r| C::ScalarField::from_le_bytes_mod_order(&r.to_bytes_le()))
            .collect();
        let t = powers.commit_scalars_g1(&r_scalar_vec);
        let challenge = challenge::<C::G1, D>(
            pubkey,
            &vanishing_poly,
            &ct_vec,
            com_f_poly,
            com_f_s_poly,
            &t_vec,
            &t,
        );
        let w_vec: Vec<BigUint> = random_params
            .s_vec
            .iter()
            .zip(&random_params.u_vec)
            .map(|(s, u)| pow_mult_mod(s, &BigUint::one(), u, &challenge, pubkey))
            .collect();
        let z_vec: Vec<BigUint> = random_params
            .r_vec
            .iter()
            .zip(values)
            .map(|(r, val)| r + &challenge * val)
            .collect();

        Self {
            challenge,
            ct_vec,
            w_vec,
            z_vec,
            com_q_poly,
            _digest: PhantomData,
            _curve: PhantomData,
        }
    }

    pub fn verify(
        &self,
        com_f_poly: &C::G1,
        com_f_s_poly: &C::G1,
        domain: &GeneralEvaluationDomain<C::ScalarField>,
        domain_s: &GeneralEvaluationDomain<C::ScalarField>,
        pubkey: &BigUint,
        powers: &Powers<C>,
    ) -> Result<(), CrateError> {
        let vanishing_poly = DensePolynomial::from(domain_s.vanishing_polynomial());
        let vanishing_poly_evals = vanishing_poly.evaluate_over_domain_by_ref(*domain);
        let com_vanishing_poly_g2 = powers.commit_scalars_g2(&vanishing_poly_evals.evals);

        let lhs_pairing = C::pairing(self.com_q_poly, com_vanishing_poly_g2);
        let rhs_pairing = C::pairing(*com_f_poly - com_f_s_poly, C::G2::generator());
        if lhs_pairing != rhs_pairing {
            return Err(Error::PairingMismatch.into());
        }

        let modulo = pubkey * pubkey;
        let t_vec_expected: Vec<BigUint> = self
            .ct_vec
            .iter()
            .zip(self.w_vec.iter().zip(&self.z_vec))
            .flat_map(|(ct, (w, z))| -> Result<BigUint, CrateError> {
                let aux = pow_mult_mod(&(pubkey + BigUint::one()), z, w, pubkey, &modulo);
                let ct_pow_c = ct.modpow(&self.challenge, &modulo);
                let ct_pow_minus_c =
                    modular_inverse(&ct_pow_c, &modulo).ok_or(Error::InvalidEncryptedValue)?;
                Ok((aux * ct_pow_minus_c) % &modulo)
            })
            .collect::<Vec<_>>();
        let z_scalar_vec: Vec<C::ScalarField> = self
            .z_vec
            .iter()
            .map(|z| C::ScalarField::from_le_bytes_mod_order(&z.to_bytes_le()))
            .collect();

        // compute t
        let challenge_scalar =
            C::ScalarField::from_le_bytes_mod_order(&self.challenge.to_bytes_le());
        let commitment_pow_challenge = *com_f_s_poly * challenge_scalar;
        let msm = powers.commit_scalars_g1(&z_scalar_vec);
        let t_expected = msm - commitment_pow_challenge;

        let challenge_expected = challenge::<C::G1, D>(
            pubkey,
            &vanishing_poly,
            &self.ct_vec,
            com_f_poly,
            com_f_s_poly,
            &t_vec_expected,
            &t_expected,
        );

        if self.challenge != challenge_expected {
            Err(Error::ChallengeMismatch.into())
        } else {
            Ok(())
        }
    }

    pub fn decrypt(&self, server: &Server) -> Vec<BigUint> {
        let denominator = server.decryption_denominator();
        let denominator_inv = modular_inverse(&denominator, &server.pubkey).unwrap();
        self.ct_vec
            .iter()
            .map(|ct| {
                let ct_lx = server.lx(&ct.modpow(&server.privkey, &server.mod_n2));
                (ct_lx * &denominator_inv) % &server.pubkey
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::*;
    use ark_ff::BigInteger;
    use ark_poly::Evaluations;
    use ark_std::{test_rng, UniformRand};

    const DATA_SIZE: usize = 16;
    const SUBSET_SIZE: usize = 16;

    type PaillierEncryptionProof = Proof<TestCurve, TestHash>;

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        // "secret" tau
        let tau = Scalar::rand(rng);
        // generate powers of tau size DATA_SIZE
        let powers = Powers::<TestCurve>::unsafe_setup_eip_4844(tau, DATA_SIZE);
        // new server (with encryption pubkey)
        let server = Server::new(rng);
        // random data to encrypt
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let domain = GeneralEvaluationDomain::new(DATA_SIZE).unwrap();
        let domain_s = GeneralEvaluationDomain::new(SUBSET_SIZE).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let index_map = crate::veck::index_map(domain);
        let subset_indices = crate::veck::subset_indices(&index_map, &domain_s);
        let evaluations_s = crate::veck::subset_evals(&evaluations, &subset_indices, domain_s);

        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let f_s_poly: UniPoly = evaluations_s.interpolate_by_ref();

        let evaluations_s_d = f_s_poly.evaluate_over_domain_by_ref(domain);

        let com_f_poly = powers.commit_scalars_g1(&evaluations.evals);
        let com_f_s_poly = powers.commit_scalars_g1(&evaluations_s_d.evals);

        let data_biguint: Vec<BigUint> = evaluations_s
            .evals
            .iter()
            .map(|d| BigUint::from_bytes_le(&d.into_bigint().to_bytes_le()))
            .collect();

        let proof = PaillierEncryptionProof::new(
            &data_biguint,
            &f_poly,
            &f_s_poly,
            &com_f_poly,
            &com_f_s_poly,
            &domain,
            &domain_s,
            &server.pubkey,
            &powers,
            rng,
        );

        assert!(proof
            .verify(
                &com_f_poly,
                &com_f_s_poly,
                &domain,
                &domain_s,
                &server.pubkey,
                &powers
            )
            .is_ok());

        let decrypted_data = proof.decrypt(&server);
        assert_eq!(decrypted_data, data_biguint);
    }
}
