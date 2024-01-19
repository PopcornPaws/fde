use crate::commit::kzg::Powers;
use crate::hash::Hasher;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_ff::fields::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::marker::PhantomData;
use ark_std::rand::distributions::Distribution;
use ark_std::rand::Rng;
use ark_std::One;
use digest::Digest;
use num_bigint::{BigInt, BigUint, RandomBits, Sign};
use num_integer::Integer;
use num_prime::nt_funcs::prev_prime;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const N_BITS: u64 = 1024;

#[derive(Debug)]
pub struct Server {
    pub pubkey: BigUint,
    pub privkey: BigUint,
}

impl Server {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        // generate small enough primes so that their product fits
        // "N_BITS" number of bits
        let (p, q) = primes(N_BITS >> 1, rng);
        let pubkey = &p * &q;
        let privkey = (p - BigUint::one()).lcm(&(q - BigUint::one()));

        Self { pubkey, privkey }
    }
    pub fn modulo_n2(&self) -> BigUint {
        &self.pubkey * &self.pubkey
    }

    pub fn lx(&self, x: &BigUint) -> BigUint {
        let modulo = self.modulo_n2();
        debug_assert!(x < &modulo && (x % &self.pubkey) == BigUint::one());
        (x - BigUint::one()) / &self.pubkey
    }

    pub fn decryption_denominator(&self) -> BigUint {
        let n_plus_1_pow_sk =
            (&self.pubkey + BigUint::one()).modpow(&self.privkey, &self.modulo_n2());
        self.lx(&n_plus_1_pow_sk)
    }
}

fn challenge<C: CurveGroup, D: Digest>(
    pubkey: &BigUint,
    vanishing_poly: &DensePolynomial<C::ScalarField>,
    ct_slice: &[BigUint],
    com_f_poly: &C,
    com_f_s_poly: &C,
    t_slice: &[BigUint],
    t: &C,
) -> BigUint {
    let mut hasher = Hasher::<D>::new();
    hasher.update(pubkey);
    hasher.update(&vanishing_poly.coeffs);
    ct_slice.iter().for_each(|ct| hasher.update(ct));
    hasher.update(com_f_poly);
    hasher.update(com_f_s_poly);
    t_slice.iter().for_each(|t| hasher.update(t));
    hasher.update(t);

    BigUint::from_bytes_le(&hasher.finalize())
}

fn primes<R: Rng>(n_bits: u64, rng: &mut R) -> (BigUint, BigUint) {
    let random_bits = RandomBits::new(n_bits);
    let target_p: BigUint = random_bits.sample(rng);
    let target_q: BigUint = random_bits.sample(rng);
    let p = find_next_smaller_prime(&target_p);
    let q = find_next_smaller_prime(&target_q);
    debug_assert_ne!(p, q);
    (p, q)
}

fn find_next_smaller_prime(target: &BigUint) -> BigUint {
    // look for previous prime because we need to fit into 2 * n bits when we multiply p and q
    loop {
        if let Some(found) = prev_prime(target, None) {
            return found;
        }
    }
}

// TODO move encryption-related stuff to encrypt::paillier.rs
fn encrypt(value: &BigUint, key: &BigUint, random: &BigUint) -> BigUint {
    let n2 = key * key;
    pow_mult_mod(&(key + BigUint::one()), value, random, key, &n2)
}

#[cfg(not(feature = "parallel"))]
fn batch_encrypt<T: AsRef<[BigUint]>>(values: T, key: &BigUint, randoms: T) -> Vec<BigUint> {
    values
        .as_ref()
        .iter()
        .zip(randoms.as_ref())
        .map(|(val, rand)| encrypt(val, key, rand))
        .collect()
}

#[cfg(feature = "parallel")]
fn batch_encrypt<T>(values: T, key: &BigUint, randoms: T) -> Vec<BigUint>
where
    T: AsRef<[BigUint]> + rayon::iter::IntoParallelIterator,
{
    values
        .as_ref()
        .par_iter()
        .zip(randoms.as_ref())
        .map(|(val, rand)| encrypt(val, key, rand))
        .collect()
}

fn pow_mult_mod(
    a: &BigUint,
    a_exp: &BigUint,
    b: &BigUint,
    b_exp: &BigUint,
    modulo: &BigUint,
) -> BigUint {
    (a.modpow(a_exp, modulo) * b.modpow(b_exp, modulo)) % modulo
}

// NOTE
// modpow cannot handle negative exponents (it panics) Thus, we are using the extended GCD
// algorithm to find the modular inverse of `num`. However, `extended_gcd_lcm` is only implemented
// for signed types such as BigInt, hence the conversions.
pub fn modular_inverse(num: &BigUint, modulo: &BigUint) -> Option<BigUint> {
    let num_signed = BigInt::from(num.clone());
    let mod_signed = BigInt::from(modulo.clone());
    let (ext_gcd, _) = num_signed.extended_gcd_lcm(&mod_signed);
    if ext_gcd.gcd != BigInt::one() {
        None
    } else {
        let (sign, uint) = ext_gcd.x.into_parts();
        debug_assert!(&uint < modulo);
        if sign == Sign::Minus {
            Some(modulo - uint)
        } else {
            Some(uint)
        }
    }
}

pub struct PaillierRandomParameters {
    pub u_vec: Vec<BigUint>,
    pub s_vec: Vec<BigUint>,
    pub r_vec: Vec<BigUint>,
}

impl PaillierRandomParameters {
    pub fn new<R: Rng>(size: usize, rng: &mut R) -> Self {
        let mut u_vec = Vec::with_capacity(size);
        let mut s_vec = Vec::with_capacity(size);
        let mut r_vec = Vec::with_capacity(size);
        let random_bits = RandomBits::new(N_BITS);
        let random_bits_2 = RandomBits::new(N_BITS >> 1);
        for _ in 0..size {
            u_vec.push(random_bits.sample(rng));
            s_vec.push(random_bits.sample(rng));
            r_vec.push(random_bits_2.sample(rng));
        }

        Self {
            u_vec,
            s_vec,
            r_vec,
        }
    }
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
        pubkey: &BigUint,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let vanishing_poly = DensePolynomial::from(domain.vanishing_polynomial());
        let q_poly = &(f_poly - f_s_poly) / &vanishing_poly;
        let q_poly_evals = q_poly.evaluate_over_domain_by_ref(*domain);
        let com_q_poly = powers.commit_scalars_g1(&q_poly_evals.evals);
        let random_params = PaillierRandomParameters::new(values.len(), rng);
        let ct_vec = batch_encrypt(values, pubkey, &random_params.u_vec);
        let t_vec = batch_encrypt(&random_params.r_vec, pubkey, &random_params.s_vec);
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
        pubkey: &BigUint,
        powers: &Powers<C>,
    ) -> bool {
        let vanishing_poly = DensePolynomial::from(domain.vanishing_polynomial());
        let vanishing_poly_evals = vanishing_poly.evaluate_over_domain_by_ref(*domain);
        let com_vanishing_poly_g2 = powers.commit_scalars_g2(&vanishing_poly_evals.evals);
        let lhs_pairing = C::pairing(self.com_q_poly, com_vanishing_poly_g2);
        let rhs_pairing = C::pairing(*com_f_poly - com_f_s_poly, C::G2::generator());
        if lhs_pairing != rhs_pairing {
            println!("failed pairing check");
            return false;
        }

        let modulo = pubkey * pubkey;
        let t_vec_expected: Vec<BigUint> = self
            .ct_vec
            .iter()
            .zip(self.w_vec.iter().zip(&self.z_vec))
            .map(|(ct, (w, z))| {
                let aux = pow_mult_mod(&(pubkey + BigUint::one()), z, w, pubkey, &modulo);
                let ct_pow_c = ct.modpow(&self.challenge, &modulo);
                // TODO handle unwrap
                let ct_pow_minus_c = modular_inverse(&ct_pow_c, &modulo).unwrap();
                (aux * ct_pow_minus_c) % &modulo
            })
            .collect();
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
        self.challenge == challenge_expected
    }

    pub fn decrypt(&self, server: &Server) -> Vec<BigUint> {
        let modulo = server.modulo_n2();
        let denominator = server.decryption_denominator();
        self.ct_vec
            .iter()
            .map(|ct| {
                (server.lx(&ct.modpow(&server.privkey, &modulo)) / &denominator) % &server.pubkey
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::{modular_inverse, Server, N_BITS};
    use crate::commit::kzg::Powers;
    use crate::tests::{BlsCurve, PaillierEncryptionProof, Scalar, UniPoly};
    use ark_ff::{BigInteger, PrimeField};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
    use ark_std::collections::HashMap;
    use ark_std::rand::distributions::Distribution;
    use ark_std::{test_rng, One, UniformRand};
    use num_bigint::{BigUint, RandomBits};

    const DATA_SIZE: usize = 32;
    const SUBSET_SIZE: usize = 8;

    #[test]
    fn compute_modular_inverse() {
        let rng = &mut test_rng();
        let server = Server::new(rng);
        let modulo = server.pubkey;
        let random_bits = RandomBits::new(N_BITS);
        for _ in 0..100 {
            let num: BigUint =
                <RandomBits as Distribution<BigUint>>::sample(&random_bits, rng) % &modulo;
            let inv = modular_inverse(&num, &modulo).unwrap();
            assert_eq!((num * inv) % &modulo, BigUint::one());
        }
    }

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        // "secret" tau
        let tau = Scalar::rand(rng);
        // generate powers of tau size DATA_SIZE
        let powers = Powers::<BlsCurve>::unsafe_setup_eip_4844(tau, DATA_SIZE);
        // new server (with encryption pubkey)
        let server = Server::new(rng);
        // random data to encrypt
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let domain = GeneralEvaluationDomain::new(DATA_SIZE).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(data.clone(), domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();

        let index_map: HashMap<Scalar, usize> =
            domain.elements().enumerate().map(|(i, e)| (e, i)).collect();
        let domain_s = GeneralEvaluationDomain::new(SUBSET_SIZE).unwrap();
        let indices: Vec<usize> = domain_s
            .elements()
            .map(|elem| *index_map.get(&elem).unwrap())
            .collect();
        let data_s: Vec<Scalar> = indices.into_iter().map(|i| data[i]).collect();
        let evaluations_s = Evaluations::from_vec_and_domain(data_s, domain_s);
        let f_s_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_scalars_g1(&evaluations_s.evals);
        let com_f_s_poly = powers.commit_scalars_g1(&evaluations_s.evals);

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
            &domain_s,
            &server.pubkey,
            &powers,
            rng,
        );

        assert!(proof.verify(
            &com_f_poly,
            &com_f_s_poly,
            &domain_s,
            &server.pubkey,
            &powers
        ));
        let modulo = &server.pubkey * &server.pubkey;
        let denominator = ((&server.pubkey + BigUint::one()).modpow(&server.privkey, &modulo)
            - BigUint::one())
            / &server.pubkey;
        let denominator_inv = modular_inverse(&denominator, &server.pubkey).unwrap();
        let decrypted_data: Vec<BigUint> = proof
            .ct_vec
            .iter()
            .map(|ct| {
                ((ct.modpow(&server.privkey, &modulo) - BigUint::one()) / &server.pubkey
                    * &denominator_inv)
                    % &server.pubkey
            })
            .collect();
        //let decrypted_data = proof.decrypt(&server);
        assert_eq!(decrypted_data, data_biguint);
    }
}
