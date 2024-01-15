use crate::commit::kzg::Powers;
use crate::hash::Hasher;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM as Msm};
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
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
}

fn challenge<C: CurveGroup, D: Digest>(
    pubkey: &BigUint,
    ct_slice: &[BigUint],
    commitment: &C,
    t_slice: &[BigUint],
    t: &C,
) -> BigUint {
    let mut hasher = Hasher::<D>::new();
    hasher.update(pubkey);
    ct_slice.iter().for_each(|ct| hasher.update(ct));
    hasher.update(commitment);
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
fn batch_encrypt<T: AsRef<[BigUint]>>(values: T, key: &BigUint, randoms: T) -> Vec<BigUint> {
    values
        .iter()
        .zip(randoms)
        .map(|val, rand| encrypt(val, key, rand))
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
    // TODO remove these lines
    pub t_vec: Vec<BigUint>,
    pub t: C::G1,
    _digest: PhantomData<D>,
    _curve: PhantomData<C>,
}

impl<C: Pairing, D: Digest> Proof<C, D> {
    pub fn new<R: Rng>(
        values: &[BigUint],
        commitment: &C::G1,
        pubkey: &BigUint,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let random_params = PaillierRandomParameters::new(values.len(), rng);
        let ct_vec = batch_encrypt(values, pubkey, &random_params.u_vec);
        let t_vec = batch_encrypt(&random_params.r_vec, pubkey, &random_params.s_vec);
        let r_scalar_vec: Vec<C::ScalarField> = random_params
            .r_vec
            .iter()
            .map(|r| C::ScalarField::from_le_bytes_mod_order(&r.to_bytes_le()))
            .collect();
        let t = <C::G1 as Msm>::msm_unchecked(&powers.g1[0..r_scalar_vec.len()], &r_scalar_vec);
        let challenge = challenge::<C::G1, D>(pubkey, &ct_vec, commitment, &t_vec, &t);
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
            t_vec,
            t,
            _digest: PhantomData,
            _curve: PhantomData,
        }
    }

    pub fn verify(&self, commitment: &C::G1, pubkey: &BigUint, powers: &Powers<C>) -> bool {
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
        assert_eq!(self.t_vec, t_vec_expected);
        let z_scalar_vec: Vec<C::ScalarField> = self
            .z_vec
            .iter()
            .map(|z| C::ScalarField::from_le_bytes_mod_order(&z.to_bytes_le()))
            .collect();

        // compute t
        let challenge_scalar =
            C::ScalarField::from_le_bytes_mod_order(&self.challenge.to_bytes_le());
        let commitment_pow_challenge = *commitment * challenge_scalar;
        let msm = <C::G1 as Msm>::msm_unchecked(&powers.g1[0..z_scalar_vec.len()], &z_scalar_vec);
        let t_expected = msm - commitment_pow_challenge;
        assert_eq!(self.t, t_expected);

        let challenge_expected = challenge::<C::G1, D>(
            pubkey,
            &self.ct_vec,
            commitment,
            &t_vec_expected,
            &t_expected,
        );
        self.challenge == challenge_expected
    }
}

#[cfg(test)]
mod test {
    use super::{modular_inverse, Server, N_BITS};
    use crate::commit::kzg::Powers;
    use crate::tests::{BlsCurve, PaillierEncryptionProof, Scalar, UniPoly};
    use ark_ec::VariableBaseMSM as Msm;
    use ark_ff::{BigInteger, PrimeField};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
    use ark_std::rand::distributions::Distribution;
    use ark_std::{test_rng, One, UniformRand};
    use num_bigint::{BigUint, RandomBits};

    const DATA_SIZE: usize = 4;

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
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<BlsCurve>::unsafe_setup_eip_4844(tau, DATA_SIZE); // generate powers of tau size DATA_SIZE
                                                                                // new server (with encryption pubkey)
        let server = Server::new(rng);
        // random data to encrypt
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let data_biguint = data
            .iter()
            .map(|d| BigUint::from_bytes_le(&d.into_bigint().to_bytes_le()))
            .collect::<Vec<BigUint>>();
        let domain = GeneralEvaluationDomain::new(DATA_SIZE).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        // TODO delet dis
        /*
        let random_bits = RandomBits::new(N_BITS >> 1);
        let challenge: BigUint = RandomBits::new(N_BITS).sample(rng);
        let challenge_scalar = Scalar::from_le_bytes_mod_order(&challenge.to_bytes_le());
        let r_vec: Vec<BigUint> = (0..DATA_SIZE).map(|_| random_bits.sample(rng)).collect();

        let z_vec: Vec<BigUint> = r_vec
            .iter()
            .zip(&f_poly.coeffs)
            .map(|(r, f_i)| {
                r + &challenge * BigUint::from_bytes_le(&f_i.into_bigint().to_bytes_le())
            })
            .collect();

        let r_scalar_vec: Vec<Scalar> = r_vec
            .iter()
            .map(|r| Scalar::from_le_bytes_mod_order(&r.to_bytes_le()))
            .collect();
        let z_scalar_vec: Vec<Scalar> = z_vec
            .iter()
            .map(|z| Scalar::from_le_bytes_mod_order(&z.to_bytes_le()))
            .collect();

        let msm_r: <BlsCurve as ark_ec::pairing::Pairing>::G1 =
            Msm::msm_unchecked(&powers.g1[0..r_scalar_vec.len()], &r_scalar_vec);
        let msm_z: <BlsCurve as ark_ec::pairing::Pairing>::G1 =
            Msm::msm_unchecked(&powers.g1[0..z_scalar_vec.len()], &z_scalar_vec);

        let commitment_pow_challenge = com_f_poly * challenge_scalar;
        assert_eq!(msm_r, msm_z - commitment_pow_challenge);
        */

        let proof =
            PaillierEncryptionProof::new(&data_biguint, &com_f_poly, &server.pubkey, &powers, rng);

        assert!(proof.verify(&com_f_poly, &server.pubkey, &powers));
    }
}
