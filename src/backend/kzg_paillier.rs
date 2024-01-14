use crate::commit::kzg::Powers;
use crate::hash::Hasher;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM as Msm};
use ark_ff::fields::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::rand::distributions::Distribution;
use ark_std::rand::Rng;
use digest::Digest;
use num_bigint::{BigInt, BigUint, RandomBits};
use num_integer::Integer;
use num_prime::nt_funcs::prev_prime;
use num_traits::One;
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
    let target_p: BigUint = RandomBits::new(n_bits).sample(rng);
    let target_q: BigUint = RandomBits::new(n_bits).sample(rng);
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

// NOTE modpow cannot handle negative exponents (it panics)
// Thus, we are using the extended GCD algorithm to find the modular inverse
// of `num`. However, `extended_gcd_lcm` is only implemented for signed types
// such as BigInt, hence the conversions.
pub fn modular_inverse(num: &BigUint, modulo: &BigUint) -> Option<BigUint> {
    let num_signed = BigInt::from(num.clone());
    let mod_signed = BigInt::from(modulo.clone());
    let (ext_gcd, _) = num_signed.extended_gcd_lcm(&mod_signed);
    if ext_gcd.gcd != BigInt::one() {
        None
    } else {
        ext_gcd.x.to_biguint()
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
        for _ in 0..size {
            u_vec.push(RandomBits::new(N_BITS).sample(rng));
            s_vec.push(RandomBits::new(N_BITS).sample(rng));
            r_vec.push(RandomBits::new(N_BITS >> 1).sample(rng));
        }

        Self {
            u_vec,
            s_vec,
            r_vec,
        }
    }
}

pub struct PaillierEncryptionProof<D> {
    pub challenge: BigUint,
    pub ct_vec: Vec<BigUint>,
    pub w_vec: Vec<BigUint>,
    pub z_vec: Vec<BigUint>,
    _digest: PhantomData<D>,
}

impl<D: Digest> PaillierEncryptionProof<D> {
    pub fn new<C: Pairing>(
        pubkey: &BigUint,
        values: &[BigUint],
        random_params: PaillierRandomParameters,
        commitment: &C::G1,
        powers: &Powers<C>,
    ) -> Self {
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
            .map(|(r, val)| {
                let aux = (&challenge * val) % pubkey;
                (r + aux) % pubkey
            })
            .collect();

        Self {
            challenge,
            ct_vec,
            w_vec,
            z_vec,
            _digest: PhantomData,
        }
    }
    pub fn verify<C: Pairing>(
        &self,
        pubkey: &BigUint,
        commitment: &C::G1,
        powers: &Powers<C>,
    ) -> bool {
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
        let t_expected =
            <C::G1 as Msm>::msm_unchecked(&powers.g1[0..z_scalar_vec.len()], &z_scalar_vec)
                - *commitment
                    * C::ScalarField::from_le_bytes_mod_order(&self.challenge.to_bytes_le());

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
    use super::*;
    use ark_std::test_rng;
    use num_bigint::BigInt;

    const DATA_SIZE: usize = 32;

    // TODO fix tests
    #[test]
    fn new_server() {
        let rng = &mut test_rng();
        let server = Server::new(rng);
        assert!(server.pubkey.bits() <= N_BITS);
        assert!(server.privkey.bits() <= N_BITS);
        println!("{}, {}", server.pubkey.bits(), server.privkey.bits());
        println!("{:#?}", server);

        let n2 = &server.pubkey * &server.pubkey;
        println!(
            "{:?}",
            BigInt::from(server.pubkey).modpow(&(-BigInt::one()), &BigInt::from(n2))
        );
    }

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, DATA_SIZE + 1); // generate powers of tau size DATA_SIZE
        // new server (with encryption pubkey)
        let server = Server::new(rng);
        // random data to encrypt
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        

    }
}
