use crate::commit::kzg::Powers;
use ark_ec::pairing::Pairing;
use ark_ec::VariableBaseMSM as Msm;
use ark_ff::fields::PrimeField;
use ark_std::rand::distributions::Distribution;
use ark_std::rand::Rng;
use num_bigint::{BigUint, RandomBits};
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

    pub fn encrypt<C: Pairing>(
        &self,
        values: &[BigUint],
        random_params: PaillierRandomParameters,
        commitment: &C::G1,
        powers: &Powers<C>,
    ) -> PaillierEncryptionProof {
        let ct_vec = batch_encrypt(values, &self.pubkey, &random_params.u_vec);
        let t_vec = batch_encrypt(&random_params.r_vec, &self.pubkey, &random_params.s_vec);
        let r_scalar_vec: Vec<C::ScalarField> = random_params
            .r_vec
            .iter()
            .map(|r| C::ScalarField::from_le_bytes_mod_order(&r.to_bytes_le()))
            .collect();
        let t = <C::G1 as Msm>::msm_unchecked(&powers.g1[0..r_scalar_vec.len()], &r_scalar_vec);
        let challenge = BigUint::one(); // TODO from hash
        let w_vec: Vec<BigUint> = random_params
            .s_vec
            .iter()
            .zip(&random_params.u_vec)
            .map(|(s, u)| pow_mult_mod(s, &BigUint::one(), u, &challenge, &self.pubkey))
            .collect();
        let z_vec: Vec<BigUint> = random_params
            .r_vec
            .iter()
            .zip(values)
            .map(|(r, val)| {
                let aux = (&challenge * val) % &self.pubkey;
                (r + aux) % &self.pubkey
            })
            .collect();

        PaillierEncryptionProof {
            challenge,
            ct_vec,
            w_vec,
            z_vec,
        }
    }
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
    pow_mult_mod(&(key + BigUint::one()), value, &random, key, &n2)
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
            r_vec.push(RandomBits::new(N_BITS).sample(rng));
        }

        Self {
            u_vec,
            s_vec,
            r_vec,
        }
    }
}

pub struct PaillierEncryptionProof {
    pub challenge: BigUint,
    pub ct_vec: Vec<BigUint>,
    pub w_vec: Vec<BigUint>,
    pub z_vec: Vec<BigUint>,
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::test_rng;

    // TODO fix tests
    #[test]
    fn new_server() {
        let rng = &mut test_rng();
        let server = Server::new(rng);
        assert!(server.pubkey.bits() <= N_BITS);
        assert!(server.privkey.bits() <= N_BITS);
        println!("{}, {}", server.pubkey.bits(), server.privkey.bits());
        println!("{:#?}", server);
    }
}
