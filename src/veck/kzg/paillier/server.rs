use super::N_BITS;
use ark_std::rand::distributions::Distribution;
use ark_std::rand::Rng;
use ark_std::One;
use num_bigint::{BigUint, RandomBits};
use num_integer::Integer;
use num_prime::nt_funcs::prev_prime;

/// A simulated server instance tailored for the Paillier encryption scheme.
#[derive(Debug)]
pub struct Server {
    pub p_prime: BigUint,
    pub q_prime: BigUint,
    pub privkey: BigUint,
    pub pubkey: BigUint,
    pub mod_n2: BigUint,
}

impl Server {
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        // generate small enough primes so that their product fits
        // "N_BITS" number of bits
        let (p, q) = primes(N_BITS >> 1, rng);
        let pubkey = &p * &q;
        let privkey = (&p - BigUint::one()).lcm(&(&q - BigUint::one()));
        let mod_n2 = &pubkey * &pubkey;

        Self {
            p_prime: p,
            q_prime: q,
            privkey,
            pubkey,
            mod_n2,
        }
    }

    /// Helper function to compute L(x) = (x - 1) / N
    pub fn lx(&self, x: &BigUint) -> BigUint {
        debug_assert!(x < &self.mod_n2 && (x % &self.pubkey) == BigUint::one());
        (x - BigUint::one()) / &self.pubkey
    }

    /// Helper function to compute the denominator in the Paillier decryption scheme equation.
    ///
    /// x = (N + 1)^{sk} mod N^2
    /// L(x) = (x - 1) / N
    pub fn decryption_denominator(&self) -> BigUint {
        let n_plus_1_pow_sk = (&self.pubkey + BigUint::one()).modpow(&self.privkey, &self.mod_n2);
        self.lx(&n_plus_1_pow_sk)
    }
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
