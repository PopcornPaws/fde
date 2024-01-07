use num_bigint::{BigUint, RandomBits};
use num_integer::Integer;
use num_prime::nt_funcs::prev_prime;
use num_traits::One;

use ark_std::rand::distributions::Distribution;
use ark_std::rand::Rng;

#[derive(Debug)]
pub struct Server {
    pub pubkey: BigUint,
    pub privkey: BigUint,
}

impl Server {
    pub fn new<R: Rng>(n_bits: u64, rng: &mut R) -> Self {
        let (p, q) = primes(n_bits, rng);
        let pubkey = &p * &q;
        let privkey = (p - BigUint::one()).lcm(&(q - BigUint::one()));

        Self { pubkey, privkey }
    }
}

pub fn primes<R: Rng>(n_bits: u64, rng: &mut R) -> (BigUint, BigUint) {
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

#[cfg(test)]
mod test {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn flow() {
        let rng = &mut test_rng();
        let server = Server::new(512, rng);
        println!("{:#?}", server);
    }
}
