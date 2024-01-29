use super::N_BITS;
use ark_std::rand::distributions::Distribution;
use ark_std::rand::Rng;
use num_bigint::{BigUint, RandomBits};

pub struct RandomParameters {
    pub u_vec: Vec<BigUint>,
    pub s_vec: Vec<BigUint>,
    pub r_vec: Vec<BigUint>,
}

impl RandomParameters {
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
