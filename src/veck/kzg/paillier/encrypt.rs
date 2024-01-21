use super::utils::pow_mult_mod;
use ark_std::One;
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

pub fn encrypt(value: &BigUint, key: &BigUint, random: &BigUint) -> BigUint {
    let n2 = key * key;
    pow_mult_mod(&(key + BigUint::one()), value, random, key, &n2)
}

#[cfg(not(feature = "parallel"))]
pub fn batch<T: AsRef<[BigUint]>>(values: T, key: &BigUint, randoms: T) -> Vec<BigUint> {
    values
        .as_ref()
        .iter()
        .zip(randoms.as_ref())
        .map(|(val, rand)| encrypt(val, key, rand))
        .collect()
}

#[cfg(feature = "parallel")]
pub fn batch<T>(values: T, key: &BigUint, randoms: T) -> Vec<BigUint>
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
