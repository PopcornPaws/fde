use crate::hash::Hasher;
use ark_ec::CurveGroup;
use ark_poly::univariate::DensePolynomial;
use ark_std::One;
use digest::Digest;
use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;

/// Computes `(a^alpha mod N) * (b^beta mod N) mod N`.
pub fn pow_mult_mod(
    a: &BigUint,
    alpha: &BigUint,
    b: &BigUint,
    beta: &BigUint,
    modulo: &BigUint,
) -> BigUint {
    (a.modpow(alpha, modulo) * b.modpow(beta, modulo)) % modulo
}

/// Modular inverse helper for `BigUint` types. Returns `None` if the inverse does not exist.
///
/// `BigUint`'s`modpow` cannot handle negative exponents, it panics. Thus, we are using the
/// extended GCD algorithm to find the modular inverse of `num`. However, `extended_gcd_lcm` is
/// only implemented for signed types such as `BigInt`, hence the conversions.
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

/// Computes the challenge for the Paillier encryption scheme.
pub fn challenge<C: CurveGroup, D: Digest>(
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

#[cfg(test)]
mod test {
    use super::super::server::Server;
    use super::super::N_BITS;
    use super::*;
    use ark_std::rand::distributions::Distribution;
    use ark_std::test_rng;
    use num_bigint::RandomBits;

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
}
