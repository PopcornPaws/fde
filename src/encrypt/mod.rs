pub mod elgamal;
pub mod split_scalar;

use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_std::rand::Rng;

// other possible encryption engines
//pub struct Generic;
//pub struct Paillier;

pub trait EncryptionEngine {
    type EncryptionKey;
    type DecryptionKey;
    type Cipher;
    type PlainText;
    fn encrypt<R: Rng>(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        rng: &mut R,
    ) -> Self::Cipher;
    fn encrypt_with_randomness(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        randomness: &Self::PlainText,
    ) -> Self::Cipher;
    fn decrypt(cipher: Self::Cipher, key: &Self::DecryptionKey) -> Self::PlainText;
}

fn shift_scalar<S: PrimeField>(scalar: &S, by: usize) -> S {
    let mut bigint = S::one().into_bigint();
    bigint.muln(by as u32);
    *scalar * S::from_bigint(bigint).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{One, Zero};

    #[test]
    fn scalar_shifting() {
        let scalar = Fr::zero();
        assert_eq!(shift_scalar(&scalar, 32), Fr::zero());

        let scalar = Fr::one();
        assert_eq!(
            shift_scalar(&scalar, 32),
            Fr::from(u64::from(u32::MAX) + 1u64)
        );

        // shifting with overflow
        // according to the docs, overflow is
        // ignored
        let scalar = Fr::one();
        assert_eq!(shift_scalar(&scalar, u32::MAX as usize), Fr::zero());
    }
}
