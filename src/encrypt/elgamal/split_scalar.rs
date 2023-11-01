use super::utils::shift_scalar;
use super::MAX_BITS;
use crate::encrypt::EncryptionEngine;
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_std::rand::Rng;

#[derive(Clone, Copy, Debug)]
pub struct SplitScalar<const N: usize, S>([S; N]);

impl<const N: usize, S: PrimeField> SplitScalar<N, S> {
    pub fn new(inner: [S; N]) -> Self {
        Self(inner)
    }

    pub fn reconstruct(&self) -> S {
        self.splits()
            .iter()
            .enumerate()
            .fold(S::zero(), |acc, (i, split)| {
                let shift = shift_scalar(split, MAX_BITS * i);
                acc + shift
            })
    }

    pub fn encrypt<E, R>(
        self,
        encryption_key: &E::EncryptionKey,
        rng: &mut R,
    ) -> ([E::Cipher; N], S)
    where
        E: EncryptionEngine<PlainText = S>,
        E::Cipher: ark_std::fmt::Debug,
        R: Rng,
    {
        let rands: Vec<S> = (0..N).map(|_| S::rand(rng)).collect();
        let ciphers: Vec<E::Cipher> = self
            .0
            .iter()
            .zip(&rands)
            .map(|(s, r)| E::encrypt_with_randomness(s, encryption_key, r))
            .collect();

        let shifted_rand_sum = rands
            .iter()
            .enumerate()
            .fold(S::zero(), |acc, (i, r)| acc + shift_scalar(r, MAX_BITS * i));

        // NOTE unwrap is fine because ciphers.len() is always N
        (ciphers.try_into().unwrap(), shifted_rand_sum)
    }

    pub fn splits(&self) -> &[S; N] {
        &self.0
    }
}

impl<const N: usize, S: PrimeField> From<S> for SplitScalar<N, S> {
    fn from(scalar: S) -> Self {
        let scalar_le_bytes = scalar.into_bigint().to_bits_le();
        let mut output = [S::zero(); N];

        for (i, chunk) in scalar_le_bytes.chunks(MAX_BITS).enumerate() {
            let split = S::from_bigint(<S::BigInt as BigInteger>::from_bits_le(chunk))
                .expect("should not fail");
            output[i] = split;
        }
        Self::new(output)
    }
}

#[cfg(test)]
mod test {
    use crate::encrypt::elgamal::MAX_BITS;
    use crate::encrypt::EncryptionEngine;
    use crate::tests::{Elgamal, Scalar, SplitScalar, G1Affine};
    use ark_ec::{CurveGroup, AffineRepr};
    use ark_std::{test_rng, UniformRand, Zero};

    #[test]
    fn scalar_splitting() {
        let scalar = Scalar::zero();
        let split_scalar = SplitScalar::from(scalar);
        println!("{:?}", split_scalar);
        let reconstructed_scalar = split_scalar.reconstruct();
        assert_eq!(scalar, reconstructed_scalar);

        let rng = &mut test_rng();
        let max_scalar = Scalar::from(u32::MAX);
        for _ in 0..10 {
            let scalar = Scalar::rand(rng);
            let split_scalar = SplitScalar::from(scalar);
            for split in split_scalar.splits() {
                assert!(split <= &max_scalar);
            }
            let reconstructed_scalar = split_scalar.reconstruct();
            assert_eq!(scalar, reconstructed_scalar);
        }
    }

    #[test]
    fn encryption() {
        let rng = &mut test_rng();
        let encryption_pk =
            (G1Affine::generator() * Scalar::rand(rng)).into_affine();
        let scalar = Scalar::rand(rng);
        let split_scalar = SplitScalar::from(scalar);

        let (short_ciphers, elgamal_r) = split_scalar.encrypt::<Elgamal, _>(&encryption_pk, rng);
        let long_cipher = <Elgamal as EncryptionEngine>::encrypt_with_randomness(
            &scalar,
            &encryption_pk,
            &elgamal_r,
        );

        assert!(long_cipher.check_encrypted_sum::<{ MAX_BITS }>(&short_ciphers));
    }
}
