use super::EncryptionEngine;
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;
use ark_std::rand::Rng;

#[derive(Clone, Copy, Debug)]
pub struct SplitScalar<const N: usize, const M: usize, S>([S; N]);

impl<const N: usize, const M: usize, S: PrimeField> SplitScalar<N, M, S> {
    pub fn new(inner: [S; N]) -> Self {
        Self(inner)
    }

    pub fn reconstruct(&self) -> S {
        self.splits()
            .iter()
            .enumerate()
            .fold(S::zero(), |acc, (i, split)| {
                let shift = shift_scalar(split, (M * i) as u32);
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
        let rands: Vec<S> = (0..N).into_iter().map(|_| S::rand(rng)).collect();
        let ciphers: Vec<E::Cipher> = self
            .0
            .iter()
            .zip(&rands)
            .map(|(s, r)| E::encrypt_with_randomness(s, encryption_key, r))
            .collect();

        let shifted_rand_sum = rands.iter().enumerate().fold(S::zero(), |acc, (i, r)| {
            acc + shift_scalar(r, (M * i) as u32)
        });

        // NOTE unwrap is fine because ciphers.len() is always N
        (ciphers.try_into().unwrap(), shifted_rand_sum)
    }

    pub fn splits(&self) -> &[S; N] {
        &self.0
    }
}

impl<const N: usize, const M: usize, S: PrimeField> From<S> for SplitScalar<N, M, S> {
    fn from(scalar: S) -> Self {
        let scalar_le_bytes = scalar.into_bigint().to_bits_le();
        let mut output = [S::zero(); N];

        for (i, chunk) in scalar_le_bytes.chunks(M).enumerate() {
            let split = S::from_bigint(<S::BigInt as BigInteger>::from_bits_le(chunk)).unwrap();
            output[i] = split;
        }
        Self::new(output)
    }
}

fn shift_scalar<S: PrimeField>(scalar: &S, by: u32) -> S {
    let mut bigint = S::one().into_bigint();
    bigint.muln(by);
    *scalar * S::from_bigint(bigint).unwrap()
}

// TODO move this to elgamal cipher
//pub fn check_encrypted_sum<const B: usize, E: EncryptionEngine>(
//    cipher: &E::Cipher,
//    ciphers: &[E::Cipher],
//) -> bool {
//    let ciphers_sum = ciphers
//        .iter()
//        .enumerate()
//        .fold(Cipher::zero(), |acc, (i, c)| {
//            acc + c * shift_scalar(&Scalar::one(), (B * i) as u32)
//        });
//    ciphers_sum == cipher
//}

#[cfg(test)]
mod test {
    use super::*;
    use crate::encrypt::elgamal::{Cipher, ExponentialElgamal, MAX_BITS};
    use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::{test_rng, One, UniformRand, Zero};

    type Scalar = <BlsCurve as Pairing>::ScalarField;
    type SpScalar = SplitScalar<{ Scalar::MODULUS_BIT_SIZE as usize }, MAX_BITS, Scalar>;
    type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;

    #[test]
    fn scalar_shifting() {
        let scalar = Scalar::zero();
        assert_eq!(shift_scalar(&scalar, 32), Scalar::zero());

        let scalar = Scalar::one();
        assert_eq!(
            shift_scalar(&scalar, 32),
            Scalar::from(u64::from(u32::MAX) + 1u64)
        );

        // shifting with overflow
        // according to the docs, overflow is
        // ignored
        let scalar = Scalar::one();
        assert_eq!(shift_scalar(&scalar, u32::MAX), Scalar::zero());
    }

    #[test]
    fn scalar_splitting() {
        let scalar = Scalar::zero();
        let split_scalar = SpScalar::from(scalar);
        let reconstructed_scalar = split_scalar.reconstruct();
        assert_eq!(scalar, reconstructed_scalar);

        let rng = &mut test_rng();
        let max_scalar = Scalar::from(u32::MAX);
        for _ in 0..10 {
            let scalar = Scalar::rand(rng);
            let split_scalar = SpScalar::from(scalar);
            for split in split_scalar.splits() {
                assert!(split <= &max_scalar);
            }
            let reconstructed_scalar = split_scalar.reconstruct();
            assert_eq!(scalar, reconstructed_scalar);
        }
    }

    #[test]
    fn split_encryption() {
        let rng = &mut test_rng();
        let scalar = Scalar::rand(rng);
        let split_scalar = SpScalar::from(scalar);
        let secret = Scalar::rand(rng);
        let encryption_key = (G1Affine::generator() * secret).into_affine();

        let (ciphers, randomness) = split_scalar.encrypt::<Elgamal, _>(&encryption_key, rng);

        let cipher = Elgamal::encrypt_with_randomness(&scalar, &encryption_key, &randomness);

        assert!(check_encrypted_sum(&cipher, &ciphers));
    }
}
