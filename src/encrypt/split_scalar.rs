use super::elgamal::MAX_BITS;
use super::EncryptionEngine;
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
                let shift = super::shift_scalar(split, MAX_BITS * i);
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

        let shifted_rand_sum = rands.iter().enumerate().fold(S::zero(), |acc, (i, r)| {
            acc + super::shift_scalar(r, MAX_BITS * i)
        });

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
