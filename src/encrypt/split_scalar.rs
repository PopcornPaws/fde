use super::elgamal::{Cipher, MAX_BITS};
use ark_crypto_primitives::encryption::elgamal::{ElGamal, Parameters, Randomness};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_ec::CurveGroup;
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

    pub fn encrypt<R: Rng, C: CurveGroup<ScalarField = S>>(
        self,
        encryption_key: &<ElGamal<C> as AsymmetricEncryptionScheme>::PublicKey,
        rng: &mut R,
    ) -> ([Cipher<C>; N], Randomness<C>) {
        let parameters = Parameters {
            generator: C::Affine::generator(),
        };
        let rands: Vec<S> = (0..N).map(|_| S::rand(rng)).collect();
        let ciphers: Vec<Cipher<C>> = self
            .0
            .iter()
            .zip(&rands)
            .map(|(s, r)| {
                let plaintext = (parameters.generator * s).into_affine();
                let randomness = Randomness(r);
                let ark_cipher = <ElGamal<C> as AsymmetricEncryptionScheme>::encrypt(
                    &parameters,
                    &encryption_key,
                    &plaintext,
                    &randomness,
                );
                Cipher::<C>::from(ark_cipher)
            })
            .collect();

        let shifted_rand_sum = rands.iter().enumerate().fold(S::zero(), |acc, (i, r)| {
            acc + super::shift_scalar(r, MAX_BITS * i)
        });

        // NOTE unwrap is fine because ciphers.len() is always N
        (ciphers.try_into().unwrap(), Randomness(shifted_rand_sum))
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
            let split = S::from_bigint(<S::BigInt as BigInteger>::from_bits_le(chunk)).unwrap();
            output[i] = split;
        }
        Self::new(output)
    }
}
