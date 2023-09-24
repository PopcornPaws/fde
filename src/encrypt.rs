use ark_ec::{AffineRepr, CurveGroup};
use ark_std::marker::PhantomData;
use ark_std::ops::Neg;
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};

// encryption engines
//pub struct Generic;
pub struct ExponentialElGamal<C>(pub PhantomData<C>);
//pub struct Paillier;

pub trait EncryptionEngine {
    type EncryptionKey;
    type DecryptionKey;
    type CipherText;
    type PlainText;
    fn encrypt<R: Rng>(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        rng: &mut R,
    ) -> Self::CipherText;
    fn decrypt(cipher: Self::CipherText, key: &Self::DecryptionKey) -> Self::PlainText;
}

//pub trait HomomorphicEncryptionEngine: EncryptionEngine {
//    fn add(lhs: <Self as EncryptionEngine>::CipherText, rhs:<Self as EncryptionEngine>::CipherText) -> <Self as EncryptionEngine>::CipherText;
//}
//
//impl<T: HomomorphicEncryptionEngine> Add for T {
//    type Output = <Self as EncryptionEngine>::CipherText;
//    fn add(self, rhs: T) -> Self::Output {
//        Self::add(
//    }
//}

//impl EncryptionEngine for Generic {
//    type EncryptionKey = ();
//    type DecryptionKey = ();
//    type PlainText = Vec<u8>;
//    type CipherText = Vec<u8>;
//    fn encrypt(data: &Self::PlainText, key: &Self::EncryptionKey) -> Self::CipherText {
//        Vec::new()
//    }
//    fn decrypt(cipher: Self::CipherText, key: &Self::DecryptionKey) -> Vec<u8> {
//        Vec::new()
//    }
//}

impl<C> ExponentialElGamal<C> {
    fn new<C>() -> Self {
        Self(PhantomData)
    }
}

impl<C: CurveGroup> EncryptionEngine for ExponentialElGamal<C>
where
    C::Affine: Neg<Output = C::Affine>,
{
    type EncryptionKey = C::Affine;
    type DecryptionKey = C::ScalarField;
    type CipherText = (C::Affine, C::Affine);
    type PlainText = C::ScalarField;

    fn encrypt<R: Rng>(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        rng: &mut R,
    ) -> Self::CipherText {
        let random_nonce = C::ScalarField::rand(rng);
        let shared_secret = *key * random_nonce;
        let c1 = <C::Affine as AffineRepr>::generator() * random_nonce;
        let c2 = <C::Affine as AffineRepr>::generator() * data + shared_secret;
        (c1.into_affine(), c2.into_affine())
    }

    fn decrypt(cipher: Self::CipherText, key: &Self::DecryptionKey) -> Self::PlainText {
        let shared_secret = (cipher.0 * key).into_affine();
        let exponential = cipher.1 + shared_secret.neg();
        // brute forcing
        let mut decrypted = C::ScalarField::zero();
        while <C::Affine as AffineRepr>::generator() * decrypted != exponential {
            decrypted += C::ScalarField::one();
        }
        decrypted
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn exponential_elgamal() {
        let engine = ExponentialElGamal::<>::new();
    }
}
