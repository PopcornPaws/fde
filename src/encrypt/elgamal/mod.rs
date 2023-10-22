mod split_scalar;
mod utils;

pub use split_scalar::SplitScalar;
use utils::shift_scalar;

use super::EncryptionEngine;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::marker::PhantomData;
use ark_std::ops::{Add, Mul};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};

pub const MAX_BITS: usize = 32;

pub struct ExponentialElgamal<C>(pub PhantomData<C>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cipher<C: CurveGroup>([C::Affine; 2]);

impl<C: CurveGroup> Zero for Cipher<C> {
    fn zero() -> Self {
        Self([C::Affine::zero(); 2])
    }
    fn is_zero(&self) -> bool {
        self.c0().is_zero() && self.c1().is_zero()
    }
}

impl<C: CurveGroup> Cipher<C> {
    pub fn c0(&self) -> C::Affine {
        self.0[0]
    }

    pub fn c1(&self) -> C::Affine {
        self.0[1]
    }

    pub fn check_encrypted_sum<const B: usize>(&self, ciphers: &[Self]) -> bool {
        let ciphers_sum = ciphers
            .iter()
            .enumerate()
            .fold(Self::zero(), |acc, (i, c)| {
                acc + *c * shift_scalar(&C::ScalarField::one(), B * i)
            });
        ciphers_sum == *self
    }
}

impl<C: CurveGroup> Add for Cipher<C> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self([
            (self.c0() + rhs.c0()).into_affine(),
            (self.c1() + rhs.c1()).into_affine(),
        ])
    }
}

impl<C: CurveGroup> Mul<C::ScalarField> for Cipher<C> {
    type Output = Self;
    fn mul(self, rhs: C::ScalarField) -> Self::Output {
        Self([
            (self.c0() * rhs).into_affine(),
            (self.c1() * rhs).into_affine(),
        ])
    }
}

impl<C: CurveGroup> EncryptionEngine for ExponentialElgamal<C> {
    type EncryptionKey = C::Affine;
    type DecryptionKey = C::ScalarField;
    type Cipher = Cipher<C>;
    type PlainText = C::ScalarField;

    fn encrypt<R: Rng>(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        rng: &mut R,
    ) -> Self::Cipher {
        let random_nonce = C::ScalarField::rand(rng);
        Self::encrypt_with_randomness(data, key, &random_nonce)
    }

    fn encrypt_with_randomness(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        randomness: &Self::PlainText,
    ) -> Self::Cipher {
        let shared_secret = *key * randomness;
        let c1 = <C::Affine as AffineRepr>::generator() * randomness;
        let c2 = <C::Affine as AffineRepr>::generator() * data + shared_secret;
        Cipher([c1.into_affine(), c2.into_affine()])
    }

    fn decrypt(cipher: Self::Cipher, key: &Self::DecryptionKey) -> Self::PlainText {
        let decrypted_exp = Self::decrypt_exp(cipher, key);
        Self::brute_force(decrypted_exp)
    }
}

impl<C: CurveGroup> ExponentialElgamal<C> {
    pub fn decrypt_exp(cipher: Cipher<C>, key: &C::ScalarField) -> C::Affine {
        let shared_secret = (cipher.c0() * key).into_affine();
        // AffineRepr has to be converted into a Group element in order to perform subtraction but
        // I believe this is optimized away in release mode
        (cipher.c1().into() - shared_secret.into()).into_affine()
    }

    pub fn brute_force(decrypted: C::Affine) -> C::ScalarField {
        let max = C::ScalarField::from(u32::MAX);
        let mut exponent = C::ScalarField::zero();

        while (<C::Affine as AffineRepr>::generator() * exponent).into_affine() != decrypted
            && exponent < max
        {
            exponent += C::ScalarField::one();
        }
        exponent
    }
}
