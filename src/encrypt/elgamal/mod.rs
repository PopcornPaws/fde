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

/// Exponential Elgamal encryption scheme ciphertext.
///
/// It contains `c1 = g^y` and `c2 = g^m * h^y` where `g` is a group generator, `h = g^x` is the
/// public encryption key computed from the secret `x` key, `y` is some random scalar and `m` is
/// the message to be encrypted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cipher<C: CurveGroup>([C::Affine; 2]);

impl<C: CurveGroup> Default for Cipher<C> {
    fn default() -> Self {
        Self::zero()
    }
}

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

    pub fn check_encrypted_sum(&self, ciphers: &[Self]) -> bool {
        let ciphers_sum = ciphers
            .iter()
            .enumerate()
            .fold(Self::zero(), |acc, (i, c)| {
                acc + *c * shift_scalar(&C::ScalarField::one(), MAX_BITS * i)
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
        // h^y
        let shared_secret = *key * randomness;
        // g^y
        let c1 = <C::Affine as AffineRepr>::generator() * randomness;
        // g^m * h^y
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{G1Affine, Scalar, TestCurve, N};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::{test_rng, UniformRand};

    type Elgamal = ExponentialElgamal<<TestCurve as Pairing>::G1>;

    #[test]
    fn exponential_elgamal() {
        let rng = &mut test_rng();
        let decryption_key = Scalar::rand(rng);
        let encryption_key = (G1Affine::generator() * decryption_key).into_affine();

        // completeness
        let data = Scalar::from(12342526u32);
        let encrypted = Elgamal::encrypt(&data, &encryption_key, rng);
        let decrypted = Elgamal::decrypt_exp(encrypted, &decryption_key);
        assert_eq!(decrypted, (G1Affine::generator() * data).into_affine());
        // soundness
        let data = Scalar::from(12342526u32);
        let invalid_decryption_key = decryption_key + Scalar::from(123u32);
        let encrypted = Elgamal::encrypt(&data, &encryption_key, rng);
        let decrypted = Elgamal::decrypt_exp(encrypted, &invalid_decryption_key);
        assert_ne!(decrypted, (G1Affine::generator() * data).into_affine());

        // with brute force check
        let data = Scalar::from(12u32);
        let encrypted = Elgamal::encrypt(&data, &encryption_key, rng);
        let decrypted = Elgamal::decrypt(encrypted, &decryption_key);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn elgamal_homomorphism() {
        let a = Scalar::from(16u8);
        let b = Scalar::from(10u8);
        let c = Scalar::from(100u8);
        let ra = Scalar::from(2u8);
        let rb = Scalar::from(20u8);
        let rc = Scalar::from(200u8);

        let decryption_key = Scalar::from(1234567);
        let encryption_key = (G1Affine::generator() * decryption_key).into_affine();

        let ea = Elgamal::encrypt_with_randomness(&a, &encryption_key, &ra);
        let eb = Elgamal::encrypt_with_randomness(&b, &encryption_key, &rb);
        let ec = Elgamal::encrypt_with_randomness(&c, &encryption_key, &rc);

        let sum = a + b + c;
        let rsum = ra + rb + rc;
        let esum = ea + eb + ec;

        assert_eq!(esum.c0(), G1Affine::generator() * rsum);
        assert_eq!(
            esum.c1(),
            G1Affine::generator() * sum + encryption_key * rsum
        );

        let ma = Scalar::from(3u8);
        let mb = Scalar::from(4u8);
        let mc = Scalar::from(5u8);

        let sum = ma * a + mb * b + mc * c;
        let rsum = ma * ra + mb * rb + mc * rc;
        let esum = ea * ma + eb * mb + ec * mc;

        assert_eq!(esum.c0(), G1Affine::generator() * rsum);
        assert_eq!(
            esum.c1(),
            G1Affine::generator() * sum + encryption_key * rsum
        );
    }

    #[test]
    fn split_encryption() {
        let rng = &mut test_rng();
        let scalar = Scalar::rand(rng);
        let split_scalar = SplitScalar::<{ N }, Scalar>::from(scalar);
        let secret = Scalar::rand(rng);
        let encryption_key = (G1Affine::generator() * secret).into_affine();

        let (ciphers, randomness) = split_scalar.encrypt::<Elgamal, _>(&encryption_key, rng);

        let cipher = Elgamal::encrypt_with_randomness(&scalar, &encryption_key, &randomness);

        assert!(cipher.check_encrypted_sum(&ciphers));
    }
}
