use ark_ec::{AffineRepr, CurveGroup};
use ark_std::marker::PhantomData;
use ark_std::ops::{Add, Neg};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};

// encryption engines
//pub struct Generic;
//pub struct Paillier;

pub struct ExponentialElGamal<C>(pub PhantomData<C>);

#[derive(Clone, Copy, Debug)]
pub struct ElGamalCipher<C: CurveGroup>([C::Affine; 2]);

impl<C: CurveGroup> ElGamalCipher<C> {
    pub fn c0(&self) -> C::Affine {
        self.0[0]
    }

    pub fn c1(&self) -> C::Affine {
        self.0[1]
    }
}

impl<C: CurveGroup> Add for ElGamalCipher<C> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self([
            (self.c0() + rhs.c0()).into_affine(),
            (self.c1() + rhs.c1()).into_affine(),
        ])
    }
}

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
    fn decrypt(cipher: Self::Cipher, key: &Self::DecryptionKey) -> Self::PlainText;
}

impl<C: CurveGroup> EncryptionEngine for ExponentialElGamal<C>
where
    C::Affine: Neg<Output = C::Affine>,
{
    type EncryptionKey = C::Affine;
    type DecryptionKey = C::ScalarField;
    type Cipher = ElGamalCipher<C>;
    type PlainText = C::ScalarField;

    fn encrypt<R: Rng>(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        rng: &mut R,
    ) -> Self::Cipher {
        let random_nonce = C::ScalarField::rand(rng);
        Self::encrypt_with_randomness(data, key, random_nonce)
    }

    fn decrypt(cipher: Self::Cipher, key: &Self::DecryptionKey) -> Self::PlainText {
        let decrypted_exp = Self::decrypt_exp(cipher, key);
        Self::brute_force(decrypted_exp)
    }
}

impl<C: CurveGroup> ExponentialElGamal<C>
where
    C::Affine: Neg<Output = C::Affine>,
{
    fn encrypt_with_randomness(
        data: &C::ScalarField,
        key: &C::Affine,
        randomness: C::ScalarField,
    ) -> ElGamalCipher<C> {
        let shared_secret = *key * randomness;
        let c1 = <C::Affine as AffineRepr>::generator() * randomness;
        let c2 = <C::Affine as AffineRepr>::generator() * data + shared_secret;
        ElGamalCipher([c1.into_affine(), c2.into_affine()])
    }

    fn decrypt_exp(cipher: ElGamalCipher<C>, key: &C::ScalarField) -> C::Affine {
        let shared_secret = (cipher.c0() * key).into_affine();
        (cipher.c1() + shared_secret.neg()).into_affine()
    }

    fn brute_force(decrypted: C::Affine) -> C::ScalarField {
        let mut exponent = C::ScalarField::zero();
        while (<C::Affine as AffineRepr>::generator() * exponent).into_affine() != decrypted {
            exponent += C::ScalarField::one();
        }
        exponent
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::Group;
    use ark_std::test_rng;
    use bls::{Fr, G1Projective as BlsG1};

    type Engine = ExponentialElGamal<BlsG1>;

    #[test]
    fn exponential_elgamal() {
        let rng = &mut test_rng();
        let decryption_key = Fr::rand(rng);
        let encryption_key = (BlsG1::generator() * decryption_key).into_affine();

        // completeness
        let data = Fr::from(12342526u32);
        let encrypted = Engine::encrypt(&data, &encryption_key, rng);
        let decrypted = Engine::decrypt_exp(encrypted, &decryption_key);
        assert_eq!(decrypted, (BlsG1::generator() * data).into_affine());
        // soundness
        let data = Fr::from(12342526u32);
        let invalid_decryption_key = decryption_key + Fr::from(123u32);
        let encrypted = Engine::encrypt(&data, &encryption_key, rng);
        let decrypted = Engine::decrypt_exp(encrypted, &invalid_decryption_key);
        assert_ne!(decrypted, (BlsG1::generator() * data).into_affine());

        // with brute force check
        let data = Fr::from(12u32);
        let encrypted = Engine::encrypt(&data, &encryption_key, rng);
        let decrypted = Engine::decrypt(encrypted, &decryption_key);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn elgamal_homomorphism() {
        let a = Fr::from(1u8);
        let b = Fr::from(10u8);
        let c = Fr::from(100u8);
        let ra = Fr::from(2u8);
        let rb = Fr::from(20u8);
        let rc = Fr::from(200u8);

        let decryption_key = Fr::from(1234567);
        let encryption_key = (BlsG1::generator() * decryption_key).into_affine();

        let ea = Engine::encrypt_with_randomness(&a, &encryption_key, ra);
        let eb = Engine::encrypt_with_randomness(&b, &encryption_key, rb);
        let ec = Engine::encrypt_with_randomness(&c, &encryption_key, rc);

        let sum = a + b + c;
        let rsum = ra + rb + rc;
        let esum = ea + eb + ec;

        assert_eq!(esum.c0(), BlsG1::generator() * rsum);
        assert_eq!(esum.c1(), BlsG1::generator() * sum + encryption_key * rsum);
    }
}
