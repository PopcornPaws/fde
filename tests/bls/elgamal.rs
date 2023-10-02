use crate::*;
use ark_ec::{AffineRepr, CurveGroup};
use fdx::encrypt::EncryptionEngine;

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
    let split_scalar = SpScalar::from(scalar);
    let secret = Scalar::rand(rng);
    let encryption_key = (G1Affine::generator() * secret).into_affine();

    let (ciphers, randomness) = split_scalar.encrypt::<Elgamal, _>(&encryption_key, rng);

    let cipher = Elgamal::encrypt_with_randomness(&scalar, &encryption_key, &randomness);

    assert!(cipher.check_encrypted_sum::<{ MAX_BITS }>(&ciphers));
}
