use crate::*;
use ark_ec::{CurveGroup, Group};
use fdx::encrypt::elgamal::MAX_BITS;
use fdx::encrypt::EncryptionEngine;

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
    let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * Scalar::rand(rng)).into_affine();
    let scalar = Scalar::rand(rng);
    let split_scalar = SplitScalar::from(scalar);

    let (short_ciphers, elgamal_r) = split_scalar.encrypt::<Elgamal, _>(&encryption_pk, rng);
    let long_cipher =
        <Elgamal as EncryptionEngine>::encrypt_with_randomness(&scalar, &encryption_pk, &elgamal_r);

    assert!(long_cipher.check_encrypted_sum::<{ MAX_BITS }>(&short_ciphers));
}
