use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::encrypt::EncryptionEngine;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// TODO do this for multiple ciphers in parallel
const N: usize = Scalar::MODULUS_BIT_SIZE as usize / fde::encrypt::elgamal::MAX_BITS + 1;

type Scalar = <BlsCurve as Pairing>::ScalarField;
type SplitScalar = fde::encrypt::elgamal::SplitScalar<{ N }, Scalar>;
type Elgamal = fde::encrypt::elgamal::ExponentialElgamal<<BlsCurve as Pairing>::G1>;

const D: usize = 32;

fn bench_elgamal(c: &mut Criterion) {
    let mut group = c.benchmark_group("split-elgamal");

    let rng = &mut test_rng();
    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (G1Affine::generator() * encryption_sk).into_affine();

    let scalars: Vec<Scalar> = (0..D).map(|_| Scalar::rand(rng)).collect();

    let mut ciphers = Vec::with_capacity(scalars.len());
    let mut split_ciphers = Vec::with_capacity(scalars.len());

    scalars.iter().for_each(|scalar| {
        let split_scalar = SplitScalar::from(*scalar);
        let (split_cipher, randomness) = split_scalar.encrypt::<Elgamal, _>(&encryption_pk, rng);
        let long_cipher = <Elgamal as EncryptionEngine>::encrypt_with_randomness(
            &scalar,
            &encryption_pk,
            &randomness,
        );

        ciphers.push(long_cipher);
        split_ciphers.push(split_cipher);
    });

    group.bench_function("encrypt-scalars", |b| {
        b.iter(|| {
            #[cfg(not(feature = "parallel"))]
            scalars.iter().for_each(|scalar| {
                let split_scalar = SplitScalar::from(*scalar);
                split_scalar.encrypt::<Elgamal, _>(&encryption_pk, rng);
            });
            #[cfg(feature = "parallel")]
            scalars.par_iter().for_each(|scalar| {
                let rng = &mut test_rng();
                let split_scalar = SplitScalar::from(*scalar);
                split_scalar.encrypt::<Elgamal, _>(&encryption_pk, rng);
            });
        })
    });

    group.bench_function("verify-split-encryption", |b| {
        b.iter(|| {
            #[cfg(not(feature = "parallel"))]
            ciphers
                .iter()
                .zip(&split_ciphers)
                .for_each(|(cipher, split_cipher)| {
                    assert!(cipher.check_encrypted_sum(split_cipher));
                });
            #[cfg(feature = "parallel")]
            ciphers
                .par_iter()
                .zip(&split_ciphers)
                .for_each(|(long_cipher, split_cipher)| {
                    assert!(long_cipher.check_encrypted_sum(split_cipher));
                });
        })
    });

    group.finish()
}

criterion_group!(benches, bench_elgamal);
criterion_main!(benches);
