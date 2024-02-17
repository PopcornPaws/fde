use ark_ec::pairing::Pairing;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const LOG_2_UPPER_BOUND: usize = 8; // 2^8

type TestCurve = ark_bls12_381::Bls12_381;
type TestHash = sha3::Keccak256;
type Scalar = <TestCurve as Pairing>::ScalarField;
type RangeProof = fde::range_proof::RangeProof<TestCurve, TestHash>;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("range-proof");

    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<TestCurve>::unsafe_setup(tau, 4 * LOG_2_UPPER_BOUND);

    let z = Scalar::from(100u32);

    group.bench_function("proof-gen", |b| {
        b.iter(|| {
            let _proof = RangeProof::new(z, LOG_2_UPPER_BOUND, &powers, rng).unwrap();
        })
    });

    group.bench_function("proof-vfy", |b| {
        let proof = RangeProof::new(z, LOG_2_UPPER_BOUND, &powers, rng).unwrap();
        b.iter(|| assert!(proof.verify(LOG_2_UPPER_BOUND, &powers).is_ok()))
    });

    group.finish();
}

fn bench_multiple_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("range-proof");
    group.sample_size(10);

    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<TestCurve>::unsafe_setup(tau, 4 * LOG_2_UPPER_BOUND);

    let max_u32 = Scalar::from(1 << LOG_2_UPPER_BOUND);
    assert_eq!(max_u32, Scalar::from(u32::MAX));
    let scalars: Vec<Scalar> = (0..4096).map(|_| Scalar::rand(rng) % max_u32).collect();

    for i in 0..=12 {
        let subset_size = 1 << i;
        let verify_split_encryption_name = format!("verify-split-encryption-{}", subset_size);
        group.bench_function(verify_split_encryption_name, |b| {
        
    group.bench_function("proof-gen", |b| {
        b.iter(|| {
            let _proof = RangeProof::new(z, LOG_2_UPPER_BOUND, &powers, rng).unwrap();
        })
    });

    group.bench_function("proof-vfy", |b| {
        let proof = RangeProof::new(z, LOG_2_UPPER_BOUND, &powers, rng).unwrap();
        b.iter(|| assert!(proof.verify(LOG_2_UPPER_BOUND, &powers).is_ok()))
    });



}

criterion_group!(benches, bench_proof, bench_multiple_proofs);
criterion_main!(benches);
