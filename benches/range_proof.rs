use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_std::{rand::RngCore, test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const LOG_2_UPPER_BOUND: usize = 32;
const N: usize = Scalar::MODULUS_BIT_SIZE as usize / fde::encrypt::elgamal::MAX_BITS + 1;

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

// NOTE in case of 4096 scalars, we need 4096 * N range proofs for each smaller split scalar
fn bench_multiple_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("range-proof");
    group.sample_size(10);

    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<TestCurve>::unsafe_setup(tau, 4 * LOG_2_UPPER_BOUND);

    let scalars: Vec<Scalar> = (0..4096 * N)
        .map(|_| Scalar::from(rng.next_u32()))
        .collect();
    println!("GENERATING RANGE PROOFS...");
    let now = std::time::Instant::now();
    let proofs = scalars
        .into_iter()
        .enumerate()
        .inspect(|(i, _)| {
            if i % 256 == 0 {
                println!("{}/{}", i, 4096 * N);
            }
        })
        .map(|(_, z)| RangeProof::new(z, LOG_2_UPPER_BOUND, &powers, rng).unwrap())
        .collect::<Vec<RangeProof>>();

    let elapsed = std::time::Instant::now().duration_since(now).as_secs();
    println!("ELAPSED: {} [s]", elapsed);

    for i in 0..=12 {
        let subset_size = 1 << i;
        let range_proof_vfy_name = format!("range-proof-vfy-{}", subset_size);
        group.bench_function(range_proof_vfy_name, |b| {
            b.iter(|| {
                #[cfg(not(feature = "parallel"))]
                unimplemented!();
                #[cfg(feature = "parallel")]
                proofs.par_iter().take(subset_size * N).for_each(|proof| {
                    assert!(proof.verify(LOG_2_UPPER_BOUND, &powers).is_ok());
                });
            })
        });
    }
}

criterion_group!(benches, bench_multiple_proofs, bench_proof);
criterion_main!(benches);
