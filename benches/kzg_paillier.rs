use ark_bls12_381::Bls12_381 as BlsCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;

type Scalar = <BlsCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::veck::kzg_paillier::Proof<{ N }, BlsCurve, sha3::Keccak256>;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-paillier");

    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, data_size + 1);

    todo!()
    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
