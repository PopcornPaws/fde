use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::univariate::DensePolynomial;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fdx::commit::kzg::Powers;

type Scalar = <BlsCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fdx::backend::elgamalkzg_multi::Proof<BlsCurve, UniPoly, sha3::Keccak256>;
type ProofInput = fdx::backend::elgamalkzg_multi::PublicProofInput<BlsCurve>;

const D: usize = 4096;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("elgamal-kzg-multi");

    let rng = &mut test_rng();
    // kzg setup
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, D);

    // encryption secret key
    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (G1Affine::generator() * encryption_sk).into_affine();

    // polynomial
    let data = (0..D).map(|_| Scalar::rand(rng)).collect::<Vec<Scalar>>();
    let input = ProofInput::new(data, &encryption_pk, rng);
    let f_poly: UniPoly = input.interpolate();
    let com_f_poly = powers.commit_g1(&f_poly);

    group.bench_function("proof-gen", |b| {
        b.iter(|| {
            Proof::new(&f_poly, &input, &encryption_sk, &powers, rng);
        })
    });

    group.bench_function("proof-vfy", |b| {
        let proof = Proof::new(&f_poly, &input, &encryption_sk, &powers, rng);
        b.iter(|| {
            proof.verify(com_f_poly, &input, encryption_pk, &powers);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
