use ark_bls12_381::Bls12_381 as BlsCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / fde::encrypt::elgamal::MAX_BITS + 1;

type Scalar = <BlsCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::backend::kzg_elgamal::Proof<BlsCurve, UniPoly, sha3::Keccak256>;
type PublicProofInput = fde::backend::kzg_elgamal::PublicProofInput<{ N }, BlsCurve>;

const D: usize = 512;
//const N: usize = 512;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-elgamal");
    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, D);

    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    let data: Vec<Scalar> = (0..D).map(|_| Scalar::rand(rng)).collect();
    let domain = GeneralEvaluationDomain::new(data.len()).unwrap();
    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);

    let input = PublicProofInput::new(&evaluations.evals, &encryption_pk, rng);

    group.bench_function("proof-gen", |b| {
        b.iter(|| {
            Proof::new(
                &f_poly,
                &input.domain,
                &input.ciphers,
                &input.random_encryption_points,
                &encryption_sk,
                &powers,
                rng,
            );
        })
    });

    group.bench_function("proof-vfy", |b| {
        let proof = Proof::new(
            &f_poly,
            &input.domain,
            &input.ciphers,
            &input.random_encryption_points,
            &encryption_sk,
            &powers,
            rng,
        );
        b.iter(|| {
            proof.verify(
                com_f_poly,
                &input.domain,
                &input.ciphers,
                &input.random_encryption_points,
                encryption_pk,
                &powers,
            );
        })
    });

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
