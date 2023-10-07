use ark_bls12_381::Bls12_381 as BlsCurve;
use ark_ec::pairing::Pairing;
use ark_ff::fields::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fdx::backend::elgamalkzg::Proof as ElgamalKzgProof;
use fdx::commit::kzg::Powers;
use fdx::encrypt::elgamal::{ExponentialElgamal, MAX_BITS};
use fdx::encrypt::split_scalar::SplitScalar;

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / MAX_BITS + 1;

type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;
type Scalar = <BlsCurve as Pairing>::ScalarField;
type SpScalar = SplitScalar<{ N }, Scalar>;
type UniPoly = DensePolynomial<Scalar>;
type Proof = ElgamalKzgProof<{ N }, BlsCurve, UniPoly>;

const D: u64 = 128;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("elgamal-kzg");

    let rng = &mut test_rng();
    // kzg setup
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, D);

    // polynomial
    let domain = GeneralEvaluationDomain::<Scalar>::new(D as usize).unwrap();
    let data = (0..D).map(|_| Scalar::rand(rng)).collect::<Vec<Scalar>>();
    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);
    // encryption secret key
    let encryption_sk = Scalar::rand(rng);
    // index
    let index = Scalar::from(7u32);

    group.bench_function("proof-gen", |b| {
        b.iter(|| Proof::new(&f_poly, index, &powers, &encryption_sk, rng))
    });

    let proof = Proof::new(&f_poly, index, &powers, &encryption_sk, rng);
    group.bench_function("proof-vfy", |b| {
        b.iter(|| proof.verify(&com_f_poly, index, &powers))
    });
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
