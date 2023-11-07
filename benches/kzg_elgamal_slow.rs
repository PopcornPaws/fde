use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
use ark_std::rand::Rng;
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;
use fde::encrypt::elgamal::ExponentialElgamal;
use fde::encrypt::EncryptionEngine;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;
type Scalar = <BlsCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::backend::kzg_elgamal_slow::Proof<BlsCurve, UniPoly>;
type Cipher = fde::encrypt::elgamal::Cipher<<BlsCurve as Pairing>::G1>;

const D: usize = 32;
const N: usize = 1;

struct Input {
    indices: Vec<Scalar>,
    rands: Vec<Scalar>,
    ciphers: Vec<Cipher>,
}

impl Input {
    fn new<R: Rng>(
        domain: GeneralEvaluationDomain<Scalar>,
        poly: &UniPoly,
        encryption_pk: G1Affine,
        rng: &mut R,
    ) -> Self {
        let mut indices = Vec::new();
        let mut rands = Vec::new();
        let mut ciphers = Vec::new();

        for i in 0..N {
            let index = domain.element(i);
            let eval = poly.evaluate(&index);
            let elgamal_r = Scalar::rand(rng);
            let cipher = <Elgamal as EncryptionEngine>::encrypt_with_randomness(
                &eval,
                &encryption_pk,
                &elgamal_r,
            );

            indices.push(index);
            rands.push(elgamal_r);
            ciphers.push(cipher);
        }

        Self {
            indices,
            rands,
            ciphers,
        }
    }
}

fn bench_proof(c: &mut Criterion) {
    assert!(D >= N);
    let mut group = c.benchmark_group("elgamal-kzg-slow");

    let rng = &mut test_rng();
    // kzg setup
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, D);

    // polynomial
    let domain = GeneralEvaluationDomain::<Scalar>::new(D).unwrap();
    let data = (0..D).map(|_| Scalar::rand(rng)).collect::<Vec<Scalar>>();
    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);
    // encryption secret key
    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (G1Affine::generator() * encryption_sk).into_affine();

    let input = Input::new(domain, &f_poly, encryption_pk, rng);

    group.bench_function("proof-gen", |b| {
        b.iter(|| {
            #[cfg(not(feature = "parallel"))]
            input
                .indices
                .iter()
                .zip(&input.rands)
                .for_each(|(index, elgamal_r)| {
                    Proof::new(&f_poly, *index, *elgamal_r, &encryption_sk, &powers, rng);
                });
            #[cfg(feature = "parallel")]
            input
                .indices
                .par_iter()
                .zip(&input.rands)
                .for_each(|(index, elgamal_r)| {
                    Proof::new(
                        &f_poly,
                        *index,
                        *elgamal_r,
                        &encryption_sk,
                        &powers,
                        &mut test_rng(),
                    );
                });
        })
    });

    group.bench_function("proof-vfy", |b| {
        let proofs: Vec<Proof> = input
            .indices
            .iter()
            .zip(&input.rands)
            .map(|(index, elgamal_r)| {
                Proof::new(&f_poly, *index, *elgamal_r, &encryption_sk, &powers, rng)
            })
            .collect();
        b.iter(|| {
            #[cfg(not(feature = "parallel"))]
            proofs
                .iter()
                .zip(input.indices.iter().zip(&input.ciphers))
                .for_each(|(proof, (index, cipher))| {
                    proof.verify(com_f_poly, *index, &cipher, &powers);
                });
            #[cfg(feature = "parallel")]
            proofs
                .par_iter()
                .zip(input.indices.par_iter().zip(&input.ciphers))
                .for_each(|(proof, (index, cipher))| {
                    proof.verify(com_f_poly, *index, &cipher, &powers);
                });
        })
    });

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
