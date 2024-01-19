use ark_bls12_381::Bls12_381 as BlsCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;

const DATA_LOG_SIZE: usize = 12; // 4096 = 2^12
const N: usize = Scalar::MODULUS_BIT_SIZE as usize / fde::encrypt::elgamal::MAX_BITS + 1;

type Scalar = <BlsCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::veck::kzg_elgamal::Proof<{ N }, BlsCurve, sha3::Keccak256>;
type PublicInput = fde::veck::kzg_elgamal::PublicInput<{ N }, BlsCurve>;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-elgamal");

    let data_size = 1 << DATA_LOG_SIZE;
    assert_eq!(data_size, 4096);

    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, data_size + 1);

    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    let data: Vec<Scalar> = (0..data_size).map(|_| Scalar::rand(rng)).collect();
    let input = PublicInput::new(&data, &encryption_pk, rng);

    let evaluations = Evaluations::from_vec_and_domain(data, input.domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);

    let index_map = input.index_map();

    for i in 0..=12 {
        let subset_size = 1 << i;
        let proof_gen_name = format!("proof-gen-{}", subset_size);
        let proof_vfy_name = format!("proof-vfy-{}", subset_size);

        let sub_domain = GeneralEvaluationDomain::new(subset_size).unwrap();
        let sub_indices = sub_domain
            .elements()
            .map(|elem| *index_map.get(&elem).unwrap())
            .collect::<Vec<usize>>();
        let sub_data = sub_indices
            .iter()
            .map(|&i| evaluations.evals[i])
            .collect::<Vec<Scalar>>();
        let sub_evaluations = Evaluations::from_vec_and_domain(sub_data, sub_domain);
        let f_s_poly: UniPoly = sub_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let sub_input = input.subset(&sub_indices);

        group.bench_function(&proof_gen_name, |b| {
            b.iter(|| {
                Proof::new(&f_poly, &f_s_poly, &encryption_sk, &sub_input, &powers, rng);
            })
        });

        group.bench_function(&proof_vfy_name, |b| {
            let proof = Proof::new(&f_poly, &f_s_poly, &encryption_sk, &sub_input, &powers, rng);
            b.iter(|| {
                assert!(proof.verify(com_f_poly, com_f_s_poly, encryption_pk, &sub_input, &powers))
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
