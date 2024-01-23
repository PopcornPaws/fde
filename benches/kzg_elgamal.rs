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

type TestCurve = ark_bls12_381::Bls12_381;
type TestHash = sha3::Keccak256;
type Scalar = <TestCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type Proof = fde::veck::kzg::elgamal::Proof<{ N }, TestCurve, TestHash>;
type EncryptionProof = fde::veck::kzg::elgamal::EncryptionProof<{ N }, TestCurve, TestHash>;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-elgamal");

    let data_size = 1 << DATA_LOG_SIZE;
    assert_eq!(data_size, 4096);

    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<TestCurve>::unsafe_setup(tau, data_size + 1);

    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    println!("Generating encryption proofs for 4096 * 8 split field elements...");
    println!("This might take a few minutes and it's not included in the actual benchmarks.");
    let t_start = std::time::Instant::now();
    let data: Vec<Scalar> = (0..data_size).map(|_| Scalar::rand(rng)).collect();
    let encryption_proof = EncryptionProof::new(&data, &encryption_pk, &powers, rng);
    let elapsed = std::time::Instant::now().duration_since(t_start).as_secs();
    println!("Generated encryption proofs, elapsed time: {} [s]", elapsed);

    let domain = GeneralEvaluationDomain::new(data.len()).expect("valid domain");
    let index_map = fde::veck::index_map(domain);

    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);

    for i in 0..=12 {
        let subset_size = 1 << i;
        let proof_gen_name = format!("proof-gen-{}", subset_size);
        let proof_vfy_name = format!("proof-vfy-{}", subset_size);

        let subdomain = GeneralEvaluationDomain::new(subset_size).unwrap();
        let subset_indices = fde::veck::subset_indices(&index_map, &subdomain);
        let subset_evaluations = fde::veck::subset_evals(&evaluations, &subset_indices, subdomain);

        let f_s_poly: UniPoly = subset_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let sub_encryption_proof = encryption_proof.subset(&subset_indices);

        group.bench_function(&proof_gen_name, |b| {
            b.iter(|| {
                Proof::new(
                    &f_poly,
                    &f_s_poly,
                    &encryption_sk,
                    sub_encryption_proof.clone(),
                    &powers,
                    rng,
                )
                .unwrap();
            })
        });

        group.bench_function(&proof_vfy_name, |b| {
            let proof = Proof::new(
                &f_poly,
                &f_s_poly,
                &encryption_sk,
                sub_encryption_proof.clone(),
                &powers,
                rng,
            )
            .unwrap();
            b.iter(|| {
                assert!(proof
                    .verify(com_f_poly, com_f_s_poly, encryption_pk, &powers)
                    .is_ok())
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
