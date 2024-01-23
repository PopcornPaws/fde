use ark_bls12_381::Bls12_381 as BlsCurve;
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::{test_rng, UniformRand};
use criterion::{criterion_group, criterion_main, Criterion};
use fde::commit::kzg::Powers;
use fde::veck::kzg::paillier::Server;
use num_bigint::BigUint;

type TestCurve = ark_bls12_381::Bls12_381;
type TestHash = sha3::Keccak256;
type Scalar = <BlsCurve as Pairing>::ScalarField;
type UniPoly = DensePolynomial<Scalar>;
type PaillierEncryptionProof = fde::veck::kzg::paillier::Proof<TestCurve, TestHash>;

fn bench_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("kzg-paillier");
    group.sample_size(10);

    // TODO until subset openings don't work, use full open
    //let data_size = 1 << 12;
    //let data: Vec<Scalar> = (0..data_size).map(|_| Scalar::rand(rng)).collect();
    //let domain = GeneralEvaluationDomain::new(DATA_SIZE).unwrap();
    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<TestCurve>::unsafe_setup_eip_4844(tau, 1 << 12); // TODO data_size
    let server = Server::new(rng);

    for i in 0..=12 {
        // TODO remove this once subset proofs work
        let data_size = 1 << i;
        let subset_size = 1 << i;
        let proof_gen_name = format!("proof-gen-{}", subset_size);
        let proof_vfy_name = format!("proof-vfy-{}", subset_size);
        let decryption_name = format!("decryption-{}", subset_size);
        // random data to encrypt
        let data: Vec<Scalar> = (0..data_size).map(|_| Scalar::rand(rng)).collect();
        let domain = GeneralEvaluationDomain::new(data_size).unwrap();
        let domain_s = GeneralEvaluationDomain::new(subset_size).unwrap();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let index_map = fde::veck::index_map(domain);
        let subset_indices = fde::veck::subset_indices(&index_map, &domain_s);
        let evaluations_s = fde::veck::subset_evals(&evaluations, &subset_indices, domain_s);

        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let f_s_poly: UniPoly = evaluations_s.interpolate_by_ref();

        let evaluations_s_d = f_s_poly.evaluate_over_domain_by_ref(domain);

        let com_f_poly = powers.commit_scalars_g1(&evaluations.evals);
        let com_f_s_poly = powers.commit_scalars_g1(&evaluations_s_d.evals);

        let data_biguint: Vec<BigUint> = evaluations_s
            .evals
            .iter()
            .map(|d| BigUint::from_bytes_le(&d.into_bigint().to_bytes_le()))
            .collect();

        group.bench_function(&proof_gen_name, |b| {
            b.iter(|| {
                PaillierEncryptionProof::new(
                    &data_biguint,
                    &f_poly,
                    &f_s_poly,
                    &com_f_poly,
                    &com_f_s_poly,
                    &domain,
                    &domain_s,
                    &server.pubkey,
                    &powers,
                    rng,
                );
            })
        });

        group.bench_function(&proof_vfy_name, |b| {
            let proof = PaillierEncryptionProof::new(
                &data_biguint,
                &f_poly,
                &f_s_poly,
                &com_f_poly,
                &com_f_s_poly,
                &domain,
                &domain_s,
                &server.pubkey,
                &powers,
                rng,
            );
            b.iter(|| {
                assert!(proof
                    .verify(
                        &com_f_poly,
                        &com_f_s_poly,
                        &domain,
                        &domain_s,
                        &server.pubkey,
                        &powers
                    )
                    .is_ok());
            })
        });

        group.bench_function(&decryption_name, |b| {
            let proof = PaillierEncryptionProof::new(
                &data_biguint,
                &f_poly,
                &f_s_poly,
                &com_f_poly,
                &com_f_s_poly,
                &domain,
                &domain_s,
                &server.pubkey,
                &powers,
                rng,
            );
            b.iter(|| {
                proof.decrypt(&server);
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_proof);
criterion_main!(benches);
