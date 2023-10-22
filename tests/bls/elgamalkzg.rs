use crate::*;
use ark_ec::{CurveGroup, Group};
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::evaluations::univariate::Evaluations;
use ark_poly::{EvaluationDomain, Polynomial};
use fdx::commit::kzg::Powers;
use fdx::encrypt::elgamal::MAX_BITS;
use fdx::encrypt::EncryptionEngine;

#[test]
fn flow() {
    let rng = &mut test_rng();

    // kzg setup
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, 10);

    // polynomial
    let domain = GeneralEvaluationDomain::<Scalar>::new(3).unwrap();
    let data = vec![
        Scalar::from(2),
        Scalar::from(3),
        Scalar::from(6),
        Scalar::from(11),
    ];
    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);

    // index and eval
    let index = Scalar::from(7u32);
    let eval = f_poly.evaluate(&index);

    // "offline" encryption with random secret key
    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();
    let split_eval = SpScalar::from(eval);

    // encrypt split evaluation data
    let (short_ciphers, elgamal_r) = split_eval.encrypt::<Elgamal, _>(&encryption_pk, rng);

    // elgamal encryption
    let long_cipher =
        <Elgamal as EncryptionEngine>::encrypt_with_randomness(&eval, &encryption_pk, &elgamal_r);

    // compute kzg proof
    let proof = ElgamalKzgProof::new(&f_poly, index, elgamal_r, &encryption_sk, &powers, rng);

    assert!(proof.verify(&com_f_poly, index, &long_cipher, &powers));
    assert!(long_cipher.check_encrypted_sum::<{ MAX_BITS }>(&short_ciphers));
}
