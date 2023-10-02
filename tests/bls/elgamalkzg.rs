use crate::*;
use fdx::encrypt::EncryptionEngine;
use fdx::commit::kzg::Powers;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::evaluations::univariate::Evaluations;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};

#[test]
fn flow() {
    let rng = &mut test_rng();

    let domain = GeneralEvaluationDomain::<Scalar>::new(3).unwrap();
    let data = vec![
        Scalar::from(2),
        Scalar::from(3),
        Scalar::from(6),
        Scalar::from(11),
    ];
    let evaluations = Evaluations::from_vec_and_domain(data, domain);

    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let index = Scalar::from(7u32);
    let eval = f_poly.evaluate(&index);

    // secret-gen
    let tau = Scalar::rand(rng);
    let secret = Scalar::rand(rng);
    let encryption_pk = (G1Affine::generator() * secret).into_affine();
    let secret_star = Scalar::rand(rng);
    let elgamal_r = Scalar::rand(rng);
    let h_secret_star = (G2Affine::generator() * secret * secret_star).into_affine();

    // elgamal encryption
    let cipher = Elgamal::encrypt_with_randomness(&eval, &encryption_pk, &elgamal_r);
    // compute polynomials
    // (x - eval) polynomial
    let d_poly = UniPoly::from_coefficients_slice(&[-index, Scalar::one()]);
    let s_s_star = UniPoly::from_coefficients_slice(&[secret * secret_star]);
    // (f(x) - eval) / (x - eval) + ss*
    let t_poly = &(&f_poly + &UniPoly::from_coefficients_slice(&[-eval])) / &d_poly + s_s_star;
    // - r / s_star - (x - eval)
    let r_poly = &UniPoly::from_coefficients_slice(&[-elgamal_r / secret_star]) - &d_poly;

    let powers = Powers::<BlsCurve>::unsafe_setup(tau, 10);

    let com_f = powers.commit_g1(&f_poly);
    let com_d = powers.commit_g2(&d_poly);
    let com_r = powers.commit_g1(&r_poly);
    let com_t = powers.commit_g1(&t_poly);

    let fp_pairing = BlsCurve::pairing(com_f - cipher.c1(), G2Affine::generator());
    let tp_pairing = BlsCurve::pairing(com_t, com_d);
    let rp_pairing = BlsCurve::pairing(com_r, h_secret_star);

    assert_eq!(fp_pairing, tp_pairing + rp_pairing);
}
