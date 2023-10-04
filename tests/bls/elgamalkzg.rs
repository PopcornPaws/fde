use crate::*;
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::evaluations::univariate::Evaluations;
use ark_poly::EvaluationDomain;
use fdx::commit::kzg::Powers;

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
    // encryption secret key
    let encryption_sk = Scalar::rand(rng);
    // index
    let index = Scalar::from(7u32);
    let proof = Proof::new(&f_poly, index, &powers, &encryption_sk, rng);

    assert!(proof.verify(&com_f_poly, index, &powers));
}
