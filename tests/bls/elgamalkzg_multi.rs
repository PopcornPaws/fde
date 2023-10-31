use crate::*;
use ark_ec::{CurveGroup, Group};
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use fdx::backend::elgamalkzg_multi::PublicProofInput;
use fdx::commit::kzg::Powers;

const D: usize = 512;
const N: usize = 128;

#[test]
fn flow() {
    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, D);

    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    // we have D data points which we interpolate into a polynomial with N coefficients
    let data: Vec<Scalar> = (0..D).map(|_| Scalar::rand(rng)).collect();
    let domain = GeneralEvaluationDomain::new(data.len()).unwrap();
    let evaluations = Evaluations::from_vec_and_domain(data, domain);
    let f_poly: UniPoly = evaluations.interpolate_by_ref();
    let com_f_poly = powers.commit_g1(&f_poly);

    // we only reveal a subset of the evaluations
    let input = PublicProofInput::<BlsCurve>::new(&evaluations.evals, &encryption_pk, rng);
    let proof = ElgamalKzgMultiProof::new(&f_poly, &input, &encryption_sk, &powers, rng);
    assert!(proof.verify(com_f_poly, &input, encryption_pk, &powers));
}
