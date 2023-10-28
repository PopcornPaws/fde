use crate::*;
use ark_ec::{CurveGroup, Group};
use fdx::backend::elgamalkzg_multi::PublicProofInput;
use fdx::commit::kzg::Powers;

const N: usize = 8;

#[test]
fn flow() {
    let rng = &mut test_rng();
    let tau = Scalar::rand(rng);
    let powers = Powers::<BlsCurve>::unsafe_setup(tau, N);

    let encryption_sk = Scalar::rand(rng);
    let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

    let data: Vec<Scalar> = (0..N).map(|_| Scalar::rand(rng)).collect();
    let input = PublicProofInput::<BlsCurve>::new(data, &encryption_pk, rng);

    let f_poly: UniPoly = input.interpolate();
    let com_f_poly = powers.commit_g1(&f_poly);

    let proof = ElgamalKzgMultiProof::new(&f_poly, &input, &encryption_sk, &powers, rng);

    assert!(proof.verify(com_f_poly, &input, encryption_pk, &powers));
}
