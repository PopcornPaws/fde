use crate::*;
use ark_ec::{AffineRepr, CurveGroup};

#[test]
fn completeness() {
    let rng = &mut test_rng();

    let g1 = G1Affine::generator();
    let g2 = (G1Affine::generator() * Scalar::rand(rng)).into_affine();

    let secret = Scalar::rand(rng);

    let h1 = (g1 * secret).into_affine();
    let h2 = (g2 * secret).into_affine();

    let proof = DleqProof::new(secret, g1, g2, rng);

    assert!(proof.verify(g1, h1, g2, h2));
}

#[test]
fn soundness() {
    let rng = &mut test_rng();

    let g1 = G1Affine::generator();
    let g2 = (G1Affine::generator() * Scalar::rand(rng)).into_affine();

    let secret = Scalar::rand(rng);

    let h1 = (g1 * secret).into_affine();
    let h2 = (g2 * secret).into_affine();

    // invalid secret
    let proof = DleqProof::new(secret * Scalar::from(2), g1, g2, rng);
    assert!(!proof.verify(g1, h1, g2, h2));

    // invalid point
    let proof = DleqProof::new(secret, g1, g2, rng);
    assert!(!proof.verify(g1, h1, g1, h1));
}
