use crate::hash::Hasher;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use digest::Digest;

pub struct Proof<C: CurveGroup, D> {
    pub challenge: C::ScalarField,
    pub claim: C::ScalarField,
    _digest: PhantomData<D>,
}

impl<C, D> Proof<C, D>
where
    C: CurveGroup,
    D: Digest,
{
    pub fn new<R: Rng>(secret: &C::ScalarField, g1: C::Affine, g2: C::Affine, rng: &mut R) -> Self {
        let rand = C::ScalarField::rand(rng);
        let k1 = g1 * rand;
        let k2 = g2 * rand;
        let h1 = g1 * secret;
        let h2 = g2 * secret;

        let mut hasher = Hasher::<D>::new();
        hasher.update(&k1);
        hasher.update(&k2);
        hasher.update(&h1);
        hasher.update(&h2);
        let hash_output = hasher.finalize();

        let challenge = C::ScalarField::from_le_bytes_mod_order(&hash_output);
        let claim = rand - challenge * secret;

        Self {
            challenge,
            claim,
            _digest: PhantomData,
        }
    }

    pub fn verify(&self, g1: C::Affine, h1: C, g2: C::Affine, h2: C) -> bool {
        let k1 = g1 * self.claim + h1 * self.challenge;
        let k2 = g2 * self.claim + h2 * self.challenge;

        let mut hasher = Hasher::<D>::new();
        hasher.update(&k1);
        hasher.update(&k2);
        hasher.update(&h1);
        hasher.update(&h2);
        let hash_output = hasher.finalize();

        let challenge = C::ScalarField::from_le_bytes_mod_order(&hash_output);

        challenge == self.challenge
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{G1Affine, Scalar, TestCurve, TestHash};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::{test_rng, UniformRand};

    type DleqProof = Proof<<TestCurve as Pairing>::G1, TestHash>;

    #[test]
    fn completeness() {
        let rng = &mut test_rng();

        let g1 = G1Affine::generator();
        let g2 = (G1Affine::generator() * Scalar::rand(rng)).into_affine();

        let secret = Scalar::rand(rng);

        let h1 = g1 * secret;
        let h2 = g2 * secret;

        let proof = DleqProof::new(&secret, g1, g2, rng);

        assert!(proof.verify(g1, h1, g2, h2));
    }

    #[test]
    fn soundness() {
        let rng = &mut test_rng();

        let g1 = G1Affine::generator();
        let g2 = (G1Affine::generator() * Scalar::rand(rng)).into_affine();

        let secret = Scalar::rand(rng);

        let h1 = g1 * secret;
        let h2 = g2 * secret;

        // invalid secret
        let proof = DleqProof::new(&(secret * Scalar::from(2)), g1, g2, rng);
        assert!(!proof.verify(g1, h1, g2, h2));

        // invalid point
        let proof = DleqProof::new(&secret, g1, g2, rng);
        assert!(!proof.verify(g1, h1, g1, h1));
    }
}
