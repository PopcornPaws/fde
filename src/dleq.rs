use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use digest::Digest;

pub struct Proof<C: CurveGroup, D> {
    pub challenge: C::ScalarField,
    pub claim: C::ScalarField,
    _digest: PhantomData<D>,
}

impl<C: CurveGroup, D: Digest> Proof<C, D> {
    pub fn new<R: Rng>(secret: C::ScalarField, g1: C::Affine, g2: C::Affine, rng: &mut R) -> Self {
        let rand = C::ScalarField::rand(rng);
        let k1 = (g1 * rand).into_affine();
        let k2 = (g2 * rand).into_affine();
        let h1 = (g1 * secret).into_affine();
        let h2 = (g2 * secret).into_affine();

        let mut serialized_points = Vec::new();
        k1.serialize_compressed(&mut serialized_points)
            .expect("should be valid");
        k2.serialize_compressed(&mut serialized_points)
            .expect("should be valid");
        h1.serialize_compressed(&mut serialized_points)
            .expect("should be valid");
        h2.serialize_compressed(&mut serialized_points)
            .expect("should be valid");

        let mut hasher = D::new();
        hasher.update(serialized_points);
        let hash_output = hasher.finalize();

        let challenge = C::ScalarField::from_le_bytes_mod_order(&hash_output);
        let claim = rand - challenge * secret;

        Self {
            challenge,
            claim,
            _digest: PhantomData,
        }
    }

    pub fn verify(&self, g1: C::Affine, h1: C::Affine, g2: C::Affine, h2: C::Affine) -> bool {
        let k1 = g1 * self.claim + h1 * self.challenge;
        let k2 = g2 * self.claim + h2 * self.challenge;

        let mut serialized_points = Vec::new();
        k1.serialize_compressed(&mut serialized_points)
            .expect("should be valid");
        k2.serialize_compressed(&mut serialized_points)
            .expect("should be valid");
        h1.serialize_compressed(&mut serialized_points)
            .expect("should be valid");
        h2.serialize_compressed(&mut serialized_points)
            .expect("should be valid");

        let mut hasher = D::new();
        hasher.update(serialized_points);
        let hash_output = hasher.finalize();

        let challenge = C::ScalarField::from_le_bytes_mod_order(&hash_output);

        challenge == self.challenge
    }
}
