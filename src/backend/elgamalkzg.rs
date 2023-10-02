use crate::commit::kzg::Powers;
use crate::encrypt::elgamal::{ExponentialElgamal, MAX_BITS};
use crate::encrypt::split_scalar::SplitScalar;
use crate::encrypt::EncryptionEngine;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly_commit::DenseUVPolynomial;
use ark_std::rand::Rng;
use ark_std::UniformRand;

// proof for a single scalar
// if |F| = 2^256, then short ciphers should
// have length 8, because we split a single scalar
// into eight u32
pub struct Proof<const N: usize, C: Pairing> {
    short_ciphers: [<ExponentialElgamal<C::G1> as EncryptionEngine>::Cipher; N],
    long_cipher: <ExponentialElgamal<C::G1> as EncryptionEngine>::Cipher,
    commitment_poly_f: C::G1Affine,
    commitment_poly_t: C::G1Affine,
    commitment_poly_r: C::G1Affine,
    h_secret_star: C::G2Affine,
}

impl<const N: usize, C: Pairing> Proof<N, C> {
    pub fn new<P: DenseUVPolynomial<C::ScalarField>, R: Rng>(
        f_poly: &P,
        index: C::ScalarField,
        kzg: &Powers<C>,
        encryption_sk: &C::ScalarField,
        rng: &mut R,
    ) -> Self {
        // random values
        let secret_star = C::ScalarField::rand(rng);
        let elgamal_r = C::ScalarField::rand(rng);
        // encryption pubkey and g2^(ss*)
        let encryption_pk =
            (<C::G1Affine as AffineRepr>::generator() * encryption_sk).into_affine();
        let h_secret_star =
            (<C::G2Affine as AffineRepr>::generator() * encryption_sk * secret_star).into_affine();
        // evaluate polynomial at index and split evaluation up into brute-forceable shards for
        // exponential elgamal
        let eval = f_poly.evaluate(&index);
        let split_eval = SplitScalar::<N, C::ScalarField>::from(eval);

        // elgamal encryption
        let cipher = <ExponentialElgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
            &eval,
            &encryption_pk,
            &elgamal_r,
        );

        todo!();
        // generate kzg parameters
        // convert data into chunks of Fr and 8xFr
        // interpolate evaluations (Fr) with indices to obtain f
        // commit f
        //
    }
}
