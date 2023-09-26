use crate::encrypt::elgamal::ExponentialElGamal;
use crate::encrypt::EncryptionEngine;
use ark_ec::pairing::Pairing;
use ark_poly_commit::kzg10::Commitment;

// proof for a single scalar
// if |F| = 2^256, then short ciphers should
// have length 8, because we split a single scalar
// into eight u32
pub struct Proof<C: Pairing> {
    short_ciphers: Vec<<ExponentialElGamal<C::G1> as EncryptionEngine>::Cipher>,
    long_cipher: <ExponentialElGamal<C::G1> as EncryptionEngine>::Cipher,
    commitment_poly_t: Commitment<C>,
    commitment_poly_r: Commitment<C>,
    h_s_star: C::G1Affine,
}
