use crate::commit::kzg::Powers;
use crate::encrypt::elgamal::{Cipher, ExponentialElgamal as Elgamal, SplitScalar, MAX_BITS};
use crate::encrypt::EncryptionEngine;
use crate::range_proof::RangeProof;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::Rng;
use digest::Digest;

/// A publicly verifiable proof based on the Elgamal encryption scheme.
pub struct EncryptionProof<const N: usize, C: Pairing, D: Clone + Digest> {
    /// The actual Elgamal ciphertexts of the encrypted data points.
    pub ciphers: Vec<Cipher<C::G1>>,
    /// Each ciphertext is split into a set of scalars that, once decrypted, can reconstruct the
    /// original data point. Since we use the exponential Elgamal encryption scheme, these "short"
    /// ciphertexts are needed to encrypt split data points in the bruteforceable range: 2^32.
    pub short_ciphers: Vec<[Cipher<C::G1>; N]>,
    /// Each "short" ciphertext requires a range proof proving that the encrypted value is in the
    /// bruteforceable range.
    pub range_proofs: Vec<[RangeProof<C, D>; N]>,
    /// Random encryption points used to encrypt the original data points. These are the `h^r`
    /// values in the exponential Elgamal scheme: `e = g^m * h^r`, where `e` is the ciphertext, `m`
    /// is the plaintext.
    pub random_encryption_points: Vec<C::G1Affine>,
}

impl<const N: usize, C: Pairing, D: Clone + Digest> EncryptionProof<N, C, D> {
    pub fn new<R: Rng>(
        evaluations: &[C::ScalarField],
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let mut random_encryption_points = Vec::with_capacity(evaluations.len());
        let mut ciphers = Vec::with_capacity(evaluations.len());
        let mut short_ciphers = Vec::with_capacity(evaluations.len());
        let mut range_proofs = Vec::with_capacity(evaluations.len());

        for eval in evaluations {
            let split_eval = SplitScalar::from(*eval);
            let rp = split_eval.splits().map(|s| {
                RangeProof::new(s, MAX_BITS, powers, rng).expect("invalid range proof input")
            });
            let (sc, rand) = split_eval.encrypt::<Elgamal<C::G1>, _>(encryption_pk, rng);
            let cipher = <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
                eval,
                encryption_pk,
                &rand,
            );
            random_encryption_points.push((C::G1Affine::generator() * rand).into_affine());
            ciphers.push(cipher);
            short_ciphers.push(sc);
            range_proofs.push(rp);
        }

        Self {
            ciphers,
            short_ciphers,
            range_proofs,
            random_encryption_points,
        }
    }

    /// Generates a subset from the total encrypted data.
    ///
    /// Clients might not be interested in the whole dataset, thus the server may generate a subset
    /// encryption proof to reduce proof verification costs.
    pub fn subset(&self, indices: &[usize]) -> Self {
        let size = indices.len();
        let mut ciphers = Vec::with_capacity(size);
        let mut short_ciphers = Vec::with_capacity(size);
        let mut random_encryption_points = Vec::with_capacity(size);
        let mut range_proofs = Vec::with_capacity(size);
        for &index in indices {
            ciphers.push(self.ciphers[index]);
            short_ciphers.push(self.short_ciphers[index]);
            random_encryption_points.push(self.random_encryption_points[index]);
            range_proofs.push(self.range_proofs[index].clone());
        }

        Self {
            ciphers,
            short_ciphers,
            range_proofs,
            random_encryption_points,
        }
    }

    /// Checks that the sum of split scalars evaluate to the encrypted value via the homomorphic
    /// properties of Elgamal encryption.
    pub fn verify_split_scalars(&self) -> bool {
        for (cipher, short_cipher) in self.ciphers.iter().zip(&self.short_ciphers) {
            if !cipher.check_encrypted_sum(short_cipher) {
                return false;
            }
        }
        true
    }

    // TODO range proofs and short ciphers are not "connected" by anything?
    // TODO parallelize
    pub fn verify_range_proofs(&self, powers: &Powers<C>) -> bool {
        for rps in self.range_proofs.iter() {
            if !rps.iter().all(|rp| rp.verify(MAX_BITS, powers).is_ok()) {
                return false;
            }
        }
        true
    }
}
