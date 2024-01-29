use crate::commit::kzg::Powers;
use crate::encrypt::elgamal::{Cipher, ExponentialElgamal as Elgamal, SplitScalar, MAX_BITS};
use crate::encrypt::EncryptionEngine;
use crate::range_proof::RangeProof;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::Rng;
use digest::Digest;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// A publicly verifiable proof based on the Elgamal encryption scheme.
#[derive(Clone)]
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

impl<const N: usize, C: Pairing, D: Clone + Digest> Default for EncryptionProof<N, C, D> {
    fn default() -> Self {
        Self {
            ciphers: Vec::new(),
            short_ciphers: Vec::new(),
            range_proofs: Vec::new(),
            random_encryption_points: Vec::new(),
        }
    }
}

impl<const N: usize, C: Pairing, D: Clone + Digest + Send + Sync> EncryptionProof<N, C, D> {
    pub fn new<R: Rng + Send + Sync>(
        evaluations: &[C::ScalarField],
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        _rng: &mut R,
    ) -> Self {
        #[cfg(not(feature = "parallel"))]
        let proof = evaluations.iter().fold(Self::default(), |acc, eval| {
            acc.append(eval, encryption_pk, powers, _rng)
        });

        #[cfg(feature = "parallel")]
        let proof = evaluations
            .par_iter()
            .fold(Self::default, |acc, eval| {
                let rng = &mut ark_std::rand::thread_rng();
                acc.append(eval, encryption_pk, powers, rng)
            })
            .reduce(Self::default, |acc, proof| acc.extend(proof));
        proof
    }

    fn append<R: Rng>(
        mut self,
        eval: &C::ScalarField,
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let split_eval = SplitScalar::from(*eval);
        let rp = split_eval
            .splits()
            .map(|s| RangeProof::new(s, MAX_BITS, powers, rng).expect("invalid range proof input"));
        let (sc, rand) = split_eval.encrypt::<Elgamal<C::G1>, _>(encryption_pk, rng);
        let cipher = <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
            eval,
            encryption_pk,
            &rand,
        );
        self.random_encryption_points
            .push((C::G1Affine::generator() * rand).into_affine());
        self.ciphers.push(cipher);
        self.short_ciphers.push(sc);
        self.range_proofs.push(rp);
        self
    }

    fn extend(mut self, other: Self) -> Self {
        self.random_encryption_points
            .extend(other.random_encryption_points);
        self.ciphers.extend(other.ciphers);
        self.short_ciphers.extend(other.short_ciphers);
        self.range_proofs.extend(other.range_proofs);
        self
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
        #[cfg(feature = "parallel")]
        let result = self
            .ciphers
            .par_iter()
            .zip(&self.short_ciphers)
            .fold(
                || true,
                |acc, (cipher, short_cipher)| acc && cipher.check_encrypted_sum(short_cipher),
            )
            .reduce(|| true, |acc: bool, sub_boolean: bool| acc && sub_boolean);

        #[cfg(not(feature = "parallel"))]
        let result = self
            .ciphers
            .iter()
            .zip(&self.short_ciphers)
            .fold(true, |acc, (cipher, short_cipher)| {
                acc && cipher.check_encrypted_sum(short_cipher)
            });
        result
    }

    // TODO range proofs and short ciphers are not "connected" by anything?
    // https://github.com/PopcornPaws/fde/issues/13
    pub fn verify_range_proofs(&self, powers: &Powers<C>) -> bool {
        #[cfg(feature = "parallel")]
        let result = self
            .range_proofs
            .par_iter()
            .fold(
                || true,
                |acc, rps| acc && rps.par_iter().all(|rp| rp.verify(MAX_BITS, powers).is_ok()),
            )
            .reduce(|| true, |acc: bool, sub_boolean: bool| acc && sub_boolean);

        #[cfg(not(feature = "parallel"))]
        let result = self.range_proofs.iter().fold(true, |acc, rps| {
            acc && rps.par_iter.all(|rp| rp.verify(MAX_BITS, powers)).is_ok()
        });
        result
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::*;
    use ark_ec::Group;
    use ark_std::{test_rng, UniformRand};

    const DATA_SIZE: usize = 16;

    type ElgamalEncryptionProof = EncryptionProof<{ N }, TestCurve, TestHash>;

    #[test]
    fn encryption_proof() {
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<TestCurve>::unsafe_setup(tau, (DATA_SIZE + 1).max(MAX_BITS * 4)); // generate powers of tau size DATA_SIZE

        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<TestCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let mut encryption_proof = ElgamalEncryptionProof::new(&data, &encryption_pk, &powers, rng);

        assert!(encryption_proof.verify_split_scalars());
        assert!(encryption_proof.verify_range_proofs(&powers));

        // manually modify the encryption proof so that it fails
        encryption_proof.short_ciphers[DATA_SIZE - 3][2] = Default::default();
        assert!(!encryption_proof.verify_split_scalars());

        encryption_proof.range_proofs[DATA_SIZE - 3][3] =
            RangeProof::new(Scalar::from(123u8), 10, &powers, rng).unwrap();
        assert!(!encryption_proof.verify_range_proofs(&powers));
    }
}
