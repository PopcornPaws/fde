pub use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use criterion as _;
use sha3::Keccak256;

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / crate::encrypt::elgamal::MAX_BITS + 1;

pub type Scalar = <BlsCurve as Pairing>::ScalarField;
pub type SplitScalar = crate::encrypt::elgamal::SplitScalar<{ N }, Scalar>;
pub type UniPoly = DensePolynomial<Scalar>;

pub type Elgamal = crate::encrypt::elgamal::ExponentialElgamal<<BlsCurve as Pairing>::G1>;
pub type PublicInput = crate::veck::kzg_elgamal::PublicInput<{ N }, BlsCurve, Keccak256>;
pub type KzgElgamalProof = crate::veck::kzg_elgamal::Proof<{ N }, BlsCurve, Keccak256>;
pub type DleqProof = crate::dleq::Proof<<BlsCurve as Pairing>::G1, Keccak256>;
pub type RangeProof = crate::range_proof::RangeProof<BlsCurve, Keccak256>;
pub type PaillierEncryptionProof = crate::veck::kzg_paillier::Proof<BlsCurve, Keccak256>;
