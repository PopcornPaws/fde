use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine};
use ark_ec::pairing::Pairing;
use ark_ff::fields::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_std::{test_rng, UniformRand, Zero};
use fdx::encrypt::elgamal::{ExponentialElgamal, SplitScalar, MAX_BITS};

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / MAX_BITS + 1;

type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;
type Scalar = <BlsCurve as Pairing>::ScalarField;
type SpScalar = SplitScalar<{ N }, Scalar>;
type UniPoly = DensePolynomial<Scalar>;
type ElgamalKzgProof = fdx::backend::elgamalkzg::Proof<BlsCurve, UniPoly>;
type ElgamalKzgMultiProof =
    fdx::backend::elgamalkzg_multi::Proof<BlsCurve, UniPoly, sha3::Keccak256>;
type DleqProof = fdx::dleq::Proof<<BlsCurve as Pairing>::G1, sha3::Keccak256>;

mod dleq;
mod elgamal;
mod elgamalkzg;
mod elgamalkzg_multi;
mod split_scalar;
