use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ff::fields::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_std::{test_rng, UniformRand, One, Zero};
use fdx::encrypt::elgamal::{ExponentialElgamal, MAX_BITS};
use fdx::encrypt::split_scalar::SplitScalar;

const N: usize = Scalar::MODULUS_BIT_SIZE as usize / MAX_BITS + 1;

type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;
type Scalar = <BlsCurve as Pairing>::ScalarField;
type SpScalar = SplitScalar<{ N }, Scalar>;
type UniPoly = DensePolynomial<Scalar>;

mod elgamal;
mod elgamalkzg;
mod split_scalar;
