#[cfg(test)]
pub mod bls {
    pub use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ff::PrimeField;
    use ark_poly::univariate::DensePolynomial;
    use crate::encrypt::elgamal::{ExponentialElgamal, MAX_BITS};
    use crate::encrypt::split_scalar::SplitScalar;

    pub type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;
    pub type Scalar = <BlsCurve as Pairing>::ScalarField;
    pub type SpScalar = SplitScalar<{ Scalar::MODULUS_BIT_SIZE as usize }, { MAX_BITS }, Scalar>;
    pub type UniPoly = DensePolynomial<Scalar>;
}
