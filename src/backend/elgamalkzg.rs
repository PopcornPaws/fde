use crate::encrypt::elgamal::ExponentialElGamal;
use crate::encrypt::EncryptionEngine;
use ark_ec::pairing::Pairing;
use ark_poly_commit::kzg10::{Commitment, Powers, KZG10};
use ark_poly_commit::DenseUVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::ops::Div;
use ark_std::rand::Rng;

// proof for a single scalar
// if |F| = 2^256, then short ciphers should
// have length 8, because we split a single scalar
// into eight u32
pub struct Proof<C: Pairing, P> {
    short_ciphers: Vec<<ExponentialElGamal<C::G1> as EncryptionEngine>::Cipher>,
    long_cipher: <ExponentialElGamal<C::G1> as EncryptionEngine>::Cipher,
    commitment_poly_f: Commitment<C>,
    commitment_poly_t: Commitment<C>,
    commitment_poly_r: Commitment<C>,
    h_secret_star: C::G1Affine,
    _poly: PhantomData<P>,
}

impl<C, P> Proof<C, P>
where
    C: Pairing,
    P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>,
    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
{
    pub fn new<R: Rng>(rng: &mut R) -> Self {
        todo!();
        // generate kzg parameters
        // convert data into chunks of Fr and 8xFr
        // interpolate evaluations (Fr) with indices to obtain f
        // commit f
        //
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine, G2Affine};
    use ark_ec::{AffineRepr, Group, CurveGroup};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::Polynomial;
    use ark_std::borrow::Cow;
    use ark_std::{test_rng, One, UniformRand};

    type Scalar = <BlsCurve as Pairing>::ScalarField;
    type UniPoly = DensePolynomial<Scalar>;
    type Kzg = KZG10<BlsCurve, UniPoly>;

    #[test]
    fn flow() {
        let rng = &mut test_rng();

        // TODO from interpolation of data
        let data_poly = UniPoly::rand(10, rng);
        let index = Scalar::from(7u32);
        let eval = data_poly.evaluate(&index);

        // secret-gen and elgamal
        let secret = Scalar::rand(rng);
        let encryption_pk = (G1Affine::generator() * secret).into_affine();
        let secret_star = Scalar::rand(rng);
        let elgamal_r = Scalar::rand(rng);
        let h_secret_star = encryption_pk * secret_star;

        let cipher = ExponentialElGamal::<<BlsCurve as Pairing>::G1>::encrypt_with_randomness(
            &eval,
            &encryption_pk,
            elgamal_r,
        );

        // kzg setup
        let params = Kzg::setup(10, false, rng).unwrap();
        let powers: Powers<'_, BlsCurve> = Powers {
            powers_of_g: Cow::Owned(params.powers_of_g),
            powers_of_gamma_g: Cow::Owned(params.powers_of_gamma_g.into_values().collect()),
        };

        // kzg commit
        let (com_f, r_f) = Kzg::commit(&powers, &data_poly, None, None).unwrap();

        // (x - eval) polynomial
        let d_poly = UniPoly::from_coefficients_slice(&[-index, Scalar::one()]);
        let s_s_star = UniPoly::from_coefficients_slice(&[secret * secret_star]);
        // (f(x) - eval) / (x - eval) + ss*
        let expected_t_poly = &(&data_poly + &UniPoly::from_coefficients_slice(&[-eval]))
            / &d_poly
            + s_s_star.clone();

        let (mut t_poly, _) = Kzg::compute_witness_polynomial(&data_poly, index, &r_f).unwrap();

        t_poly += &s_s_star;
        assert_eq!(t_poly, expected_t_poly);

        // - r / s_star - (x - eval)
        let r_poly = &UniPoly::from_coefficients_slice(&[-elgamal_r / secret_star]) - &d_poly;

        // commit t_poly and r_poly and div_poly
        let (com_t, r_t) = Kzg::commit(&powers, &t_poly, None, None).unwrap();
        let (com_r, r_r) = Kzg::commit(&powers, &r_poly, None, None).unwrap();
        let (com_d, r_d) = Kzg::commit(&powers, &d_poly, None, None).unwrap();

        // proof is (com_t, com_r, h_secret_star)
        let fp_pairing = BlsCurve::pairing(com_f.0 - cipher.c1(), G2Affine::generator());
        let tp_pairing = BlsCurve::pairing(com_t.0 + com_d.0, G2Affine::generator());
        let rp_pairing = BlsCurve::pairing(com_r.0 + h_secret_star, G2Affine::generator());

        assert_eq!(fp_pairing, tp_pairing + rp_pairing);
    }
}
