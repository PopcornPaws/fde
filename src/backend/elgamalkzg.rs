// proof for a single scalar
// if |F| = 2^256, then short ciphers should
// have length 8, because we split a single scalar
// into eight u32
//pub struct Proof<C: Pairing, P> {
//    short_ciphers: Vec<<ExponentialElGamal<C::G1> as EncryptionEngine>::Cipher>,
//    long_cipher: <ExponentialElGamal<C::G1> as EncryptionEngine>::Cipher,
//    commitment_poly_f: Commitment<C>,
//    commitment_poly_t: Commitment<C>,
//    commitment_poly_r: Commitment<C>,
//    h_secret_star: C::G1Affine,
//    _poly: PhantomData<P>,
//}

//impl<C, P> Proof<C, P>
//where
//    C: Pairing,
//    P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>,
//    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
//{
//    pub fn new<R: Rng>(rng: &mut R) -> Self {
//        todo!();
//        // generate kzg parameters
//        // convert data into chunks of Fr and 8xFr
//        // interpolate evaluations (Fr) with indices to obtain f
//        // commit f
//        //
//    }
//}

#[cfg(test)]
mod test {
    use crate::backend::kzg::Powers;
    use crate::encrypt::elgamal::ExponentialElGamal;
    use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine, G2Affine};
    use ark_ec::pairing::Pairing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use ark_std::{test_rng, One, UniformRand};

    type Scalar = <BlsCurve as Pairing>::ScalarField;
    type UniPoly = DensePolynomial<Scalar>;

    #[test]
    fn flow() {
        let rng = &mut test_rng();

        // TODO from interpolation of data
        let f_poly = UniPoly::rand(10, rng);
        let index = Scalar::from(7u32);
        let eval = f_poly.evaluate(&index);

        // secret-gen
        let tau = Scalar::rand(rng);
        let secret = Scalar::rand(rng);
        let encryption_pk = (G1Affine::generator() * secret).into_affine();
        let secret_star = Scalar::rand(rng);
        let elgamal_r = Scalar::rand(rng);
        let h_secret_star = (G2Affine::generator() * secret * secret_star).into_affine();

        // elgamal encryption
        let cipher = ExponentialElGamal::<<BlsCurve as Pairing>::G1>::encrypt_with_randomness(
            &eval,
            &encryption_pk,
            elgamal_r,
        );
        // compute polynomials
        // (x - eval) polynomial
        let d_poly = UniPoly::from_coefficients_slice(&[-index, Scalar::one()]);
        let s_s_star = UniPoly::from_coefficients_slice(&[secret * secret_star]);
        // (f(x) - eval) / (x - eval) + ss*
        let t_poly =
            &(&f_poly + &UniPoly::from_coefficients_slice(&[-eval])) / &d_poly + s_s_star;
        // - r / s_star - (x - eval)
        let r_poly = &UniPoly::from_coefficients_slice(&[-elgamal_r / secret_star]) - &d_poly;

        let powers = Powers::<BlsCurve>::unsafe_setup(tau, 10);

        let com_f = powers.commit_g1(&f_poly);
        let com_d = powers.commit_g2(&d_poly);
        let com_r = powers.commit_g1(&r_poly);
        let com_t = powers.commit_g1(&t_poly);

        let fp_pairing = BlsCurve::pairing(com_f - cipher.c1(), G2Affine::generator());
        let tp_pairing = BlsCurve::pairing(com_t, com_d);
        let rp_pairing = BlsCurve::pairing(com_r, h_secret_star);

        assert_eq!(fp_pairing, tp_pairing + rp_pairing);
    }
}
