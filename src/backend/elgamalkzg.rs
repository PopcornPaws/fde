use crate::commit::kzg::Powers;
use crate::encrypt::elgamal::Cipher;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_poly_commit::DenseUVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::ops::{Add, Div, Sub};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand};

pub struct Proof<C: Pairing, P> {
    com_r_poly: C::G1Affine,
    com_t_poly: C::G1Affine,
    h_secret_star: C::G2Affine,
    _poly: PhantomData<P>,
}

impl<C: Pairing, P> Proof<C, P>
where
    C: Pairing,
    P: DenseUVPolynomial<C::ScalarField>,
    for<'a> &'a P: Add<&'a P, Output = P>,
    for<'a> &'a P: Sub<&'a P, Output = P>,
    for<'a> &'a P: Div<&'a P, Output = P>,
{
    pub fn new<R: Rng>(
        f_poly: &P,
        index: C::ScalarField,
        elgamal_r: C::ScalarField,
        encryption_sk: &C::ScalarField,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        // random values
        let secret_star = C::ScalarField::rand(rng);
        // g2^(ss*)
        let h_secret_star = (C::G2::generator() * encryption_sk * secret_star).into_affine();
        // evaluate polynomial at index and split evaluation up into brute-forceable shards for
        // exponential elgamal
        let eval = f_poly.evaluate(&index);
        // (x - eval) polynomial
        let d_poly = P::from_coefficients_slice(&[-index, C::ScalarField::one()]);
        let s_s_star = P::from_coefficients_slice(&[*encryption_sk * secret_star]);
        // (f(x) - eval) / (x - eval) + ss*
        let t_poly = &(f_poly + &P::from_coefficients_slice(&[-eval])) / &d_poly + s_s_star;
        // - r / s_star - (x - eval)
        let r_poly = &P::from_coefficients_slice(&[-elgamal_r / secret_star]) - &d_poly;

        // kzg commitments
        let com_r_poly = powers.commit_g1(&r_poly).into();
        let com_t_poly = powers.commit_g1(&t_poly).into();

        Self {
            com_r_poly,
            com_t_poly,
            h_secret_star,
            _poly: PhantomData,
        }
    }

    pub fn verify(
        &self,
        com_f_poly: C::G1,
        index: C::ScalarField,
        cipher: &Cipher<C::G1>,
        powers: &Powers<C>,
    ) -> bool {
        let d_poly = P::from_coefficients_slice(&[-index, C::ScalarField::one()]);
        let com_d_poly = powers.commit_g2(&d_poly);

        let pairing_f_poly = C::pairing(com_f_poly - C::G1::from(cipher.c1()), C::G2::generator());
        let pairing_t_poly = C::pairing(self.com_t_poly, com_d_poly);
        let pairing_r_poly = C::pairing(self.com_r_poly, self.h_secret_star);

        pairing_f_poly == pairing_t_poly + pairing_r_poly
    }
}
