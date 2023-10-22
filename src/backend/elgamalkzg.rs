use crate::commit::kzg::Powers;
use crate::encrypt::elgamal::{ExponentialElgamal, SplitScalar, MAX_BITS};
use crate::encrypt::EncryptionEngine;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group};
use ark_poly_commit::DenseUVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::ops::{Add, Div, Sub};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand};

// proof for a single scalar if |F| = 2^256, then short ciphers should have length 8, because we
// split a single scalar into eight u32
pub struct Proof<const N: usize, C: Pairing, P> {
    short_ciphers: [<ExponentialElgamal<C::G1> as EncryptionEngine>::Cipher; N],
    long_cipher: <ExponentialElgamal<C::G1> as EncryptionEngine>::Cipher,
    com_r_poly: C::G1Affine,
    com_t_poly: C::G1Affine,
    h_secret_star: C::G2Affine,
    _poly: PhantomData<P>,
}

impl<const N: usize, C: Pairing, P> Proof<N, C, P>
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
        kzg: &Powers<C>,
        encryption_sk: &C::ScalarField,
        rng: &mut R,
    ) -> Self {
        // random values
        let secret_star = C::ScalarField::rand(rng);
        // encryption pubkey and g2^(ss*)
        let encryption_pk = (C::G1::generator() * encryption_sk).into_affine();
        let h_secret_star = (C::G2::generator() * encryption_sk * secret_star).into_affine();
        // evaluate polynomial at index and split evaluation up into brute-forceable shards for
        // exponential elgamal
        let eval = f_poly.evaluate(&index);
        let split_eval = SplitScalar::<N, C::ScalarField>::from(eval);
        // encrypt split evaluation data
        let (short_ciphers, elgamal_r) =
            split_eval.encrypt::<ExponentialElgamal<C::G1>, R>(&encryption_pk, rng);

        // elgamal encryption
        let long_cipher = <ExponentialElgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
            &eval,
            &encryption_pk,
            &elgamal_r,
        );

        // (x - eval) polynomial
        let d_poly = P::from_coefficients_slice(&[-index, C::ScalarField::one()]);
        let s_s_star = P::from_coefficients_slice(&[*encryption_sk * secret_star]);
        // (f(x) - eval) / (x - eval) + ss*
        let t_poly = &(f_poly + &P::from_coefficients_slice(&[-eval])) / &d_poly + s_s_star;
        // - r / s_star - (x - eval)
        let r_poly = &P::from_coefficients_slice(&[-elgamal_r / secret_star]) - &d_poly;

        // kzg commitments
        let com_r_poly = kzg.commit_g1(&r_poly);
        let com_t_poly = kzg.commit_g1(&t_poly);

        Self {
            short_ciphers,
            long_cipher,
            com_r_poly,
            com_t_poly,
            h_secret_star,
            _poly: PhantomData,
        }
    }

    pub fn verify(&self, com_f_poly: &C::G1Affine, index: C::ScalarField, kzg: &Powers<C>) -> bool {
        let d_poly = P::from_coefficients_slice(&[-index, C::ScalarField::one()]);
        let com_d_poly = kzg.commit_g2(&d_poly);

        let pairing_f_poly = C::pairing(
            C::G1::from(*com_f_poly) - C::G1::from(self.long_cipher.c1()),
            C::G2::generator(),
        );
        let pairing_t_poly = C::pairing(self.com_t_poly, com_d_poly);
        let pairing_r_poly = C::pairing(self.com_r_poly, self.h_secret_star);

        let pairing_check = pairing_f_poly == pairing_t_poly + pairing_r_poly;
        let encryption_check = self
            .long_cipher
            .check_encrypted_sum::<{ MAX_BITS }>(&self.short_ciphers);
        pairing_check && encryption_check
    }
}
