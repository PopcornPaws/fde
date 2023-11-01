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

#[cfg(test)]
mod test {
    use crate::commit::kzg::Powers;
    use crate::encrypt::EncryptionEngine;
    use crate::tests::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_poly::domain::general::GeneralEvaluationDomain;
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::{EvaluationDomain, Polynomial};
    use ark_std::{test_rng, UniformRand};

    #[test]
    fn completeness() {
        let rng = &mut test_rng();

        // kzg setup
        let tau = Scalar::rand(rng);
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, 10);

        // polynomial
        let domain = GeneralEvaluationDomain::<Scalar>::new(3).unwrap();
        let data = vec![
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(6),
            Scalar::from(11),
        ];
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        // index and eval
        let index = Scalar::from(7u32);
        let eval = f_poly.evaluate(&index);

        // "offline" encryption with random secret key
        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (G1Affine::generator() * encryption_sk).into_affine();
        let split_eval = SplitScalar::from(eval);

        // encrypt split evaluation data
        let (short_ciphers, elgamal_r) = split_eval.encrypt::<Elgamal, _>(&encryption_pk, rng);

        // elgamal encryption
        let long_cipher = <Elgamal as EncryptionEngine>::encrypt_with_randomness(
            &eval,
            &encryption_pk,
            &elgamal_r,
        );

        // compute kzg proof
        let proof =
            KzgElgamalSlowProof::new(&f_poly, index, elgamal_r, &encryption_sk, &powers, rng);

        assert!(proof.verify(com_f_poly, index, &long_cipher, &powers));
        assert!(long_cipher.check_encrypted_sum(&short_ciphers));
    }
}
