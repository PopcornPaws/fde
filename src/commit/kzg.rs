// We need to commit to G2 as well, which arkworks' kzg10 implementation doesn't allow
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_poly_commit::DenseUVPolynomial;
use ark_std::One;

pub struct Powers<C: Pairing> {
    pub g1: Vec<C::G1Affine>,
    pub g2: Vec<C::G2Affine>,
}

impl<C: Pairing> Powers<C> {
    pub fn unsafe_setup(tau: C::ScalarField, range: usize) -> Self {
        let mut g1 = Vec::new();
        let mut g2 = Vec::new();
        let mut exponent = C::ScalarField::one();
        for _ in 0..=range {
            g1.push((<C::G1Affine as AffineRepr>::generator() * exponent).into_affine());
            g2.push((<C::G2Affine as AffineRepr>::generator() * exponent).into_affine());
            exponent *= tau;
        }
        Self { g1, g2 }
    }

    pub fn commit_g1<P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>>(
        &self,
        poly: &P,
    ) -> C::G1Affine {
        poly.coeffs()
            .iter()
            .zip(self.g1.iter().take(poly.coeffs().len()))
            .fold(C::G1Affine::zero(), |acc, (coeff, base)| {
                (acc + *base * *coeff).into()
            })
    }

    pub fn commit_g2<P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>>(
        &self,
        poly: &P,
    ) -> C::G2Affine {
        poly.coeffs()
            .iter()
            .zip(self.g2.iter().take(poly.coeffs().len()))
            .fold(C::G2Affine::zero(), |acc, (coeff, base)| {
                (acc + *base * *coeff).into()
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::Polynomial;
    use ark_std::One;

    type Scalar = <BlsCurve as Pairing>::ScalarField;
    type UniPoly = DensePolynomial<Scalar>;

    #[test]
    fn commitment() {
        let tau = Scalar::from(2);
        // 3 - 2x + x^2
        let poly =
            UniPoly::from_coefficients_slice(&[Scalar::from(3), -Scalar::from(2), Scalar::one()]);
        let poly_tau = poly.evaluate(&tau);
        assert_eq!(poly_tau, Scalar::from(3));
        // kzg
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, 10);
        let com_g1 = powers.commit_g1(&poly);
        let com_g2 = powers.commit_g2(&poly);

        assert_eq!(com_g1, (G1Affine::generator() * poly_tau).into_affine());
        assert_eq!(com_g2, (G2Affine::generator() * poly_tau).into_affine());
    }
}
