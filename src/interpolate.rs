use ark_ff::fields::PrimeField;
use ark_poly::polynomial::univariate::DensePolynomial;

// performs textbook interpolation over a scalar field
pub fn interpolate<S: PrimeField>(x: &[S], y: &[S]) -> DensePolynomial<S> {
    let n = x.len();
    let mut s = vec![S::zero(); n];
    let mut coeffs = vec![S::zero(); n];

    s.push(S::one());
    s[n - 1] = -x[0];

    for (i, &x_elem) in x.iter().enumerate().skip(1) {
        for j in n - 1 - i..n - 1 {
            let aux = x_elem * s[j + 1];
            s[j] -= aux;
        }
        s[n - 1] -= x_elem;
    }

    for i in 0..n {
        let mut phi = S::zero();
        for j in (1..=n).rev() {
            phi *= x[i];
            phi += S::from(j as u64) * s[j];
        }
        let mut b = S::one();
        for j in (0..n).rev() {
            let aux = y[i] * b / phi;
            coeffs[j] += aux;
            b *= x[i];
            b += s[j];
        }
    }

    DensePolynomial { coeffs }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::Scalar;
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain, Polynomial};
    use ark_std::ops::Neg;
    use ark_std::{test_rng, UniformRand};
    use ark_std::{One, Zero};

    #[test]
    fn interpolation_works() {
        // constant polynomial (y = 53)
        let x = vec![Scalar::from(3_u64); 1];
        let y = vec![Scalar::from(53_u64); 1];
        let poly = interpolate(&x, &y);
        assert_eq!(poly.coeffs, &[Scalar::from(53_u64)]);
        assert_eq!(
            poly.evaluate(&Scalar::from(123456_u64)),
            Scalar::from(53_u64),
        );
        assert_eq!(
            poly.evaluate(&Scalar::from(78910_u64)),
            Scalar::from(53_u64),
        );

        // simple first order polynomial (y = x)
        let x = vec![Scalar::from(1_u64), Scalar::from(2_u64)];

        let y = x.clone();
        let poly = interpolate(&x, &y);
        assert_eq!(poly.coeffs, &[Scalar::zero(), Scalar::one()]);

        // first order polynomial (y = 32 * x - 13)
        let x = vec![Scalar::from(2_u64), Scalar::from(3_u64)];
        let y = vec![Scalar::from(51_u64), Scalar::from(83_u64)];
        let poly = interpolate(&x, &y);
        assert_eq!(
            poly.coeffs,
            &[Scalar::from(13_u64).neg(), Scalar::from(32_u64)]
        );

        assert_eq!(poly.evaluate(&x[0]), y[0]);
        assert_eq!(poly.evaluate(&x[1]), y[1]);
        assert_eq!(
            poly.evaluate(&Scalar::from(100_u64)),
            Scalar::from(3187_u64)
        );

        // fourth order polynomial
        // y = x^4 + 0 * x^3 + 3 * x^2 + 2 * x + 14
        let x = vec![
            Scalar::from(1_u64),
            Scalar::from(2_u64),
            Scalar::from(3_u64),
            Scalar::from(4_u64),
            Scalar::from(5_u64),
            Scalar::from(6_u64),
        ];
        let y = vec![
            Scalar::from(20_u64),
            Scalar::from(46_u64),
            Scalar::from(128_u64),
            Scalar::from(326_u64),
            Scalar::from(724_u64),
            Scalar::from(1430_u64),
        ];
        let poly = interpolate(&x, &y);
        x.iter()
            .zip(y)
            .for_each(|(x, y)| assert_eq!(poly.evaluate(x), y));
        poly.coeffs
            .into_iter()
            .zip([14u64, 2, 3, 0, 1])
            .for_each(|(coeff, s)| assert_eq!(coeff, Scalar::from(s)));
    }

    #[test]
    fn interpolation_with_domain_works() {
        let rng = &mut test_rng();
        let evals: Vec<Scalar> = (0..64).map(|_| Scalar::rand(rng)).collect();
        let general_domain = GeneralEvaluationDomain::new(evals.len()).unwrap();

        let domain: Vec<Scalar> = general_domain.elements().collect();
        let other_poly = interpolate(&domain, &evals);

        let evaluations = Evaluations::from_vec_and_domain(evals, general_domain);
        let poly = evaluations.interpolate_by_ref();

        assert_eq!(poly, other_poly);
    }
}
