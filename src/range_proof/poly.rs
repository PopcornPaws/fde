use ark_ff::{BigInteger, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};

pub fn f<S: PrimeField>(domain: &GeneralEvaluationDomain<S>, z: S, r: S) -> DensePolynomial<S> {
    // f is a linear polynomial: f(1) = z
    DensePolynomial::from_coefficients_vec(domain.ifft(&[z, r]))
}

pub fn g<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    z: S,
    alpha: S,
    beta: S,
) -> DensePolynomial<S> {
    // get bits for z -> consider only the first `n` bits
    let size = domain.size();
    let z_bits = &z.into_bigint().to_bits_le()[0..size];
    let mut evaluations: Vec<S> = vec![S::zero(); size];

    // take the first evaluation point, i.e. (n-1)th bit of z
    evaluations[size - 1] = S::from(z_bits[size - 1]);

    // for the rest of bits (n-2 .. 0)
    // g_i = 2* g_(i+1) + z_i
    z_bits
        .iter()
        .enumerate()
        .rev()
        .skip(1)
        .for_each(|(i, &bit)| {
            evaluations[i] = S::from(2u8) * evaluations[i + 1] + S::from(bit as u8);
        });

    // compute g
    let g_poly = DensePolynomial::from_coefficients_vec(domain.ifft(&evaluations));

    // extended domain
    let domain_ext = GeneralEvaluationDomain::<S>::new(size + 1).expect("valid domain");

    // Map the original g_poly to domain(n+1). Add random values alpha and beta as evaluations of g
    // at all even indices, g_evals[2k] matches the evaluation at some original root of unity.
    // Hence only update two odd indices with alpha and beta this makes g evaluate to the expected
    // evaluations at all roots of unity of domain size `n`, but makes is a different polynomial
    let mut g_evals = domain_ext.fft(&g_poly);
    g_evals[1] = alpha;
    g_evals[3] = beta;

    DensePolynomial::from_coefficients_vec(domain_ext.ifft(&g_evals))
}

pub fn w1_w2<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    f_poly: &DensePolynomial<S>,
    g_poly: &DensePolynomial<S>,
) -> (DensePolynomial<S>, DensePolynomial<S>) {
    let one = S::one();
    let w_n_minus_1 = domain.elements().last().unwrap();

    // polynomial: P(x) = x - w^(n-1)
    let x_minus_w_n_minus_1_poly = DensePolynomial::from_coefficients_slice(&[-w_n_minus_1, one]);

    // polynomial: P(x) = x^n - 1
    let x_n_minus_1_poly = DensePolynomial::from(domain.vanishing_polynomial());

    // polynomial: P(x) = x - 1
    let x_minus_1_poly = DensePolynomial::from_coefficients_slice(&[-one, one]);

    let g_minus_f_poly = g_poly - f_poly;
    let w1_poly = &(&g_minus_f_poly * &x_n_minus_1_poly) / &x_minus_1_poly;

    // polynomial: P(x) = 1
    let one_poly = DensePolynomial::from_coefficients_slice(&[one]);
    let one_minus_g_poly = &one_poly - g_poly;
    let w2_poly = &(&(g_poly * &one_minus_g_poly) * &x_n_minus_1_poly) / &x_minus_w_n_minus_1_poly;

    (w1_poly, w2_poly)
}

pub fn w3<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    domain_2n: &GeneralEvaluationDomain<S>,
    g_poly: &DensePolynomial<S>,
) -> DensePolynomial<S> {
    // w3: [g(X) - 2g(Xw)] * [1 - g(X) + 2g(Xw)] * [X - w^(n-1)]
    // degree of g = n - 1
    // degree of w3 = (2n - 1) + (2n - 1) + 1 = 4n - 1
    // the new domain can be of size 4n
    let domain_4n = GeneralEvaluationDomain::<S>::new(2 * domain_2n.size()).unwrap();

    // find evaluations of g in the new domain
    let mut g_evals = domain_4n.fft(g_poly);

    // since we have doubled the domain size, the roots of unity of the new domain will also occur
    // among the roots of unity of the original domain. hence, if g(X) <- g_evals[i] then g(Xw) <-
    // g_evals[i+4]
    g_evals.push(g_evals[0]);
    g_evals.push(g_evals[1]);
    g_evals.push(g_evals[2]);
    g_evals.push(g_evals[3]);

    // calculate evaluations of w3
    let w_n_minus_1 = domain.elements().last().unwrap();
    let two = S::from(2u8);
    let w3_evals: Vec<S> = domain_4n
        .elements()
        .enumerate()
        .map(|(i, x_i)| {
            let part_a = g_evals[i] - (two * g_evals[i + 4]);
            let part_b = S::one() - g_evals[i] + (two * g_evals[i + 4]);
            let part_c = x_i - w_n_minus_1;
            part_a * part_b * part_c
        })
        .collect();

    DensePolynomial::from_coefficients_vec(domain_4n.ifft(&w3_evals))
}

pub fn w_cap<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    f_poly: &DensePolynomial<S>,
    q_poly: &DensePolynomial<S>,
    rho: S,
) -> DensePolynomial<S> {
    let (rho_1, rho_2) = super::utils::rho_relations(domain.size(), rho);
    let rho_poly_1 = DensePolynomial::from_coefficients_slice(&[rho_1]);
    let rho_poly_2 = DensePolynomial::from_coefficients_slice(&[rho_2]);
    &(f_poly * &rho_poly_1) + &(q_poly * &rho_poly_2)
}

pub fn quotient<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    w1_poly: &DensePolynomial<S>,
    w2_poly: &DensePolynomial<S>,
    w3_poly: &DensePolynomial<S>,
    tau: S,
) -> DensePolynomial<S> {
    // find constant polynomials for tau and tau^2
    let (tau_poly, tau2_poly) = tau_12(tau);
    // find linear combination of w1, w2, w3
    let lc = &(w1_poly + &(w2_poly * &tau_poly)) + &(w3_poly * &tau2_poly);
    let (_, quotient_poly) = lc
        .divide_by_vanishing_poly(*domain)
        .expect("valid vanishing poly");
    quotient_poly
}

pub fn tau_12<S: PrimeField>(tau: S) -> (DensePolynomial<S>, DensePolynomial<S>) {
    (
        DensePolynomial::from_coefficients_slice(&[tau]),
        DensePolynomial::from_coefficients_slice(&[tau.square()]),
    )
}

#[cfg(test)]
mod test {
    use crate::commit::kzg::Powers;
    use crate::tests::{BlsCurve, Scalar};
    use ark_ec::pairing::Pairing;
    use ark_ec::CurveGroup;
    use ark_ff::{Field, PrimeField};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial};
    use ark_std::{test_rng, UniformRand};
    use ark_std::{One, Zero};

    fn w2_w3_parts<S: PrimeField>(
        w2: &DensePolynomial<S>,
        w3: &DensePolynomial<S>,
        tau: S,
    ) -> (DensePolynomial<S>, DensePolynomial<S>) {
        let (poly_tau, poly_tau_2) = super::tau_12(tau);
        (w2 * &poly_tau, w3 * &poly_tau_2)
    }

    fn w1_part<S: PrimeField>(
        domain: &GeneralEvaluationDomain<S>,
        g_poly: &DensePolynomial<S>,
    ) -> DensePolynomial<S> {
        let one = S::one();
        let divisor = DensePolynomial::<S>::from_coefficients_slice(&[-one, one]);
        &g_poly.mul_by_vanishing_poly(*domain) / &divisor
    }

    #[test]
    fn compute_f_poly_success() {
        let rng = &mut test_rng();
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let z = Scalar::from(2u8);
        let r = Scalar::from(4u8);
        let f_poly = super::f(&domain, z, r);

        let rho = Scalar::rand(rng);

        assert_eq!(f_poly.evaluate(&Scalar::one()), z);
        assert_eq!(f_poly.evaluate(&domain.group_gen()), r);
        assert_ne!(f_poly.evaluate(&rho), z);
        assert_ne!(f_poly.evaluate(&rho), r);
    }
    #[test]
    fn compute_g_poly_success() {
        let rng = &mut test_rng();
        // n = 8, 2^n = 256, 0 <= z < 2^n degree of polynomial should be (n - 1) it should also
        // evaluate to `z` at x = 1
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let z = Scalar::from(100u8);

        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let g_poly = super::g(&domain, z, alpha, beta);
        assert_eq!(g_poly.degree(), 2 * n - 1);
        assert_eq!(g_poly.evaluate(&Scalar::one()), z);

        // n2 = 4, 2^n2 = 16, 0 <= z < 2^n2 degree of polynomial should be (n2 - 1) it should also
        // evaluate to `z2` at x = 1
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let z = Scalar::from(13u8);

        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let g_poly = super::g(&domain, z, alpha, beta);
        assert_eq!(g_poly.degree(), 2 * n - 1);
        assert_eq!(g_poly.evaluate(&Scalar::one()), z);
    }

    #[test]
    fn compute_w1_w2_polys_success() {
        let rng = &mut test_rng();

        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();

        let one = Scalar::one();
        let zero = Scalar::zero();
        let r = Scalar::rand(rng);
        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let z = Scalar::from(92u8);
        let f_poly = super::f(&domain, z, r);
        let g_poly = super::g(&domain, z, alpha, beta);

        let (w1_poly, w2_poly) = super::w1_w2(&domain, &f_poly, &g_poly);

        // both w1 and w2 should evaluate to 0 at x = 1
        assert_eq!(w1_poly.evaluate(&one), zero);
        assert_eq!(w2_poly.evaluate(&one), zero);

        // both w1 and w2 should evaluate to 0 at all roots of unity
        for root in domain.elements() {
            assert_eq!(w1_poly.evaluate(&root), zero);
            assert_eq!(w2_poly.evaluate(&root), zero);
        }

        let n_as_ref = Scalar::from(n as u8).into_bigint();
        // evaluate w1 at a random field element
        let r = Scalar::rand(rng);
        let part_a = g_poly.evaluate(&r);
        let part_b = f_poly.evaluate(&r);
        let part_c = (r.pow(n_as_ref) - one) / (r - one);
        let w1_expected = (part_a - part_b) * part_c;
        assert_eq!(w1_poly.evaluate(&r), w1_expected);

        // evaluate w2 at a random field element
        let w_n_minus_1 = domain.elements().last().unwrap();
        let r = Scalar::rand(rng);
        let part_a = g_poly.evaluate(&r);
        let part_b = one - part_a;
        let part_c = (r.pow(n_as_ref) - one) / (r - w_n_minus_1);
        let w2_expected = part_a * part_b * part_c;
        assert_eq!(w2_poly.evaluate(&r), w2_expected);
    }

    #[test]
    fn compute_w3_poly_success() {
        let rng = &mut test_rng();

        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let domain_2n = GeneralEvaluationDomain::<Scalar>::new(2 * n).unwrap();

        let one = Scalar::one();
        let two = Scalar::from(2u8);

        let z = Scalar::from(83u8);
        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let g_poly = super::g(&domain, z, alpha, beta);

        let w3_poly = super::w3(&domain, &domain_2n, &g_poly);

        // w3 should evaluate to 0 at all roots of unity for original domain
        for root in domain.elements() {
            assert!(w3_poly.evaluate(&root).is_zero());
        }

        // w3 degree should be 4n - 1
        assert_eq!(w3_poly.degree(), 4 * domain.size() - 1);

        // evaluate w3 at a random field element
        let w_n_minus_1 = domain.elements().last().unwrap();
        let r = Scalar::rand(rng);
        let part_a = g_poly.evaluate(&r) - two * g_poly.evaluate(&(r * domain.group_gen()));
        let part_b = one - g_poly.evaluate(&r) + two * g_poly.evaluate(&(r * domain.group_gen()));
        let part_c = r - w_n_minus_1;
        let w3_expected = part_a * part_b * part_c;
        assert_eq!(w3_poly.evaluate(&r), w3_expected);

        // evaluate w3 at another random field element
        let r = Scalar::rand(rng);
        let part_a = g_poly.evaluate(&r) - two * g_poly.evaluate(&(r * domain.group_gen()));
        let part_b = one - g_poly.evaluate(&r) + two * g_poly.evaluate(&(r * domain.group_gen()));
        let part_c = r - w_n_minus_1;
        let w3_expected = part_a * part_b * part_c;
        assert_eq!(w3_poly.evaluate(&r), w3_expected);
    }

    #[test]
    fn compute_q_poly_success() {
        let rng = &mut test_rng();
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let domain_2n = GeneralEvaluationDomain::<Scalar>::new(2 * n).unwrap();

        let z = Scalar::from(68u8);
        let r = Scalar::rand(rng);
        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let f_poly = super::f(&domain, z, r);
        let g_poly = super::g(&domain, z, alpha, beta);
        let (w1_poly, w2_poly) = super::w1_w2(&domain, &f_poly, &g_poly);
        let w3_poly = super::w3(&domain, &domain_2n, &g_poly);

        let tau = Scalar::rand(rng);

        let q_poly = super::quotient(&domain, &w1_poly, &w2_poly, &w3_poly, tau);

        // since the linear combination should also satisfy all roots of unity, q_rem should be a
        // zero polynomial
        assert_eq!(
            q_poly,
            DensePolynomial::from_coefficients_slice(&[Scalar::zero()])
        );
    }

    #[test]
    fn compute_w_cap_poly_success() {
        let rng = &mut test_rng();

        // domain setup
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let domain_2n = GeneralEvaluationDomain::<Scalar>::new(2 * n).unwrap();
        // KZG setup
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, 4 * n);

        // random numbers
        let r = Scalar::rand(rng);
        let t = Scalar::rand(rng);
        let rho = Scalar::rand(rng);
        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);

        // compute polynomials
        let z = Scalar::from(68u8);
        let f_poly = super::f(&domain, z, r);
        let g_poly = super::g(&domain, z, alpha, beta);
        let (w1_poly, w2_poly) = super::w1_w2(&domain, &f_poly, &g_poly);
        let w3_poly = super::w3(&domain, &domain_2n, &g_poly);
        let q_poly = super::quotient(&domain, &w1_poly, &w2_poly, &w3_poly, t);
        let w_cap_poly = super::w_cap(&domain, &f_poly, &q_poly, rho);

        // compute commitments
        let f_commitment = powers.commit_g1(&f_poly).into_affine();
        let q_commitment = powers.commit_g1(&q_poly).into_affine();
        let w_cap_commitment_expected = powers.commit_g1(&w_cap_poly);

        // calculate w_cap commitment fact that commitment scheme is additively homomorphic
        let w_cap_commitment_calculated = super::super::commitment::w_cap::<
            <BlsCurve as Pairing>::G1,
        >(&domain, f_commitment, q_commitment, rho);

        assert_eq!(w_cap_commitment_expected, w_cap_commitment_calculated);

        // check evaluations
        let w_cap_eval = w_cap_poly.evaluate(&rho);
        let g_eval = g_poly.evaluate(&rho);
        let g_omega_eval = g_poly.evaluate(&(rho * domain.group_gen()));
        let (w1, w2, w3) =
            super::super::utils::w1_w2_w3_evals(&domain, g_eval, g_omega_eval, rho, tau);
        assert_eq!(w1 + w2 + w3, w_cap_eval);
    }

    #[test]
    fn compute_w1_part_success() {
        let rng = &mut test_rng();
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let z = Scalar::from(92u8);
        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let g_poly = super::g(&domain, z, alpha, beta);

        let rho = Scalar::rand(rng);
        let g_eval = g_poly.evaluate(&rho);

        let n_as_ref = Scalar::from(domain.size() as u8).into_bigint();
        let one = Scalar::one();
        let rho_n_minus_1 = rho.pow(n_as_ref) - one;

        let w1_part_poly = w1_part(&domain, &g_poly);

        assert_eq!(
            w1_part_poly.evaluate(&rho),
            g_eval * rho_n_minus_1 / (rho - one)
        )
    }

    #[test]
    fn test_compute_w2_w3_part() {
        let rng = &mut test_rng();

        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Scalar>::new(n).unwrap();
        let domain_2n = GeneralEvaluationDomain::<Scalar>::new(2 * n).unwrap();

        let z = Scalar::from(92u8);
        let r = Scalar::rand(rng);
        let alpha = Scalar::rand(rng);
        let beta = Scalar::rand(rng);
        let f_poly = super::f(&domain, z, r);
        let g_poly = super::g(&domain, z, alpha, beta);
        let (_, w2) = super::w1_w2(&domain, &f_poly, &g_poly);
        let w3 = super::w3(&domain, &domain_2n, &g_poly);

        let tau = Scalar::rand(rng);
        let rho = Scalar::rand(rng);
        let g_eval = g_poly.evaluate(&rho);
        let g_omega_eval = g_poly.evaluate(&(rho * domain.group_gen()));

        let (_, rho_n_minus_1) = super::super::utils::rho_relations(domain.size(), rho);
        let one = Scalar::one();
        let two = Scalar::from(2u8);
        let w_n_minus_1 = domain.elements().last().unwrap();

        let (w2_part_poly, w3_part_poly) = w2_w3_parts(&w2, &w3, tau);

        assert_eq!(
            w2_part_poly.evaluate(&rho),
            tau * g_eval * (one - g_eval) * (rho_n_minus_1) / (rho - w_n_minus_1)
        );

        assert_eq!(w3_part_poly.evaluate(&rho), {
            let part_a = g_eval - (two * g_omega_eval);
            let part_b = one - part_a;
            let part_c = rho - w_n_minus_1;
            tau * tau * part_a * part_b * part_c
        });
    }
}
