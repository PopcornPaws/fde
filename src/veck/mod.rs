pub mod kzg_elgamal;
#[cfg(feature = "paillier")]
pub mod kzg_paillier;

use crate::commit::kzg::Powers;
use ark_ec::pairing::Pairing;
use ark_ec::Group;
use ark_ff::FftField;
use ark_poly::univariate::DensePolynomial;
use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
use ark_std::collections::HashMap;

fn subset_pairing_check<C: Pairing>(
    phi: &DensePolynomial<C::ScalarField>,
    phi_s: &DensePolynomial<C::ScalarField>,
    domain: &GeneralEvaluationDomain<C::ScalarField>,
    subdomain: &GeneralEvaluationDomain<C::ScalarField>,
    powers: &Powers<C>,
) {
    let vanishing_poly = DensePolynomial::from(domain.vanishing_polynomial());
    let quotient = &(phi - phi_s) / &vanishing_poly;
    let quotient_expected = (phi - phi_s)
        .divide_by_vanishing_poly(*domain)
        .unwrap()
        .0;
    assert_eq!(quotient, quotient_expected);
    // this only works with powers of tau
    //let com_q = powers.commit_g1(&quotient);
    //let com_f = powers.commit_g1(phi);
    //let com_f_s = powers.commit_g1(phi_s);
    //let com_v = powers.commit_g2(&vanishing_poly);
    //let lhs_pairing = C::pairing(com_q, com_v);
    //let rhs_pairing = C::pairing(com_f - com_f_s, C::G2::generator());
    //assert_eq!(lhs_pairing, rhs_pairing);

    let phi_evals = phi.evaluate_over_domain_by_ref(*subdomain);
    let phi_s_evals = phi_s.evaluate_over_domain_by_ref(*subdomain);
    let q_evals = quotient.evaluate_over_domain_by_ref(*subdomain);
    let v_evals = vanishing_poly.evaluate_over_domain_by_ref(*subdomain);
    let com_q = powers.commit_scalars_g1(&q_evals.evals);
    let com_f = powers.commit_scalars_g1(&phi_evals.evals);
    let com_f_s = powers.commit_scalars_g1(&phi_s_evals.evals);
    let com_v = powers.commit_scalars_g2(&v_evals.evals);
    let lhs_pairing = C::pairing(com_q, com_v);
    let rhs_pairing = C::pairing(com_f - com_f_s, C::G2::generator());
    assert_eq!(lhs_pairing, rhs_pairing);
}

// TODO move index map out of here so that it's not recomputed every time
fn subset_evals<S: FftField>(
    evaluations: &Evaluations<S>,
    subdomain: GeneralEvaluationDomain<S>,
) -> Evaluations<S> {
    debug_assert!(evaluations.domain().size() >= subdomain.size());
    let index_map: HashMap<S, usize> = evaluations
        .domain()
        .elements()
        .enumerate()
        .map(|(i, e)| (e, i))
        .collect();
    let indices = subdomain
        .elements()
        .map(|e| *index_map.get(&e).unwrap())
        .collect::<Vec<usize>>();
    let mut subset_evals = Vec::<S>::new();
    for index in indices {
        subset_evals.push(evaluations.evals[index]);
    }
    Evaluations::from_vec_and_domain(subset_evals, subdomain)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tests::{BlsCurve, Scalar};
    use ark_std::{test_rng, UniformRand};

    const DATA_SIZE: usize = 32;
    const SUBSET_SIZE: usize = 16;

    #[test]
    fn mivan() {
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng);
        let powers = Powers::<BlsCurve>::unsafe_setup_eip_4844(tau, DATA_SIZE + 1);

        let domain = GeneralEvaluationDomain::new(DATA_SIZE).unwrap();
        let subdomain = GeneralEvaluationDomain::new(SUBSET_SIZE).unwrap();

        let data = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let subset_evaluations = subset_evals(&evaluations, subdomain);

        let phi = evaluations.interpolate_by_ref();
        let phi_s = subset_evaluations.interpolate_by_ref();
        subset_pairing_check(&phi, &phi_s, &domain, &subdomain, &powers);

        let r_scalars: Vec<Scalar> = (0..SUBSET_SIZE).map(|_| Scalar::rand(rng)).collect();
        let t = powers.commit_scalars_g1(&r_scalars);
        let challenge = Scalar::rand(rng);
        let z_scalars: Vec<Scalar> = r_scalars
            .iter()
            .zip(&subset_evaluations.evals)
            .map(|(&r, &v)| r + challenge * v)
            .collect();
        let com_f_s_poly = powers.commit_scalars_g1(&subset_evaluations.evals);
        let commitment_pow_challenge = com_f_s_poly * challenge;
        let com_z = powers.commit_scalars_g1(&z_scalars);
        let t_expected = com_z - commitment_pow_challenge;
        assert_eq!(t, t_expected);
    }
}
