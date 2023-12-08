// NOTE code mostly taken from https://github.com/roynalnaruto/range_proof
mod utils;
use utils::*;

use crate::commit::kzg::Powers;
use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::rand::Rng;
use ark_std::UniformRand;

pub struct Evaluations<S> {
    pub g: S,
    pub g_omega: S,
    pub w_cap: S,
}

pub struct Commitments<C: Pairing> {
    pub f: C::G1,
    pub g: C::G1,
    pub q: C::G1,
}

pub struct RangeProof<C: Pairing> {
    pub evaluations: Evaluations<C::ScalarField>,
    pub commitments: Commitments<C>,
    pub aggregate_witness_commitment: C::G1,
    pub shifted_witness_commitment: C::G1,
    // TODO transcript?
    // tau
    // rho
    // aggregation_chalenge
}

impl<C: Pairing> RangeProof<C> {
    // prove 0 <= z < 2^n
    pub fn new<R: Rng>(z: C::ScalarField, n: usize, powers: &Powers<C>, rng: &mut R) -> Self {
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(n).expect("valid domain");
        let domain_2n =
            GeneralEvaluationDomain::<C::ScalarField>::new(2 * n).expect("valid domain");

        // random scalars
        let r = C::ScalarField::rand(rng);
        let alpha = C::ScalarField::rand(rng);
        let beta = C::ScalarField::rand(rng);
        let tau = C::ScalarField::rand(rng); // for aggregation
        let aggregation_challenge = C::ScalarField::rand(rng);

        // compute all polynomials
        let f_poly = compute_f_poly(&domain, z, r);
        let g_poly = compute_g_poly(&domain, z, alpha, beta);
        let (w1_poly, w2_poly) = compute_w1_w2_polys(&domain, &f_poly, &g_poly);
        let w3_poly = compute_w3_poly(&domain, &domain_2n, &g_poly);

        // aggregate w1, w2 and w3 to compute quotient polynomial
        let q_poly = compute_quotient_poly(&domain, &w1_poly, &w2_poly, &w3_poly, tau);

        // compute commitments to polynomials
        let f_commitment = powers.commit_g1(&f_poly);
        let g_commitment = powers.commit_g1(&g_poly);
        let q_commitment = powers.commit_g1(&q_poly);

        let rho = C::ScalarField::rand(rng); // random eval point
        let rho_omega: C::ScalarField = rho * domain.group_gen();
        // evaluate g at rho
        let g_eval = g_poly.evaluate(&rho);
        // evaluate g at `rho * omega`
        let g_omega_eval = g_poly.evaluate(&rho_omega);

        // compute evaluation of w_cap at ρ
        let w_cap_poly = compute_w_cap_poly(&domain, &f_poly, &q_poly, rho);
        let w_cap_eval = w_cap_poly.evaluate(&rho);

        // compute witness for g(X) at ρw
        let shifted_witness_poly = create_witness(&g_poly, rho_omega);
        let shifted_witness_commitment = powers.commit_g1(&shifted_witness_poly);

        // compute aggregate witness for
        // g(X) at ρ, f(X) at ρ, w_cap(X) at ρ
        let aggregate_witness_poly =
            create_aggregate_witness(&[g_poly, w_cap_poly], rho, aggregation_challenge);
        let aggregate_witness_commitment = powers.commit_g1(&aggregate_witness_poly);

        let evaluations = Evaluations {
            g: g_eval,
            g_omega: g_omega_eval,
            w_cap: w_cap_eval,
        };

        let commitments = Commitments {
            f: f_commitment,
            g: g_commitment,
            q: q_commitment,
        };

        Self {
            evaluations,
            commitments,
            aggregate_witness_commitment,
            shifted_witness_commitment,
        }
    }

    pub fn verify(&self) -> bool {
        todo!()
    }
}
