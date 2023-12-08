// NOTE code mostly taken from https://github.com/roynalnaruto/range_proof
mod utils;
use utils::*;

use crate::commit::kzg::{Kzg, Powers};
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::rand::Rng;
use ark_std::{One, UniformRand, Zero};

pub struct Evaluations<S> {
    pub g: S,
    pub g_omega: S,
    pub w_cap: S,
}

pub struct Commitments<C: Pairing> {
    pub f: C::G1Affine,
    pub g: C::G1Affine,
    pub q: C::G1Affine,
}

pub struct Proofs<C: Pairing> {
    pub aggregate: C::G1Affine,
    pub shifted: C::G1Affine,
}

pub struct RangeProof<C: Pairing> {
    pub evaluations: Evaluations<C::ScalarField>,
    pub commitments: Commitments<C>,
    pub proofs: Proofs<C>,
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
        let shifted_proof = powers.commit_g1(&shifted_witness_poly);

        // compute aggregate witness for
        // g(X) at ρ, f(X) at ρ, w_cap(X) at ρ
        let aggregate_witness_poly =
            create_aggregate_witness(&[g_poly, w_cap_poly], rho, aggregation_challenge);
        let aggregate_proof = powers.commit_g1(&aggregate_witness_poly);

        let evaluations = Evaluations {
            g: g_eval,
            g_omega: g_omega_eval,
            w_cap: w_cap_eval,
        };

        let commitments = Commitments {
            f: f_commitment.into_affine(),
            g: g_commitment.into_affine(),
            q: q_commitment.into_affine(),
        };

        let proofs = Proofs {
            aggregate: aggregate_proof.into_affine(),
            shifted: shifted_proof.into_affine(),
        };

        Self {
            evaluations,
            commitments,
            proofs,
        }
    }

    pub fn verify(
        &self,
        domain: &GeneralEvaluationDomain<C::ScalarField>,
        powers: &Powers<C>,
    ) -> bool {
        // TODO transcript
        let tau = C::ScalarField::one();
        let rho = C::ScalarField::one();
        let aggregation_challenge = C::ScalarField::one();

        // calculate w_cap_commitment
        let w_cap_commitment =
            compute_w_cap_commitment::<C::G1>(domain, self.commitments.f, self.commitments.q, rho);

        // calculate w2(ρ) and w3(ρ)
        let (w1_part, w2_part, w3_part) = compute_w1_w2_w3_evals(
            domain,
            self.evaluations.g,
            self.evaluations.g_omega,
            rho,
            tau,
        );

        // calculate w(ρ)
        // that should zero since w(X) is after all a zero polynomial
        let w_at_rho = w1_part + w2_part + w3_part - self.evaluations.w_cap;
        if !w_at_rho.is_zero() {
            return false;
        }

        // check aggregate witness commitment
        let aggregate_poly_commitment = aggregate_commitments::<C::G1>(
            &[self.commitments.g, w_cap_commitment],
            aggregation_challenge,
        );
        let aggregate_value = aggregate_values(
            &[self.evaluations.g, self.evaluations.w_cap],
            aggregation_challenge,
        );
        let aggregation_kzg_check = Kzg::verify_scalar(
            self.proofs.aggregate,
            aggregate_poly_commitment,
            rho,
            aggregate_value,
            powers,
        );

        // check shifted witness commitment
        let rho_omega = rho * domain.group_gen();
        let shifted_kzg_check = Kzg::verify_scalar(
            self.proofs.shifted,
            self.commitments.g,
            rho_omega,
            self.evaluations.g_omega,
            powers,
        );

        aggregation_kzg_check && shifted_kzg_check
    }
}
