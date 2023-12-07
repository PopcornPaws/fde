// NOTE code mostly taken from https://github.com/roynalnaruto/range_proof
use crate::commit::kzg::Powers;
use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
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
}

impl<C: Pairing> RangeProof<C> {
    // prove 0 <= num < 2^n
    pub fn new<R: Rng>(num: C::ScalarField, n: usize, powers: &Powers<C>, rng: &mut R) -> Self {
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(n).expect("valid domain");
        let domain_2n =
            GeneralEvaluationDomain::<C::ScalarField>::new(2 * n).expect("valid domain");

        // random scalars
        let r = C::ScalarField::rand(rng);
        let alpha = C::ScalarField::rand(rng);
        let beta = C::ScalarField::rand(rng);
        let tau = C::ScalarField::rand(rng); // for aggregation
        let aggregation_challenge = C::ScalarField::rand(rng);
        let rho = C::ScalarField::rand(rng); // random eval point
        let rho_omega: C::ScalarField = rho * domain.group_gen();

        // compute all polynomials

        todo!()
    }

    pub fn verify(&self) -> bool {
        todo!()
    }
}
