use super::utils::rho_relations;
use ark_ec::CurveGroup;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

pub fn w_cap<C: CurveGroup>(
    domain: &GeneralEvaluationDomain<C::ScalarField>,
    f_commitment: C::Affine,
    q_commitment: C::Affine,
    rho: C::ScalarField,
) -> C::Affine {
    let (rho_relation_1, rho_relation_2) = rho_relations(domain.size(), rho);
    let f_commit = f_commitment * rho_relation_1;
    let q_commit = q_commitment * rho_relation_2;
    (f_commit + q_commit).into()
}
