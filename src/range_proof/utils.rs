use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::ops::{AddAssign, Mul};
use ark_std::Zero;

// returns (rho^n - 1) / (rho - 1) and (rho^n - 1)
pub fn rho_relations<S: PrimeField>(size: usize, rho: S) -> (S, S) {
    let n_as_ref = S::from(size as u8).into_bigint();
    let one = S::one();
    let rho_n_minus_1 = rho.pow(n_as_ref) - one;
    let rho_n_minus_1_by_rho_minus_1 = rho_n_minus_1 / (rho - one);

    (rho_n_minus_1_by_rho_minus_1, rho_n_minus_1)
}

// computes the sum of
// - w1(x) = g * (x^n - 1) / (x - 1) // note that we don't compute (g - f) here
// - w2(x) = g * (1 - g) * (x^n - 1) / (x - omega^{n - 1})
// - w3(x) = (g(x) - 2 * g(x * omega)) * (1 - g(x) + 2 * g(x * omega)) * (x - omega^{n - 1})
//
// where g = g(rho), f = f(rho), i.e. the polynomial evaluations at point rho, n is the domain size
// and omega denotes the roots of unity
pub fn w1_w2_w3_evals_sum<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    g_eval: S,
    g_omega_eval: S,
    rho: S,
    tau: S,
) -> S {
    let (rho_n_minus_1_by_rho_minus_1, rho_n_minus_1) = rho_relations(domain.size(), rho);
    let one = S::one();
    let two = S::from(2u8);
    let w_n_minus_1 = domain.elements().last().unwrap();
    // w1_part
    let w1_eval = g_eval * rho_n_minus_1_by_rho_minus_1;
    // w2
    let w2_eval = g_eval * (one - g_eval) * rho_n_minus_1 / (rho - w_n_minus_1);
    // w3
    let w3_eval = {
        let part_a = g_eval - (two * g_omega_eval);
        let part_b = one - part_a;
        let part_c = rho - w_n_minus_1;
        part_a * part_b * part_c
    };

    w1_eval + tau * w2_eval + tau.square() * w3_eval
}

// returns w_cap(x) = f(x) * (rho^n - 1) / (rho - 1) + q(x) * (rho^n - 1)
pub fn w_cap<C: CurveGroup>(
    size: usize,
    f_commitment: C::Affine,
    q_commitment: C::Affine,
    rho: C::ScalarField,
) -> C::Affine {
    let (rho_relation_1, rho_relation_2) = rho_relations(size, rho);
    let f_commit = f_commitment * rho_relation_1;
    let q_commit = q_commitment * rho_relation_2;
    (f_commit + q_commit).into()
}

pub fn aggregate<T, S>(values: &[T], by: S) -> T
where
    S: PrimeField,
    T: Sized + Zero + Mul<S> + AddAssign<<T as Mul<S>>::Output> + Copy,
{
    let mut acc = S::one();
    let mut result = T::zero();

    for &value in values {
        let tmp = value * acc;
        result += tmp;
        acc *= by;
    }

    result
}
