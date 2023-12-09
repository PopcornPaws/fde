use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::ops::{AddAssign, Mul};
use ark_std::Zero;

pub fn rho_relations<S: PrimeField>(size: usize, rho: S) -> (S, S) {
    let n_as_ref = S::from(size as u8).into_bigint();
    let one = S::one();
    let rho_n_minus_1 = rho.pow(n_as_ref) - one;
    let rho_n_minus_1_by_rho_minus_1 = rho_n_minus_1 / (rho - one);

    (rho_n_minus_1_by_rho_minus_1, rho_n_minus_1)
}

pub fn w1_w2_w3_evals<S: PrimeField>(
    domain: &GeneralEvaluationDomain<S>,
    g_eval: S,
    g_omega_eval: S,
    rho: S,
    tau: S,
) -> (S, S, S) {
    let (_, rho_n_minus_1) = rho_relations(domain.size(), rho);
    let one = S::one();
    let two = S::from(2u8);
    let w_n_minus_1 = domain.elements().last().unwrap();
    // w1_part
    let w1_eval = g_eval * rho_n_minus_1 / (rho - one);
    // w2
    let w2_eval = g_eval * (one - g_eval) * rho_n_minus_1 / (rho - w_n_minus_1);
    // w3
    let w3_eval = {
        let part_a = g_eval - (two * g_omega_eval);
        let part_b = one - part_a;
        let part_c = rho - w_n_minus_1;
        part_a * part_b * part_c
    };

    (w1_eval, tau * w2_eval, tau * tau * w3_eval)
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
