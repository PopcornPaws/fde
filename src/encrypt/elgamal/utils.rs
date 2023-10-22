use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;

pub fn shift_scalar<S: PrimeField>(scalar: &S, by: usize) -> S {
    let mut bigint = S::one().into_bigint();
    bigint.muln(by as u32);
    *scalar * S::from_bigint(bigint).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_std::{One, Zero};

    #[test]
    fn scalar_shifting() {
        let scalar = Fr::zero();
        assert_eq!(shift_scalar(&scalar, 32), Fr::zero());

        let scalar = Fr::one();
        assert_eq!(
            shift_scalar(&scalar, 32),
            Fr::from(u64::from(u32::MAX) + 1u64)
        );

        // shifting with overflow
        // according to the docs, overflow is
        // ignored
        let scalar = Fr::one();
        assert_eq!(shift_scalar(&scalar, u32::MAX as usize), Fr::zero());
    }
}
