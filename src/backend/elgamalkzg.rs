use crate::encrypt::elgamal::ExponentialElgamal;
use crate::encrypt::EncryptionEngine;
use ark_ec::pairing::Pairing;
use ark_ff::biginteger::BigInteger;
use ark_ff::fields::PrimeField;
use ark_std::rand::Rng;
// proof for a single scalar
// if |F| = 2^256, then short ciphers should
// have length 8, because we split a single scalar
// into eight u32
pub struct Proof<C: Pairing> {
    short_ciphers: Vec<<ExponentialElgamal<C::G1> as EncryptionEngine>::Cipher>,
    long_cipher: <ExponentialElgamal<C::G1> as EncryptionEngine>::Cipher,
    commitment_poly_f: C::G1Affine,
    commitment_poly_t: C::G1Affine,
    commitment_poly_r: C::G1Affine,
    h_secret_star: C::G2Affine,
}

//impl<C, P> Proof<C, P>
//where
//    C: Pairing,
//    P: DenseUVPolynomial<C::ScalarField, Point = C::ScalarField>,
//    for<'a, 'b> &'a P: Div<&'b P, Output = P>,
//{
//    pub fn new<R: Rng>(rng: &mut R) -> Self {
//        todo!();
//        // generate kzg parameters
//        // convert data into chunks of Fr and 8xFr
//        // interpolate evaluations (Fr) with indices to obtain f
//        // commit f
//        //
//    }
//}

#[derive(Clone, Copy, Debug)]
struct SplitScalar<const N: usize, const M: usize, S>([S; N]);

impl<const N: usize, const M: usize, S: PrimeField> SplitScalar<N, M, S> {
    pub fn new(inner: [S; N]) -> Self {
        Self(inner)
    }

    pub fn reconstruct(&self) -> S {
        self.splits()
            .iter()
            .enumerate()
            .fold(S::zero(), |acc, (i, split)| {
                let shift = shift_scalar(split, (M * i) as u32);
                acc + shift
            })
    }

    pub fn encrypt<E, R>(
        self,
        encryption_key: &E::EncryptionKey,
        rng: &mut R,
    ) -> ([E::Cipher; N], S)
    where
        E: EncryptionEngine<PlainText = S>,
        E::Cipher: ark_std::fmt::Debug,
        R: Rng,
    {
        let rands: Vec<S> = (0..N).into_iter().map(|_| S::rand(rng)).collect();
        let ciphers: Vec<E::Cipher> = self
            .0
            .iter()
            .zip(&rands)
            .map(|(s, r)| E::encrypt_with_randomness(s, encryption_key, r))
            .collect();

        let shifted_rand_sum = rands.iter().enumerate().fold(S::zero(), |acc, (i, r)| {
            acc + shift_scalar(r, (M * i) as u32)
        });
        (ciphers.try_into().unwrap(), shifted_rand_sum)
    }

    pub fn splits(&self) -> &[S; N] {
        &self.0
    }
}

fn shift_scalar<S: PrimeField>(scalar: &S, by: u32) -> S {
    let mut bigint = S::one().into_bigint();
    bigint.muln(by);
    *scalar * S::from_bigint(bigint).unwrap()
}

impl<const N: usize, const M: usize, S: PrimeField> From<S> for SplitScalar<N, M, S> {
    fn from(scalar: S) -> Self {
        let scalar_le_bytes = scalar.into_bigint().to_bits_le();
        let mut output = [S::zero(); N];

        for (i, chunk) in scalar_le_bytes.chunks(M).enumerate() {
            let split = S::from_bigint(<S::BigInt as BigInteger>::from_bits_le(chunk)).unwrap();
            output[i] = split;
        }
        Self::new(output)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commit::kzg::Powers;
    use crate::encrypt::elgamal::Cipher;
    use ark_bls12_381::{Bls12_381 as BlsCurve, G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_poly::domain::general::GeneralEvaluationDomain;
    use ark_poly::evaluations::univariate::Evaluations;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, Polynomial};
    use ark_std::{test_rng, One, UniformRand, Zero};

    const BITS: usize = 32;

    type Scalar = <BlsCurve as Pairing>::ScalarField;
    type SpScalar = SplitScalar<{ Scalar::MODULUS_BIT_SIZE as usize }, BITS, Scalar>;
    type UniPoly = DensePolynomial<Scalar>;
    type Elgamal = ExponentialElgamal<<BlsCurve as Pairing>::G1>;

    #[test]
    fn flow() {
        let rng = &mut test_rng();

        let domain = GeneralEvaluationDomain::<Scalar>::new(3).unwrap();
        let data = vec![
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(6),
            Scalar::from(11),
        ];
        let evaluations = Evaluations::from_vec_and_domain(data, domain);

        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let index = Scalar::from(7u32);
        let eval = f_poly.evaluate(&index);

        // secret-gen
        let tau = Scalar::rand(rng);
        let secret = Scalar::rand(rng);
        let encryption_pk = (G1Affine::generator() * secret).into_affine();
        let secret_star = Scalar::rand(rng);
        let elgamal_r = Scalar::rand(rng);
        let h_secret_star = (G2Affine::generator() * secret * secret_star).into_affine();

        // elgamal encryption
        let cipher = Elgamal::encrypt_with_randomness(&eval, &encryption_pk, &elgamal_r);
        // compute polynomials
        // (x - eval) polynomial
        let d_poly = UniPoly::from_coefficients_slice(&[-index, Scalar::one()]);
        let s_s_star = UniPoly::from_coefficients_slice(&[secret * secret_star]);
        // (f(x) - eval) / (x - eval) + ss*
        let t_poly = &(&f_poly + &UniPoly::from_coefficients_slice(&[-eval])) / &d_poly + s_s_star;
        // - r / s_star - (x - eval)
        let r_poly = &UniPoly::from_coefficients_slice(&[-elgamal_r / secret_star]) - &d_poly;

        let powers = Powers::<BlsCurve>::unsafe_setup(tau, 10);

        let com_f = powers.commit_g1(&f_poly);
        let com_d = powers.commit_g2(&d_poly);
        let com_r = powers.commit_g1(&r_poly);
        let com_t = powers.commit_g1(&t_poly);

        let fp_pairing = BlsCurve::pairing(com_f - cipher.c1(), G2Affine::generator());
        let tp_pairing = BlsCurve::pairing(com_t, com_d);
        let rp_pairing = BlsCurve::pairing(com_r, h_secret_star);

        assert_eq!(fp_pairing, tp_pairing + rp_pairing);
    }

    #[test]
    fn scalar_splitting() {
        let scalar = Scalar::zero();
        let split_scalar = SpScalar::from(scalar);
        let reconstructed_scalar = split_scalar.reconstruct();
        assert_eq!(scalar, reconstructed_scalar);

        let rng = &mut test_rng();
        let max_scalar = Scalar::from(u32::MAX);
        for _ in 0..10 {
            let scalar = Scalar::rand(rng);
            let split_scalar = SpScalar::from(scalar);
            for split in split_scalar.splits() {
                assert!(split <= &max_scalar);
            }
            let reconstructed_scalar = split_scalar.reconstruct();
            assert_eq!(scalar, reconstructed_scalar);
        }
    }

    #[test]
    fn split_encryption() {
        let rng = &mut test_rng();
        let scalar = Scalar::rand(rng);
        let split_scalar = SpScalar::from(scalar);
        let secret = Scalar::rand(rng);
        let encryption_key = (G1Affine::generator() * secret).into_affine();

        let (ciphers, randomness) = split_scalar.encrypt::<Elgamal, _>(&encryption_key, rng);

        let cipher = Elgamal::encrypt_with_randomness(&scalar, &encryption_key, &randomness);

        let ciphers_sum = ciphers
            .into_iter()
            .enumerate()
            .fold(Cipher::zero(), |acc, (i, c)| {
                acc + c * shift_scalar(&Scalar::one(), (BITS * i) as u32)
            });
        assert_eq!(ciphers_sum, cipher);
    }
}
