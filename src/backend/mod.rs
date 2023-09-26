use crate::encrypt::elgamal::ExponentialElGamal;
use crate::encrypt::EncryptionEngine;
use ark_ec::pairing::Pairing;
use ark_ec::CurveGroup;
use ark_poly_commit::kzg10::KZG10;
use ark_poly_commit::DenseUVPolynomial;
use ark_std::marker::PhantomData;
use ark_std::ops::Neg;

pub trait Prover {
    type EncryptionEngine: EncryptionEngine;
    type CommitmentScheme;
}

pub struct ElGamalWithKzg<C, P> {
    _curve: PhantomData<C>,
    _polycommit: PhantomData<P>,
}

// proof for a single scalar
// if |F| = 2^256, then short ciphers should
// have length 8, because we split a single scalar
// into eight u32
pub struct Proof<C: Pairing, P> {
    short_ciphers: Vec<Cipher>,
    long_cipher: Cipher,
    commitment_poly_t: Commitment,
    commitment_poly_r: Commitment,
    h_s_star: C::G1Affine,
}


impl<C: Pairing, P: DenseUVPolynomial<C::ScalarField>> Prover for ElGamalWithKzg<C, P>
where
    <C::G1 as CurveGroup>::Affine: Neg<Output = <C::G1 as CurveGroup>::Affine>,
{
    type EncryptionEngine = ExponentialElGamal<C::G1>;
    type CommitmentScheme = KZG10<C, P>;
    type Proof = ElGamalWithKzgProof<C, P>;
}
