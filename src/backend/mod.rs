//pub mod elgamalkzg;

//use crate::encrypt::elgamal::ExponentialElGamal;
//use crate::encrypt::EncryptionEngine;
//use ark_ec::CurveGroup;
//use ark_poly_commit::kzg10::KZG10;
//use ark_poly_commit::DenseUVPolynomial;
//use ark_std::marker::PhantomData;
//use ark_std::ops::Neg;

/*
pub trait Prover {
    type EncryptionEngine: EncryptionEngine;
    type CommitmentScheme;
}

pub struct ElGamalWithKzg<C, P> {
    _curve: PhantomData<C>,
    _polycommit: PhantomData<P>,
}
*/



/*
impl<C: Pairing, P: DenseUVPolynomial<C::ScalarField>> Prover for ElGamalWithKzg<C, P>
where
    <C::G1 as CurveGroup>::Affine: Neg<Output = <C::G1 as CurveGroup>::Affine>,
{
    type EncryptionEngine = ExponentialElGamal<C::G1>;
    type CommitmentScheme = KZG10<C, P>;
    type Proof = ElGamalWithKzgProof<C, P>;
}
*/
