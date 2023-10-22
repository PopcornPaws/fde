use crate::commit::kzg::Powers;
use crate::dleq::Proof as DleqProof;
use ark_ec::pairing::Pairing;
use ark_std::marker::PhantomData;
use ark_std::ops::Range;
use ark_std::rand::Rng;
use digest::Digest;

pub struct Proof<C: Pairing, P, D> {
    commitment_alpha: C::G1Affine,
    proof_alpha: C::G1Affine,
    dleq_proof: DleqProof<C::G1, D>,
    _poly: PhantomData<P>,
    _digest: PhantomData<D>,
}

impl<C: Pairing, P, D> Proof<C, P, D> {
    pub fn new<R: Rng>(
        f_poly: &P,
        index_range: Range<usize>,
        kzg: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        todo!()
    }

    pub fn verify(&self) -> bool {
        todo!()
    }
}
