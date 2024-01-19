use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use ark_std::marker::PhantomData;
use digest::{Digest, Output};

#[derive(Clone, Debug)]
pub struct Hasher<D> {
    data: Vec<u8>,
    _digest: PhantomData<D>,
}

impl<D> Default for Hasher<D> {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            _digest: PhantomData,
        }
    }
}

impl<D: Digest> Hasher<D> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update<T: CanonicalSerialize>(&mut self, input: &T) {
        input
            .serialize_compressed(&mut self.data)
            .expect("should not fail");
    }

    pub fn finalize(self) -> Output<D> {
        D::digest(self.data)
    }

    pub fn next_scalar<S: PrimeField>(&mut self, label: &[u8]) -> S {
        self.data.extend_from_slice(label);
        let output = D::digest(&self.data);
        S::from_le_bytes_mod_order(&output)
    }
}
