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

    pub fn update<P: CanonicalSerialize>(&mut self, point: &P) {
        point
            .serialize_compressed(&mut self.data)
            .expect("should not fail");
    }

    pub fn finalize(self) -> Output<D> {
        let mut hasher = D::new();
        hasher.update(self.data);
        hasher.finalize()
    }
}
