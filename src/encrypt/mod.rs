pub mod elgamal;

use ark_std::rand::Rng;

// other possible encryption engines
//pub struct Generic;
//pub struct Paillier;

pub trait EncryptionEngine {
    type EncryptionKey;
    type DecryptionKey;
    type Cipher;
    type PlainText;
    fn encrypt<R: Rng>(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        rng: &mut R,
    ) -> Self::Cipher;
    fn decrypt(cipher: Self::Cipher, key: &Self::DecryptionKey) -> Self::PlainText;
}
