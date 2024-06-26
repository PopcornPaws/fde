pub mod elgamal;

use ark_std::rand::Rng;

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
    fn encrypt_with_randomness(
        data: &Self::PlainText,
        key: &Self::EncryptionKey,
        randomness: &Self::PlainText,
    ) -> Self::Cipher;
    fn decrypt(cipher: Self::Cipher, key: &Self::DecryptionKey) -> Self::PlainText;
}
