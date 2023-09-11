use ark_ec::pairing::Pairing;
use fdx::adaptor_sig::*;

type Transaction = ();

// encryption engines
pub struct Generic;
pub struct ElGamal;
pub struct Paillier;

impl EncryptionEngine for Generic {
    type EncryptionKey = ();
    type DecryptionKey = ();
    type PlainText = Vec<u8>;
    type CipherText = Vec<u8>;
    fn encrypt(data: &Self::PlainText, key: &Self::EncryptionKey) -> Self::CipherText {
        Vec::new()
    }
    fn decrypt(cipher: Self::CipherText, key: &Self::DecryptionKey) -> Vec<u8> {
        Vec::new()
    }
}

pub trait EncryptionEngine {
    type EncryptionKey;
    type DecryptionKey;
    type CipherText;
    type PlainText;
    fn encrypt(data: &Self::PlainText, key: &Self::EncryptionKey) -> Self::CipherText;
    fn decrypt(cipher: Self::CipherText, key: &Self::DecryptionKey) -> Vec<u8>;
}

// backend types
// pub struct Snark;
// pub struct Ipa;
// pub struct Kzg;

pub trait Backend {
    type Signature: AdaptorSignatureScheme;
    type EncryptionEngine: EncryptionEngine; // TODO bound by curve somehow?
    type Commitment; // TODO bound by curve somehow?
}

pub trait Server {
    type Backend: Backend;

    fn commit(&self, data: &[u8]) -> <Self::Backend as Backend>::Commitment;

    fn encrypt(
        &self,
        data: &[u8],
    ) -> <<Self::Backend as Backend>::EncryptionEngine as EncryptionEngine>::CipherText;

    fn adapt(
        &self,
        pre_sig: <Self::Backend as Backend>::Signature,
    ) -> <<Self::Backend as Backend>::Signature as AdaptorSignatureScheme>::AdaptedSignature;
}

pub trait Client {
    type Server: Server;
    fn check(
        commitment: <<Self::Server as Server>::Backend as Backend>::Commitment,
        encryption: <<<Self::Server as Server>::Backend as Backend>::EncryptionEngine as EncryptionEngine>::CipherText,
    ) -> bool;

    fn pre_sign(
        &self,
        tx: Transaction,
        adaptor_pubkey: <<<Self::Server as Server>::Backend as Backend>::Signature as AdaptorSignatureScheme>::PublicKey,
    ) -> <<Self::Server as Server>::Backend as Backend>::Signature;

    fn extract(
        &self,
        signature: <<<Self::Server as Server>::Backend as Backend>::Signature as AdaptorSignatureScheme>::AdaptedSignature,
        adaptor_pk: <<<Self::Server as Server>::Backend as Backend>::Signature as AdaptorSignatureScheme>::PublicKey,
    ) -> <<<Self::Server as Server>::Backend as Backend>::Signature as AdaptorSignatureScheme>::SecretKey;

    fn decrypt(
        &self,
        sk_s: <<<Self::Server as Server>::Backend as Backend>::EncryptionEngine as EncryptionEngine>::DecryptionKey,
    ) -> Vec<u8>;
}

fn main() {
    /* SERVER
     *
     * new(data, sk_s)
     * commit(data)
     * encrypt(data, sk_s)
     * adapt(pre_signature, sk_s)
     *
     */

    /* CLIENT
     *
     * new(secret_key) -> Self
     * check(commitment, encryption) -> bool
     * pre_sign(sk_c, transaction, pk_s) -> PreSignature
     * extract(signature, pre_signature, pk_s) -> SecretKey
     * decrypt(sk_s, encryption) -> Vec<u8>
     *
     */
}
