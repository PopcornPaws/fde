/*
use ark_crypto_primitives::signature::SignatureScheme;
use fdx::adaptor_sig::*;
use fdx::backend::*;
use fdx::encrypt::*;

type Transaction = ();

// backend types
// pub struct Snark;
// pub struct Ipa;
// pub struct Kzg;

pub trait Server {
    type Signature: AdaptorSignatureScheme;
    type Backend: Backend;

    fn commit(&self, data: &[u8]) -> <Self::Backend as Backend>::Commitment;

    fn encrypt(
        &self,
        data: &[u8],
    ) -> <<Self::Backend as Backend>::EncryptionEngine as EncryptionEngine>::Cipher;

    fn adapt(
        &self,
        pre_sig: <Self::Signature as AdaptorSignatureScheme>::PreSignature,
    ) -> <Self::Signature as SignatureScheme>::Signature;
}

pub trait Client {
    type Server: Server;
    fn check(
        commitment: <<Self::Server as Server>::Backend as Backend>::Commitment,
        encryption: <<<Self::Server as Server>::Backend as Backend>::EncryptionEngine as EncryptionEngine>::Cipher,
    ) -> bool;

    fn pre_sign(
        &self,
        tx: Transaction,
        adaptor_pubkey: <<Self::Server as Server>::Signature as SignatureScheme>::PublicKey,
    ) -> <<Self::Server as Server>::Signature as AdaptorSignatureScheme>::PreSignature;

    fn extract(
        &self,
        pre_signature: <<Self::Server as Server>::Signature as AdaptorSignatureScheme>::PreSignature,
        signature: <<Self::Server as Server>::Signature as SignatureScheme>::Signature,
        adaptor_pk: <<Self::Server as Server>::Signature as SignatureScheme>::PublicKey,
    ) -> <<Self::Server as Server>::Signature as SignatureScheme>::SecretKey;

    fn decrypt(
        &self,
        sk_s: <<<Self::Server as Server>::Backend as Backend>::EncryptionEngine as EncryptionEngine>::DecryptionKey,
    ) -> Vec<u8>;
}
*/

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

