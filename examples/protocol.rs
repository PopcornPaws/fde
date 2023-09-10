use ark_ec::pairing::Pairing;

// encryption engines
pub struct Generic;
pub struct ElGamal;
pub struct Paillier;

impl EncryptionEngine for Generic {
    type Output = Vec<u8>;
    fn encrypt(&self, data: &[u8]) -> Self::Output {
        Vec::new()
    }
}

pub trait EncryptionEngine {
    type Output;
    fn encrypt(&self, data: &[u8]) -> Self::Output;
}

// backend types
// pub struct Snark;
// pub struct Ipa;
// pub struct Kzg;

pub trait Backend {
    type Curve: Pairing;
    type EncryptionEngine: EncryptionEngine; // TODO bound by curve somehow?
    type Commitment; // TODO bound by curve somehow?
}

pub trait Server {
    type Fdx: Backend;
    fn commit(&self, data: &[u8]) -> Commitment;
    fn encrypt(&self, data: &[u8]) -> <<Self::Fdx as Backend>::EncryptionEngine as EncryptionEngine>::Output;
    fn adapt(&self, pre_sig: PreSignature) -> Signature;
}

pub trait Client {
    type DataSource: Server;
    fn check(
        commitment: Commitment,
        encryption: <<<Self::DataSource as Server>::Backend as Backend>::EncryptionEngine as EncryptionEngine>::Output,
    ) -> bool;
    fn pre_sign(&self, tx: Transaction, pk_s: PublicKey) -> PreSignature;
    fn extract(&self, signature: Signature, pre_sig: PreSignature, pk_s: PublicKey) -> SecretKey;
    fn decrypt(&self, sk_s: SecretKey) -> Vec<u8>;
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
