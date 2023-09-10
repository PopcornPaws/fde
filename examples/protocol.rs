use ark_ec::pairing::Pairing;

// TODO
type PublicKey = ();
type SecretKey = ();
type Transaction = ();

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
    fn commit(&self, data: &[u8]) -> <Self::Fdx as Backend>::Commitment;
    fn encrypt(
        &self,
        data: &[u8],
    ) -> <<Self::Fdx as Backend>::EncryptionEngine as EncryptionEngine>::Output;
    fn adapt(&self, pre_sig: AdaptorSignature<Pre>) -> AdaptorSignature<Adapted>;
}

pub struct AdaptorSignature<T>(T);

impl AdaptorSignature<Pre> {
    pub fn new(sk: SecretKey, message: &[u8], rel_pub: Vec<u8>) -> Self {
        Self(Pre(Vec::new()))
    }

    pub fn verify(&self, pk: PublicKey, message: &[u8], rel_pub: Vec<u8>) -> bool {
        true
    }

    pub fn adapt(self, pk: PublicKey, rel_priv: Vec<u8>) -> AdaptorSignature<Adapted> {
        AdaptorSignature(Adapted {
            pre: self.0 .0,
            adapted: Vec::new(),
        })
    }
}

impl AdaptorSignature<Adapted> {
    pub fn extract(&self, rel_pub: Vec<u8>) -> Vec<u8> {
        Vec::new() // rel_priv
    }
}

pub struct Pre(Vec<u8>);
pub struct Adapted {
    pre: Vec<u8>,
    adapted: Vec<u8>,
}

pub trait Client {
    type DataSource: Server;
    fn check(
        commitment: <<Self::DataSource as Server>::Fdx as Backend>::Commitment,
        encryption: <<<Self::DataSource as Server>::Fdx as Backend>::EncryptionEngine as EncryptionEngine>::Output,
    ) -> bool;
    fn pre_sign(&self, tx: Transaction, pk_s: PublicKey) -> AdaptorSignature<Pre>;
    fn extract(&self, signature: AdaptorSignature<Adapted>, pk_s: PublicKey) -> SecretKey;
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
