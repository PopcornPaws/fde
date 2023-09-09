pub trait Server {
    type Curve; // pairing friendly curve - bound by traits
    type EncrypionEngine; // Type of encryption - bound by traits
    fn data(&self) -> &[u8];
    fn commit<C>(&self) -> C; // commitment (generic - should be bounded by Self::...)
    fn encrypt<E>(&self) -> E; // encryption (generic - should be bounded by Self::...)
    fn adapt(&self, pre_sig: PreSignature) -> Signature;
}
fn main() {
}
