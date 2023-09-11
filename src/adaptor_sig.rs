use ark_crypto_primitives::signature::{schnorr::Schnorr, SignatureScheme};
use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use ark_std::marker::PhantomData;
use ark_std::ops::Mul;
use ark_std::rand::Rng;
use digest::Digest;

pub struct PreSchnorr<C: CurveGroup>(C::Affine);
pub struct AdaptedSchnorr<C: CurveGroup>(C::Affine);

pub trait AdaptorSignatureScheme {
    type PublicKey;
    type SecretKey;
    type PreSignature;
    type AdaptedSignature;

    fn keygen<R: Rng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error>;

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;

    fn adapt(
        signature: Self::PreSignature,
        signer_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error>;

    fn extract(
        signature: &Self::AdaptedSignature,
        pre_signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
    ) -> Result<Self::SecretKey, Error>;
}

impl<C: CurveGroup, D: Digest> AdaptorSignatureScheme for Schnorr<C, D> {
    type SecretKey = <Self as SignatureScheme>::SecretKey;
    type PublicKey = <Self as SignatureScheme>::PublicKey;
    type PreSignature = PreSignature<C>;
    type AdaptedSignature = AdaptedSignature<C>;

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        // Parameter could be the adaptor public key??
        let random_nonce = C::ScalarField::rand(rng);
        todo!();
    }

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {
        // TODO
        Ok(())
    }

    fn adapt(
        signature: Self::PreSignature,
        signer_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error> {
        // TODO
        Ok(AdaptedSignature {
            pre: signature.0,
            adapted: <C::Affine as AffineRepr>::generator(),
        })
    }

    fn extract(
        signature: &Self::AdaptedSignature,
        pre_signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
    ) -> Result<Self::SecretKey, Error> {
        Ok(SecretKey(C::ScalarField::zero()))
    }
}
