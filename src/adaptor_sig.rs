use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use ark_std::marker::PhantomData;
use ark_std::ops::Mul;
use ark_std::rand::Rng;

pub struct SecretKey<C: CurveGroup>(C::ScalarField);
pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub struct Parameters<C: CurveGroup> {
    adaptor_pubkey: PublicKey<C>,
}

pub struct PreSignature<C: CurveGroup>(C::Affine);
pub struct AdaptedSignature<C: CurveGroup> {
    pre: C::Affine,
    adapted: C::Affine,
}

pub trait AdaptorSignatureScheme {
    type Parameters;
    type PublicKey;
    type SecretKey;
    type AdaptedSignature;

    fn keygen<R: Rng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), Error>;

    fn pre_sign<R: Rng>(
        parameters: &Self::Parameters,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error>
    where
        Self: Sized;

    fn verify(
        &self,
        prameters: &Self::Parameters,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error>;

    fn adapt(
        self,
        signer_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error>;
}

impl<C: CurveGroup> AdaptorSignatureScheme for PreSignature<C> {
    type Parameters = Parameters<C>;
    type SecretKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;
    type AdaptedSignature = AdaptedSignature<C>;

    fn keygen<R: Rng>(rng: &mut R) -> Result<(Self::PublicKey, Self::SecretKey), Error> {
        let secret_key = C::ScalarField::rand(rng);
        let public_key = <C::Affine as AffineRepr>::generator()
            .mul(secret_key)
            .into();
        Ok((public_key, SecretKey(secret_key)))
    }

    fn pre_sign<R: Rng>(
        parameters: &Self::Parameters,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self, Error> {
        // TODO
        Ok(PreSignature(C::rand(rng).into()))
    }

    fn verify(
        &self,
        parameters: &Self::Parameters,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {
        // TODO
        Ok(())
    }

    fn adapt(
        self,
        signer_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error> {
        // TODO
        Ok(AdaptedSignature {
            pre: self.0,
            adapted: <C::Affine as AffineRepr>::generator(),
        })
    }
}

impl<C: CurveGroup> AdaptedSignature<C> {
    pub fn extract(&self, adaptor_pk: PublicKey<C>) -> SecretKey<C> {
        // TODO
        SecretKey(C::ScalarField::zero())
    }
}
