use ark_crypto_primitives::signature::schnorr::{Schnorr, SecretKey};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::ops::Neg;
use ark_std::rand::Rng;
use digest::Digest;

pub struct PreSchnorr<C: CurveGroup>(C::ScalarField, C::Affine);
pub struct AdaptedSchnorr<C: CurveGroup>(C::ScalarField, C::Affine);

pub trait AdaptorSignatureScheme {
    type PublicKey;
    type SecretKey;
    type PreSignature;
    type AdaptedSignature;

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
        signature: &Self::PreSignature,
        signer_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error>;

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
        adaptor_pk: &Self::PublicKey,
    ) -> Result<Self::SecretKey, Error>;
}

impl<C: CurveGroup, D: Digest + Send + Sync> AdaptorSignatureScheme for Schnorr<C, D>
where
    <C as CurveGroup>::Affine: Neg<Output = <C as CurveGroup>::Affine>,
{
    type SecretKey = <Self as SignatureScheme>::SecretKey;
    type PublicKey = <Self as SignatureScheme>::PublicKey;
    type PreSignature = PreSchnorr<C>;
    type AdaptedSignature = AdaptedSchnorr<C>;

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error> {
        let signer_pk = (<C::Affine as AffineRepr>::generator() * signer_sk.0).into_affine();
        let (random_nonce, challenge, commitment) = loop {
            // r
            let random_nonce = C::ScalarField::rand(rng);
            // R_hat = r * G + Y
            // TODO is commitment allowed to be zero?
            let commitment =
                (<C::Affine as AffineRepr>::generator() * random_nonce + adaptor_pk).into_affine();
            let mut hash_input = Vec::new();
            commitment.serialize_compressed(&mut hash_input)?;
            signer_pk.serialize_compressed(&mut hash_input)?;
            message.serialize_compressed(&mut hash_input)?;

            if let Some(challenge) = C::ScalarField::from_random_bytes(&D::digest(&hash_input)) {
                break (random_nonce, challenge, commitment);
            }
        };

        Ok(PreSchnorr(
            random_nonce + challenge * signer_sk.0,
            commitment,
        ))
    }

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {
        let &PreSchnorr(s_scalar, commitment) = signature;

        let mut hash_input = Vec::new();
        commitment.serialize_compressed(&mut hash_input)?;
        signer_pk.serialize_compressed(&mut hash_input)?;
        message.serialize_compressed(&mut hash_input)?;

        let challenge = C::ScalarField::from_random_bytes(&D::digest(&hash_input))
            .ok_or::<Error>("invalid challenge".into())?;

        let s_point = <C::Affine as AffineRepr>::generator() * s_scalar;
        let r_point = commitment + adaptor_pk.neg();

        if s_point != r_point + *signer_pk * challenge {
            Err("verification failure".into())
        } else {
            Ok(())
        }
    }

    fn adapt(
        signature: &Self::PreSignature,
        signer_pk: &Self::PublicKey,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::AdaptedSignature, Error> {
        let &PreSchnorr(s_scalar, commitment) = signature;
        Ok(AdaptedSchnorr(s_scalar + adaptor_sk.0, commitment))
    }

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::AdaptedSignature,
        adaptor_pk: &Self::PublicKey,
    ) -> Result<Self::SecretKey, Error> {
        let &PreSchnorr(s_scalar, pre_commitment) = pre_signature;
        let &AdaptedSchnorr(s_scalar_hat, commitment) = signature;
        if pre_commitment != commitment {
            Err("commitment mismatch".into())
        } else {
            Ok(SecretKey(s_scalar_hat - s_scalar))
        }
    }
}
