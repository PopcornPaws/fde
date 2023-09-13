use ark_crypto_primitives::signature::schnorr::{Schnorr, SecretKey};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::ops::{Neg, Sub};
use ark_std::rand::Rng;
use digest::Digest;

pub struct PreSchnorr<C: CurveGroup>(C::ScalarField, C::Affine);
pub struct AdaptedSchnorr<C: CurveGroup>(C::ScalarField, C::Affine);

pub trait AdaptorSignatureScheme {
    type PublicKey;
    type SecretKey;
    type PreSignature;
    type AdaptedSignature;

    fn keygen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey);

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

    fn keygen<R: Rng>(rng: &mut R) -> (Self::PublicKey, Self::SecretKey) {
        let sk = C::ScalarField::rand(rng);
        let pk = (<C::Affine as AffineRepr>::generator() * sk).into_affine();
        (pk, SecretKey(sk))
    }

    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error> {
        let signer_pk = (<C::Affine as AffineRepr>::generator() * signer_sk.0).into_affine();
        // r
        let random_nonce = C::ScalarField::rand(rng);
        // R_hat = r * G + Y
        // TODO is commitment allowed to be zero?
        let commitment =
            (<C::Affine as AffineRepr>::generator() * random_nonce + adaptor_pk).into_affine();
        let challenge = hash_challenge::<C, D>(&commitment, &signer_pk, message)?;

        commitment + adaptor_pk.neg() + *adaptor_pk * challenge;

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

        let challenge = hash_challenge::<C, D>(&commitment, signer_pk, message)?;

        let s_point = <C::Affine as AffineRepr>::generator() * s_scalar;
        // R_hat - Y
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

fn hash_challenge<C: CurveGroup, D: Digest>(
    commitment: &C::Affine,
    signer_pk: &C::Affine,
    message: &[u8],
) -> Result<C::ScalarField, Error> {
    let mut hash_input = Vec::new();
    commitment.serialize_compressed(&mut hash_input)?;
    signer_pk.serialize_compressed(&mut hash_input)?;
    message.serialize_compressed(&mut hash_input)?;

    C::ScalarField::from_random_bytes(&D::digest(&hash_input))
        .ok_or::<Error>("invalid challenge".into())
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::Group;
    use ark_std::test_rng;
    use secp256k1::Projective as Secp256k1;
    use sha3::Keccak256;

    type Scheme = Schnorr<Secp256k1, Keccak256>;

    #[test]
    fn completeness() {
        // setup and keygen
        let rng = &mut test_rng();
        let (signer_pk, signer_sk) = <Scheme as AdaptorSignatureScheme>::keygen(rng);
        let (adaptor_pk, adaptor_sk) = <Scheme as AdaptorSignatureScheme>::keygen(rng);

        // pre-signature generation
        let message = b"hello adaptor signature";
        let pre_sig = Scheme::pre_sign(&adaptor_pk, &signer_sk, message, rng).unwrap();
        // verify pre-signature
        assert!(<Scheme as AdaptorSignatureScheme>::verify(
            &pre_sig,
            &adaptor_pk,
            &signer_pk,
            message
        )
        .is_ok());

        // adapt and verify signature
        let adapted_sig = Scheme::adapt(&pre_sig, &signer_pk, &adaptor_sk).unwrap();

        let challenge =
            hash_challenge::<Secp256k1, Keccak256>(&adapted_sig.1, &signer_pk, message).unwrap();
        assert_eq!(
            (Secp256k1::generator() * adapted_sig.0).into_affine(),
            (adapted_sig.1 + signer_pk * challenge).into_affine()
        );

        // extract adaptor secret key
        let extracted_sk = Scheme::extract(&pre_sig, &adapted_sig, &adaptor_pk).unwrap();
        assert_eq!(extracted_sk.0, adaptor_sk.0);
    }

    #[test]
    fn soundness() {
        // setup and keygen
        let rng = &mut test_rng();
        let (signer_pk, signer_sk) = <Scheme as AdaptorSignatureScheme>::keygen(rng);
        let (adaptor_pk, adaptor_sk) = <Scheme as AdaptorSignatureScheme>::keygen(rng);

        let message = b"hello adaptor signature";
        // pre-signature generation (with invalid adaptor pubkey)
        let pre_sig = Scheme::pre_sign(&adaptor_pk.neg(), &signer_sk, message, rng).unwrap();
        // verify pre-signature
        assert!(<Scheme as AdaptorSignatureScheme>::verify(
            &pre_sig,
            &adaptor_pk,
            &signer_pk,
            message
        )
        .is_err());

        // pre-signature generation (with invalid message pubkey)
        let pre_sig = Scheme::pre_sign(&adaptor_pk.neg(), &signer_sk, b"invalid", rng).unwrap();
        // verify pre-signature
        assert!(<Scheme as AdaptorSignatureScheme>::verify(
            &pre_sig,
            &adaptor_pk,
            &signer_pk,
            message
        )
        .is_err());
    }
}
