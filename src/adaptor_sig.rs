use ark_crypto_primitives::signature::schnorr::{Schnorr, SecretKey, Signature};
use ark_crypto_primitives::signature::SignatureScheme;
use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::Rng;
use ark_std::UniformRand;
use digest::Digest;

pub trait AdaptorSignatureScheme: SignatureScheme {
    type PreSignature;

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
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::Signature, Error>;

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::Signature,
        adaptor_pk: &Self::PublicKey,
    ) -> Result<Self::SecretKey, Error>;
}

impl<C: CurveGroup, D: Digest + Send + Sync> AdaptorSignatureScheme for Schnorr<C, D> {
    type PreSignature = Signature<C>;
    fn pre_sign<R: Rng>(
        adaptor_pk: &Self::PublicKey,
        signer_sk: &Self::SecretKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::PreSignature, Error> {
        let signer_pk = (<C::Affine as AffineRepr>::generator() * signer_sk.0).into_affine();
        // random nonce (r) sampled uniformly
        let random_nonce = C::ScalarField::rand(rng);
        // commitment is shifted by the adaptor's pubkey
        // R_hat = r * G + Y
        let commitment =
            (<C::Affine as AffineRepr>::generator() * random_nonce + adaptor_pk).into_affine();
        // compute challenge from public values (R_hat, X, m)
        let verifier_challenge = hash_challenge::<C, D>(&commitment, &signer_pk, message)?;
        // s_hat = r - cx
        let prover_response = random_nonce - verifier_challenge * signer_sk.0;

        Ok(Signature {
            prover_response,
            verifier_challenge,
        })
    }

    fn verify(
        signature: &Self::PreSignature,
        adaptor_pk: &Self::PublicKey,
        signer_pk: &Self::PublicKey,
        message: &[u8],
    ) -> Result<(), Error> {
        let &Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        // s_hat * G + c * X + Y
        let commitment = <C::Affine as AffineRepr>::generator() * prover_response
            + *signer_pk * verifier_challenge
            + adaptor_pk;
        // compute challenge
        let challenge = hash_challenge::<C, D>(&commitment.into_affine(), signer_pk, message)?;
        if challenge != verifier_challenge {
            Err("verification failure".into())
        } else {
            Ok(())
        }
    }

    fn adapt(
        signature: &Self::PreSignature,
        adaptor_sk: &Self::SecretKey,
    ) -> Result<Self::Signature, Error> {
        let &Signature {
            prover_response,
            verifier_challenge,
        } = signature;
        Ok(Signature {
            prover_response: prover_response + adaptor_sk.0,
            verifier_challenge,
        })
    }

    fn extract(
        pre_signature: &Self::PreSignature,
        signature: &Self::Signature,
        adaptor_pk: &Self::PublicKey,
    ) -> Result<Self::SecretKey, Error> {
        let &Signature {
            prover_response: pre_prover_response,
            ..
        } = pre_signature;
        let &Signature {
            prover_response, ..
        } = signature;
        let sk = prover_response - pre_prover_response;
        let pk = (<C::Affine as AffineRepr>::generator() * sk).into_affine();
        if pk != *adaptor_pk {
            Err("invalid signatures".into())
        } else {
            Ok(SecretKey(sk))
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
    use ark_secp256k1::Projective as Secp256k1;
    use sha3::Keccak256;

    type Scheme = Schnorr<Secp256k1, Keccak256>;

    fn keygen<R: Rng>(
        rng: &mut R,
    ) -> (
        <Scheme as SignatureScheme>::PublicKey,
        <Scheme as SignatureScheme>::SecretKey,
    ) {
        let mut parameters = Scheme::setup(rng).unwrap();
        parameters.generator = Secp256k1::generator().into_affine();
        Scheme::keygen(&parameters, rng).unwrap()
    }

    #[test]
    fn completeness() {
        // setup and keygen
        let rng = &mut test_rng();
        let (signer_pk, signer_sk) = keygen(rng);
        let (adaptor_pk, adaptor_sk) = keygen(rng);

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
        let adapted_sig = Scheme::adapt(&pre_sig, &adaptor_sk).unwrap();

        // s + y
        let commitment = Secp256k1::generator() * adapted_sig.prover_response
            + signer_pk * adapted_sig.verifier_challenge;

        let challenge =
            hash_challenge::<Secp256k1, Keccak256>(&commitment.into_affine(), &signer_pk, message)
                .unwrap();

        assert_eq!(challenge, adapted_sig.verifier_challenge);

        // extract adaptor secret key
        let extracted_sk = Scheme::extract(&pre_sig, &adapted_sig, &adaptor_pk).unwrap();
        assert_eq!(extracted_sk.0, adaptor_sk.0);
    }

    #[test]
    fn soundness() {
        // setup and keygen
        let rng = &mut test_rng();
        let (signer_pk, signer_sk) = keygen(rng);
        let (adaptor_pk, _adaptor_sk) = keygen(rng);

        let message = b"hello adaptor signature";

        // pre-signature generation (with invalid adaptor pubkey)
        let pre_sig = Scheme::pre_sign(&signer_pk, &signer_sk, message, rng).unwrap();
        assert!(<Scheme as AdaptorSignatureScheme>::verify(
            &pre_sig,
            &adaptor_pk,
            &signer_pk,
            message
        )
        .is_err());

        // pre-signature generation (with invalid message pubkey)
        let pre_sig = Scheme::pre_sign(&adaptor_pk, &signer_sk, b"invalid", rng).unwrap();
        assert!(<Scheme as AdaptorSignatureScheme>::verify(
            &pre_sig,
            &adaptor_pk,
            &signer_pk,
            message
        )
        .is_err());

        // valid pre-signature
        let pre_sig = Scheme::pre_sign(&adaptor_pk, &signer_sk, message, rng).unwrap();
        assert!(<Scheme as AdaptorSignatureScheme>::verify(
            &pre_sig,
            &adaptor_pk,
            &signer_pk,
            message
        )
        .is_ok());

        // adapt with invalid secret key
        let adapted_sig = Scheme::adapt(&pre_sig, &signer_sk).unwrap();
        // signature will be invalid, thus it will be rejected when checked by a 3rd party
        // s + y
        let commitment = Secp256k1::generator() * adapted_sig.prover_response
            + signer_pk * adapted_sig.verifier_challenge;

        let challenge =
            hash_challenge::<Secp256k1, Keccak256>(&commitment.into_affine(), &signer_pk, message)
                .unwrap();

        assert_ne!(challenge, adapted_sig.verifier_challenge);

        // extract invalid adaptor secret key
        assert!(Scheme::extract(&pre_sig, &adapted_sig, &adaptor_pk).is_err());
    }
}
