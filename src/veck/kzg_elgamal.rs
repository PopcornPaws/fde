use crate::commit::kzg::{Kzg, Powers};
use crate::dleq::Proof as DleqProof;
use crate::encrypt::elgamal::{Cipher, ExponentialElgamal as Elgamal, SplitScalar, MAX_BITS};
use crate::encrypt::EncryptionEngine;
use crate::hash::Hasher;
use crate::range_proof::RangeProof;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM as Msm};
use ark_ff::PrimeField;
use ark_poly::domain::general::GeneralEvaluationDomain;
use ark_poly::univariate::DensePolynomial;
use ark_poly::EvaluationDomain;
use ark_poly::Polynomial;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use digest::Digest;

pub struct PublicInput<const N: usize, C: Pairing, D: Clone + Digest> {
    pub ciphers: Vec<Cipher<C::G1>>,
    pub short_ciphers: Vec<[Cipher<C::G1>; N]>,
    pub range_proofs: Vec<[RangeProof<C, D>; N]>,
    pub random_encryption_points: Vec<C::G1Affine>,
}

impl<const N: usize, C: Pairing, D: Clone + Digest> PublicInput<N, C, D> {
    pub fn new<R: Rng>(
        evaluations: &[C::ScalarField],
        encryption_pk: &<Elgamal<C::G1> as EncryptionEngine>::EncryptionKey,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let mut random_encryption_points = Vec::with_capacity(evaluations.len());
        let mut ciphers = Vec::with_capacity(evaluations.len());
        let mut short_ciphers = Vec::with_capacity(evaluations.len());
        let mut range_proofs = Vec::with_capacity(evaluations.len());

        for eval in evaluations {
            let split_eval = SplitScalar::from(*eval);
            let rp = split_eval
                .splits()
                .map(|s| RangeProof::new(s, MAX_BITS, powers, rng).unwrap());
            let (sc, rand) = split_eval.encrypt::<Elgamal<C::G1>, _>(encryption_pk, rng);
            let cipher = <Elgamal<C::G1> as EncryptionEngine>::encrypt_with_randomness(
                eval,
                encryption_pk,
                &rand,
            );
            random_encryption_points.push((C::G1Affine::generator() * rand).into_affine());
            ciphers.push(cipher);
            short_ciphers.push(sc);
            range_proofs.push(rp);
        }

        Self {
            ciphers,
            short_ciphers,
            range_proofs,
            random_encryption_points,
        }
    }

    pub fn subset(&self, indices: &[usize]) -> Self {
        let size = indices.len();
        let mut ciphers = Vec::with_capacity(size);
        let mut short_ciphers = Vec::with_capacity(size);
        let mut random_encryption_points = Vec::with_capacity(size);
        let mut range_proofs = Vec::with_capacity(size);
        for &index in indices {
            ciphers.push(self.ciphers[index]);
            short_ciphers.push(self.short_ciphers[index]);
            random_encryption_points.push(self.random_encryption_points[index]);
            range_proofs.push(self.range_proofs[index].clone());
        }

        Self {
            ciphers,
            short_ciphers,
            range_proofs,
            random_encryption_points,
        }
    }
}

pub struct Proof<const N: usize, C: Pairing, D> {
    challenge_eval_commitment: C::G1Affine,
    challenge_opening_proof: C::G1Affine,
    dleq_proof: DleqProof<C::G1, D>,
    com_f_q_poly: C::G1Affine,
    _poly: PhantomData<DensePolynomial<C::ScalarField>>,
    _digest: PhantomData<D>,
}

impl<const N: usize, C, D> Proof<N, C, D>
where
    C: Pairing,
    D: Digest + Clone,
{
    pub fn new<R: Rng>(
        f_poly: &DensePolynomial<C::ScalarField>,
        f_s_poly: &DensePolynomial<C::ScalarField>,
        encryption_sk: &C::ScalarField,
        input: &PublicInput<N, C, D>,
        powers: &Powers<C>,
        rng: &mut R,
    ) -> Self {
        let mut hasher = Hasher::<D>::new();
        input
            .ciphers
            .iter()
            .for_each(|cipher| hasher.update(&cipher.c1()));

        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(input.ciphers.len())
            .expect("valid domain");

        // challenge and KZG proof
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());
        let challenge_eval = f_s_poly.evaluate(&challenge);
        let challenge_opening_proof = Kzg::proof(f_s_poly, challenge, challenge_eval, powers);
        let challenge_eval_commitment = (C::G1Affine::generator() * challenge_eval).into_affine();

        // subset polynomial KZG commitment
        let f_q_poly = (f_poly - f_s_poly)
            .divide_by_vanishing_poly(domain)
            .unwrap()
            .0;
        let com_f_q_poly = powers.commit_g1(&f_q_poly).into();

        // DLEQ proof
        let lagrange_evaluations = &domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 =
            Msm::msm_unchecked(&input.random_encryption_points, lagrange_evaluations);

        let dleq_proof = DleqProof::new(
            encryption_sk,
            q_point.into_affine(),
            C::G1Affine::generator(),
            rng,
        );

        Self {
            challenge_eval_commitment,
            challenge_opening_proof,
            dleq_proof,
            com_f_q_poly,
            _poly: PhantomData,
            _digest: PhantomData,
        }
    }

    pub fn verify(
        &self,
        com_f_poly: C::G1,
        com_f_s_poly: C::G1,
        encryption_pk: C::G1Affine,
        input: &PublicInput<N, C, D>,
        powers: &Powers<C>,
    ) -> bool {
        let mut hasher = Hasher::<D>::new();
        let c1_points: Vec<C::G1Affine> = input
            .ciphers
            .iter()
            .map(|cipher| {
                let c1 = cipher.c1();
                hasher.update(&c1);
                c1
            })
            .collect();
        let challenge = C::ScalarField::from_le_bytes_mod_order(&hasher.finalize());
        let domain = GeneralEvaluationDomain::<C::ScalarField>::new(input.ciphers.len())
            .expect("valid domain");

        // polynomial division check via vanishing polynomial
        let vanishing_poly = DensePolynomial::from(domain.vanishing_polynomial());
        let com_vanishing_poly = powers.commit_g2(&vanishing_poly);
        let subset_pairing_check = Kzg::<C>::pairing_check(
            com_f_poly - com_f_s_poly,
            self.com_f_q_poly.into_group(),
            com_vanishing_poly,
        );

        // DLEQ check
        let lagrange_evaluations = &domain.evaluate_all_lagrange_coefficients(challenge);
        let q_point: C::G1 =
            Msm::msm_unchecked(&input.random_encryption_points, lagrange_evaluations); // Q
        let ct_point: C::G1 = Msm::msm_unchecked(&c1_points, lagrange_evaluations); // C_t

        let q_star = ct_point - self.challenge_eval_commitment; // Q* = C_t / C_alpha
        let dleq_check = self.dleq_proof.verify(
            q_point.into(),
            q_star,
            C::G1Affine::generator(),
            encryption_pk.into(),
        );

        // KZG pairing check
        let point = C::G2Affine::generator() * challenge;
        let kzg_check = Kzg::verify(
            self.challenge_opening_proof,
            com_f_s_poly.into(),
            point,
            self.challenge_eval_commitment.into_group(),
            powers,
        );

        dleq_check && kzg_check && subset_pairing_check
    }
}

#[cfg(test)]
mod test {
    use crate::commit::kzg::Powers;
    use crate::encrypt::elgamal::MAX_BITS;
    use crate::tests::{BlsCurve, KzgElgamalProof, PublicInput, Scalar, UniPoly};
    use ark_ec::pairing::Pairing;
    use ark_ec::{CurveGroup, Group};
    use ark_poly::{EvaluationDomain, Evaluations, GeneralEvaluationDomain};
    use ark_std::collections::HashMap;
    use ark_std::{test_rng, UniformRand};

    const DATA_SIZE: usize = 16;
    const SUBSET_SIZE: usize = 8;

    #[test]
    fn flow() {
        // KZG setup simulation
        let rng = &mut test_rng();
        let tau = Scalar::rand(rng); // "secret" tau
        let powers = Powers::<BlsCurve>::unsafe_setup(tau, (DATA_SIZE + 1).max(MAX_BITS * 4)); // generate powers of tau size DATA_SIZE

        // Server's (elphemeral?) encryption key for this session
        let encryption_sk = Scalar::rand(rng);
        let encryption_pk = (<BlsCurve as Pairing>::G1::generator() * encryption_sk).into_affine();

        // Generate random data and public inputs (encrypted data, etc)
        let data: Vec<Scalar> = (0..DATA_SIZE).map(|_| Scalar::rand(rng)).collect();
        let input = PublicInput::new(&data, &encryption_pk, &powers, rng);

        input
            .range_proofs
            .iter()
            .for_each(|rps| assert!(rps.iter().all(|rp| rp.verify(MAX_BITS, &powers).is_ok())));

        let domain = GeneralEvaluationDomain::new(data.len()).expect("valid domain");

        let index_map: HashMap<Scalar, usize> =
            domain.elements().enumerate().map(|(i, e)| (e, i)).collect();

        // Interpolate original polynomial and compute its KZG commitment.
        // This is performed only once by the server
        let evaluations = Evaluations::from_vec_and_domain(data, domain);
        let f_poly: UniPoly = evaluations.interpolate_by_ref();
        let com_f_poly = powers.commit_g1(&f_poly);

        // get subdomain with size suitable for interpolating a polynomial with SUBSET_SIZE
        // coefficients
        let sub_domain = GeneralEvaluationDomain::new(SUBSET_SIZE).unwrap();
        let sub_indices = sub_domain
            .elements()
            .map(|elem| *index_map.get(&elem).unwrap())
            .collect::<Vec<usize>>();
        let sub_data = sub_indices
            .iter()
            .map(|&i| evaluations.evals[i])
            .collect::<Vec<Scalar>>();
        let sub_evaluations = Evaluations::from_vec_and_domain(sub_data, sub_domain);
        let f_s_poly: UniPoly = sub_evaluations.interpolate_by_ref();
        let com_f_s_poly = powers.commit_g1(&f_s_poly);

        let sub_input = input.subset(&sub_indices);
        sub_input
            .range_proofs
            .iter()
            .for_each(|rps| assert!(rps.iter().all(|rp| rp.verify(MAX_BITS, &powers).is_ok())));

        let proof =
            KzgElgamalProof::new(&f_poly, &f_s_poly, &encryption_sk, &sub_input, &powers, rng);
        assert!(proof.verify(com_f_poly, com_f_s_poly, encryption_pk, &sub_input, &powers));

        for (cipher, short_cipher) in sub_input.ciphers.iter().zip(&sub_input.short_ciphers) {
            assert!(cipher.check_encrypted_sum(short_cipher));
        }
    }
}
