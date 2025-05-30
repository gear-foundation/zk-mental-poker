use crate::services::EdwardsProjective;
use crate::services::{
    EncryptedCard, PublicKey,
    curve::{compare_points, compare_projective_and_coords, compare_public_keys},
};
use ark_ed_on_bls12_381_bandersnatch::Fq;
use ark_ff::{One, PrimeField};
use core::ops::AddAssign;
use gbuiltin_bls381::{
    Request, Response,
    ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective as G1, G2Affine},
    ark_ec::{AffineRepr, Group, pairing::Pairing},
    ark_ff::Field,
    ark_scale,
    ark_scale::hazmat::ArkScaleProjective,
    ark_serialize::CanonicalDeserialize,
};
use gstd::{ActorId, Encode, ext, msg, prelude::*};

// ================================================================================================
// Type Aliases & Constants
// ================================================================================================

type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;
type Gt = <Bls12_381 as Pairing>::TargetField;

/// Card deck configuration constants
#[derive(Debug, Clone, Copy)]
pub struct DeckConfig {
    pub num_cards: usize,
    pub num_coords: usize, // Coordinates per encrypted card point (X, Y, Z for both c0 and c1)
    pub pk_size: usize,    // Public key components count
}

impl DeckConfig {
    pub const STANDARD: Self = Self {
        num_cards: 52,
        num_coords: 6, // c0.X, c0.Y, c0.Z, c1.X, c1.Y, c1.Z
        pk_size: 3,    // x, y, z coordinates
    };

    #[inline]
    pub const fn expected_input_length(&self) -> usize {
        1 + self.pk_size + (self.num_coords * self.num_cards * 2) // valid + pk + original + permuted
    }
}

// ================================================================================================
// Core Data Structures
// ================================================================================================

/// Serialized verifying key for zk-SNARK verification
#[derive(Debug, Default, Clone, Encode, Decode, TypeInfo)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = scale_info)]
pub struct VerifyingKeyBytes {
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
    pub ic: Vec<Vec<u8>>,
}

/// Deserialized verifying key with curve points
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1_beta_g2: ArkScale<Gt>,
    pub gamma_g2_neg_pc: G2Affine,
    pub delta_g2_neg_pc: G2Affine,
    pub ic: Vec<G1Affine>,
}

/// Serialized zk-SNARK proof components
#[derive(Debug, Clone, Encode, Decode, TypeInfo)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = scale_info)]
pub struct ProofBytes {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}

/// Complete verification instance containing proof and public inputs
#[derive(Debug, Clone, Encode, Decode, TypeInfo)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = scale_info)]
pub struct VerificationVariables {
    pub proof_bytes: ProofBytes,
    pub public_input: Vec<Vec<u8>>,
}

/// Parsed public input containing original deck, permuted deck, and public key
#[derive(Debug, Clone)]
pub struct ParsedPublicInput {
    pub original_deck: Vec<EncryptedCard>,
    pub permuted_deck: Vec<EncryptedCard>,
    pub public_key: PublicKey,
}

/// Batch verification context for managing multiple proof verifications
#[derive(Debug)]
pub struct BatchVerificationContext {
    pub verifying_key: VerifyingKey,
    pub builtin_address: ActorId,
}

// ================================================================================================
// Core Implementation
// ================================================================================================

impl VerifyingKey {
    /// Creates a new verifying key from serialized bytes
    pub fn from_bytes(vk_bytes: &VerifyingKeyBytes) -> Self {
        Self {
            delta_g2_neg_pc: CurvePointDeserializer::deserialize_g2(&vk_bytes.delta_g2_neg_pc),
            gamma_g2_neg_pc: CurvePointDeserializer::deserialize_g2(&vk_bytes.gamma_g2_neg_pc),
            alpha_g1_beta_g2: ArkScale::decode(&mut &*vk_bytes.alpha_g1_beta_g2)
                .expect("Deserialization failed: alpha_g1_beta_g2"),
            ic: vk_bytes
                .ic
                .iter()
                .map(|bytes| CurvePointDeserializer::deserialize_g1(bytes))
                .collect(),
        }
    }
}

impl BatchVerificationContext {
    /// Creates a new batch verification context
    pub fn new(vk_bytes: &VerifyingKeyBytes, builtin_address: ActorId) -> Self {
        BatchVerificationContext {
            verifying_key: VerifyingKey::from_bytes(vk_bytes),
            builtin_address,
        }
    }

    /// Performs batch verification of multiple zk-SNARK proofs
    pub async fn verify_batch(&self, instances: Vec<VerificationVariables>) {
        let proof_points = self.prepare_proof_points(instances).await;
        let is_valid = self.execute_pairing_check(&proof_points).await;

        if !is_valid {
            ext::panic("Batch verification failed");
        }
    }

    /// Prepares proof points for batch verification
    async fn prepare_proof_points(&self, instances: Vec<VerificationVariables>) -> ProofPoints {
        let len = instances.len();
        let mut a_points = Vec::with_capacity(3 * len);
        let mut b_points = Vec::with_capacity(3 * len);

        for instance in instances {
            let prepared_inputs = PublicInputProcessor::prepare_inputs_bytes(
                &instance.public_input,
                &self.verifying_key.ic,
                self.builtin_address,
            )
            .await;

            let proof_components = ProofComponents::from_bytes(&instance.proof_bytes);

            a_points.extend([proof_components.a, prepared_inputs, proof_components.c]);
            b_points.extend([
                proof_components.b,
                self.verifying_key.gamma_g2_neg_pc,
                self.verifying_key.delta_g2_neg_pc,
            ]);
        }

        ProofPoints {
            a_points,
            b_points,
            batch_size: len,
        }
    }

    /// Executes the pairing check for batch verification
    async fn execute_pairing_check(&self, proof_points: &ProofPoints) -> bool {
        let a: ArkScale<Vec<G1Affine>> = proof_points.a_points.clone().into();
        let b: ArkScale<Vec<G2Affine>> = proof_points.b_points.clone().into();

        let miller_out =
            PairingOperations::multi_miller_loop(a.encode(), b.encode(), self.builtin_address)
                .await;

        let exp = PairingOperations::final_exponentiation(miller_out, self.builtin_address).await;
        let expected = self
            .verifying_key
            .alpha_g1_beta_g2
            .0
            .pow([proof_points.batch_size as u64]);

        exp.0 == expected
    }
}

/// Helper struct for managing proof point collections
#[derive(Debug, Clone)]
struct ProofPoints {
    a_points: Vec<G1Affine>,
    b_points: Vec<G2Affine>,
    batch_size: usize,
}

/// Deserialized proof components
#[derive(Debug, Clone)]
struct ProofComponents {
    a: G1Affine,
    b: G2Affine,
    c: G1Affine,
}

impl ProofComponents {
    fn from_bytes(proof_bytes: &ProofBytes) -> Self {
        Self {
            a: CurvePointDeserializer::deserialize_g1(&proof_bytes.a),
            b: CurvePointDeserializer::deserialize_g2(&proof_bytes.b),
            c: CurvePointDeserializer::deserialize_g1(&proof_bytes.c),
        }
    }
}

// ================================================================================================
// Utility Modules
// ================================================================================================

/// Handles curve point deserialization
struct CurvePointDeserializer;

impl CurvePointDeserializer {
    #[inline]
    fn deserialize_g1(data: &[u8]) -> G1Affine {
        G1Affine::deserialize_uncompressed_unchecked(data)
            .expect("Deserialization failed: G1 point")
    }

    #[inline]
    fn deserialize_g2(data: &[u8]) -> G2Affine {
        G2Affine::deserialize_uncompressed_unchecked(data)
            .expect("Deserialization failed: G2 point")
    }
}

/// Handles pairing operations via builtin calls
struct PairingOperations;

impl PairingOperations {
    async fn multi_scalar_mul_g1(
        bases: Vec<u8>,
        scalars: Vec<u8>,
        builtin_address: ActorId,
    ) -> Vec<u8> {
        match PairingOperations::send_request_and_extract(
            Request::MultiScalarMultiplicationG1 { bases, scalars },
            builtin_address,
            "MSM",
        )
        .await
        {
            Response::MultiScalarMultiplicationG1(result) => result,
            _ => unreachable!("MSM: unexpected response type"),
        }
    }

    async fn multi_miller_loop(g1: Vec<u8>, g2: Vec<u8>, builtin_address: ActorId) -> Vec<u8> {
        match PairingOperations::send_request_and_extract(
            Request::MultiMillerLoop { a: g1, b: g2 },
            builtin_address,
            "MultiMillerLoop",
        )
        .await
        {
            Response::MultiMillerLoop(result) => result,
            _ => unreachable!("MultiMillerLoop: unexpected response type"),
        }
    }

    async fn final_exponentiation(f: Vec<u8>, builtin_address: ActorId) -> ArkScale<Gt> {
        match PairingOperations::send_request_and_extract(
            Request::FinalExponentiation { f },
            builtin_address,
            "FinalExp",
        )
        .await
        {
            Response::FinalExponentiation(result) => ArkScale::<Gt>::decode(&mut result.as_slice())
                .expect("FinalExp: decode ArkScale failed"),
            _ => unreachable!("FinalExp: unexpected response type"),
        }
    }

    async fn send_request_and_extract(
        request: Request,
        builtin_address: ActorId,
        context: &'static str,
    ) -> Response {
        let reply = msg::send_bytes_for_reply(builtin_address, &request.encode(), 0, 0)
            .expect(&format!("{}: failed to send request", context))
            .await
            .expect(&format!("{}: reply failed", context));

        Response::decode(&mut reply.as_slice())
            .expect(&format!("{}: failed to decode response", context))
    }
}

/// Handles public input processing and preparation
struct PublicInputProcessor;

impl PublicInputProcessor {
    /// Prepares public inputs for verification from byte representation
    async fn prepare_inputs_bytes(
        public_input: &[Vec<u8>],
        ic: &[G1Affine],
        builtin_address: ActorId,
    ) -> G1Affine {
        let public_inputs: Vec<Fr> = public_input
            .iter()
            .map(|bytes| {
                Fr::deserialize_uncompressed_unchecked(&**bytes)
                    .expect("Deserialization failed: public input")
            })
            .collect();

        Self::prepare_inputs(ic, &public_inputs, builtin_address).await
    }

    /// Prepares verification inputs using multi-scalar multiplication
    async fn prepare_inputs(
        gamma_abc_g1: &[G1Affine],
        public_inputs: &[Fr],
        builtin_address: ActorId,
    ) -> G1Affine {
        if (public_inputs.len() + 1) != gamma_abc_g1.len() {
            panic!("Invalid proof length");
        }

        let mut g_ic = gamma_abc_g1[0].into_group();

        let bases: ArkScale<Vec<G1Affine>> = gamma_abc_g1[1..].to_vec().into();
        let scalars: ArkScale<Vec<<G1 as Group>::ScalarField>> = public_inputs.to_vec().into();

        let msm_result_bytes = PairingOperations::multi_scalar_mul_g1(
            bases.encode(),
            scalars.encode(),
            builtin_address,
        )
        .await;

        let msm_result_affine = ArkScaleProjective::<G1>::decode(&mut msm_result_bytes.as_slice())
            .expect("Deserialization failed: MSM result")
            .0;

        g_ic.add_assign(msm_result_affine);
        g_ic.into()
    }
}

/// Handles parsing and validation of public inputs
struct PublicInputParser;

impl PublicInputParser {
    /// Parses original and permuted card decks from public input
    pub fn parse_original_and_permuted(
        public_input: &[Vec<u8>],
        config: DeckConfig,
    ) -> ParsedPublicInput {
        if public_input.len() != config.expected_input_length() {
            panic!("Invalid proof length");
        }

        // Validate proof validity flag
        let is_valid = Fq::from_le_bytes_mod_order(&public_input[0]);
        if is_valid != Fq::one() {
            panic!("Invalid proof flag");
        }

        let public_key = Self::extract_public_key(public_input);

        // Parse decks
        let original_offset = 1 + config.pk_size;
        let permuted_offset = original_offset + config.num_coords * config.num_cards;

        let original_deck = Self::parse_encrypted_deck(public_input, original_offset, config);
        let permuted_deck = Self::parse_encrypted_deck(public_input, permuted_offset, config);

        ParsedPublicInput {
            original_deck,
            permuted_deck,
            public_key,
        }
    }

    fn extract_public_key(public_input: &[Vec<u8>]) -> PublicKey {
        PublicKey {
            x: public_input[1]
                .clone()
                .try_into()
                .expect("Deserialization failed: pk.x"),
            y: public_input[2]
                .clone()
                .try_into()
                .expect("Deserialization failed: pk.y"),
            z: public_input[3]
                .clone()
                .try_into()
                .expect("Deserialization failed: pk.z"),
        }
    }

    fn parse_encrypted_deck(
        public_input: &[Vec<u8>],
        offset: usize,
        config: DeckConfig,
    ) -> Vec<EncryptedCard> {
        (0..config.num_cards)
            .map(|card_idx| EncryptedCard {
                c0: [
                    public_input[offset + 0 * config.num_cards + card_idx].clone(),
                    public_input[offset + 1 * config.num_cards + card_idx].clone(),
                    public_input[offset + 2 * config.num_cards + card_idx].clone(),
                ],
                c1: [
                    public_input[offset + 3 * config.num_cards + card_idx].clone(),
                    public_input[offset + 4 * config.num_cards + card_idx].clone(),
                    public_input[offset + 5 * config.num_cards + card_idx].clone(),
                ],
            })
            .collect()
    }
}

/// Handles shuffle chain validation
pub struct ShuffleChainValidator;

impl ShuffleChainValidator {
    /// Validates the integrity of a shuffle chain
    pub fn validate_shuffle_chain(
        instances: &[VerificationVariables],
        original_deck: &[EdwardsProjective],
        expected_pub_key: &PublicKey,
        final_encrypted_deck: &[EncryptedCard],
    ) {
        let config = DeckConfig::STANDARD;

        // Parse and validate first instance
        let first_parsed =
            PublicInputParser::parse_original_and_permuted(&instances[0].public_input, config);

        if !compare_public_keys(expected_pub_key, &first_parsed.public_key) {
            panic!("Public key mismatch");
        }

        Self::validate_initial_deck_matches(original_deck, &first_parsed.original_deck);

        let mut current_deck = first_parsed.permuted_deck;

        // Validate chain continuity
        for instance in instances[1..].iter() {
            let parsed =
                PublicInputParser::parse_original_and_permuted(&instance.public_input, config);

            if !compare_public_keys(expected_pub_key, &parsed.public_key) {
                panic!("Public key mismatch");
            }

            if parsed.original_deck != current_deck {
                panic!("Shuffle chain discontinuity");
            }

            current_deck = parsed.permuted_deck;
        }

        // Validate final deck state
        Self::validate_final_deck_matches(&current_deck, final_encrypted_deck);
    }

    fn validate_initial_deck_matches(expected: &[EdwardsProjective], actual: &[EncryptedCard]) {
        if expected.len() != actual.len() {
            panic!("Initial deck len mismatch");
        }

        for (expected_card, actual_card) in expected.iter().zip(actual) {
            if !compare_projective_and_coords(expected_card, &actual_card.c1) {
                panic!("Initial deck mismatch");
            }
        }
    }

    fn validate_final_deck_matches(expected: &[EncryptedCard], actual: &[EncryptedCard]) {
        for (expected_card, actual_card) in expected.iter().zip(actual) {
            if !compare_points(&expected_card.c0, &actual_card.c0)
                || !compare_points(&expected_card.c1, &actual_card.c1)
            {
                panic!("Final deck mismatch");
            }
        }
    }
}
