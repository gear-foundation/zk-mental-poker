use crate::services::{
    EncryptedCard, PublicKey,
    curve::{compare_points, compare_public_keys},
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

type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;

#[derive(Debug, Encode, Decode, TypeInfo, Clone, Default)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct VerifyingKeyBytes {
    pub alpha_g1_beta_g2: Vec<u8>,
    pub gamma_g2_neg_pc: Vec<u8>,
    pub delta_g2_neg_pc: Vec<u8>,
    pub ic: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1_beta_g2: ArkScale<<Bls12_381 as Pairing>::TargetField>,
    pub gamma_g2_neg_pc: G2Affine,
    pub delta_g2_neg_pc: G2Affine,
    pub ic: Vec<G1Affine>,
}

pub fn decode_verifying_key(vk: &VerifyingKeyBytes) -> VerifyingKey {
    let delta_g2_neg_pc = G2Affine::deserialize_uncompressed_unchecked(&*vk.delta_g2_neg_pc)
        .expect("Failed to deserialize delta_g2_neg_pc");

    let gamma_g2_neg_pc = G2Affine::deserialize_uncompressed_unchecked(&*vk.gamma_g2_neg_pc)
        .expect("Failed to deserialize gamma_g2_neg_pc");

    let alpha_g1_beta_g2 = <ArkScale<<Bls12_381 as Pairing>::TargetField> as Decode>::decode(
        &mut vk.alpha_g1_beta_g2.as_slice(),
    )
    .expect("Decode error");

    let ic = vk
        .ic
        .iter()
        .map(|bytes| {
            G1Affine::deserialize_uncompressed_unchecked(&**bytes)
                .expect("Failed to deserialize ic element")
        })
        .collect::<Vec<G1Affine>>();

    VerifyingKey {
        alpha_g1_beta_g2,
        gamma_g2_neg_pc,
        delta_g2_neg_pc,
        ic,
    }
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct ProofBytes {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct VerificationVariables {
    pub proof_bytes: ProofBytes,
    pub public_input: Vec<Vec<u8>>,
}

pub async fn verify_batch(
    vk: &VerifyingKey,
    instances: Vec<VerificationVariables>,
    builtin_bls381_address: ActorId,
) {
    let mut a_points = Vec::with_capacity(3 * instances.len());
    let mut b_points = Vec::with_capacity(3 * instances.len());

    let len = instances.len();

    for instance in instances {
        let VerificationVariables {
            proof_bytes,
            public_input,
        } = instance;

        let prepared_inputs =
            get_prepared_inputs_bytes(public_input, vk.ic.clone(), builtin_bls381_address).await;
        let a = G1Affine::deserialize_uncompressed_unchecked(&*proof_bytes.a)
            .expect("Deserialize error");
        let b = G2Affine::deserialize_uncompressed_unchecked(&*proof_bytes.b)
            .expect("Deserialize error");
        let c = G1Affine::deserialize_uncompressed_unchecked(&*proof_bytes.c)
            .expect("Deserialize error");

        a_points.extend([a, prepared_inputs, c]);
        b_points.extend([b, vk.gamma_g2_neg_pc, vk.delta_g2_neg_pc]);
    }

    let a: ArkScale<Vec<G1Affine>> = a_points.into();
    let b: ArkScale<Vec<G2Affine>> = b_points.into();
    let miller_out =
        calculate_multi_miller_loop(a.encode(), b.encode(), builtin_bls381_address).await;

    let exp = calculate_exponentiation(miller_out, builtin_bls381_address).await;

    let expected = vk.alpha_g1_beta_g2.0.pow([len as u64]);

    if exp.0 != expected {
        ext::panic("Batch verification failed");
    }
}

async fn calculate_multi_scalar_mul_g1(
    bases: Vec<u8>,
    scalars: Vec<u8>,
    builtin_bls381_address: ActorId,
) -> Vec<u8> {
    let request = Request::MultiScalarMultiplicationG1 { bases, scalars }.encode();
    let reply = msg::send_bytes_for_reply(builtin_bls381_address, &request, 0, 0)
        .expect("Failed to send message")
        .await
        .expect("Received error reply");
    let response = Response::decode(&mut reply.as_slice()).expect("Error: decode response");
    match response {
        Response::MultiScalarMultiplicationG1(v) => v,
        _ => unreachable!(),
    }
}

async fn calculate_multi_miller_loop(
    g1: Vec<u8>,
    g2: Vec<u8>,
    builtin_bls381_address: ActorId,
) -> Vec<u8> {
    let request = Request::MultiMillerLoop { a: g1, b: g2 }.encode();
    let reply = msg::send_bytes_for_reply(builtin_bls381_address, &request, 0, 0)
        .expect("Failed to send message")
        .await
        .expect("Received error reply");
    let response = Response::decode(&mut reply.as_slice()).expect("Error: decode response");
    match response {
        Response::MultiMillerLoop(v) => v,
        _ => unreachable!(),
    }
}

async fn calculate_exponentiation(
    f: Vec<u8>,
    builtin_bls381_address: ActorId,
) -> ArkScale<<Bls12_381 as Pairing>::TargetField> {
    let request = Request::FinalExponentiation { f }.encode();
    let reply = msg::send_bytes_for_reply(builtin_bls381_address, &request, 0, 0)
        .expect("Failed to send message")
        .await
        .expect("Received error reply");
    let response = Response::decode(&mut reply.as_slice()).expect("Error: decode response");
    let exp = match response {
        Response::FinalExponentiation(v) => {
            ArkScale::<<Bls12_381 as Pairing>::TargetField>::decode(&mut v.as_slice())
                .expect("Error: decode ArkScale")
        }
        _ => unreachable!(),
    };
    exp
}

pub async fn get_prepared_inputs_bytes(
    public_input: Vec<Vec<u8>>,
    ic: Vec<G1Affine>,
    builtin_bls381_address: ActorId,
) -> G1Affine {
    let public_inputs: Vec<Fr> = public_input
        .iter()
        .map(|bytes| {
            Fr::deserialize_uncompressed_unchecked(&**bytes)
                .expect("Failed to deserialize public input")
        })
        .collect();

    prepare_inputs(&ic, &public_inputs, builtin_bls381_address).await
}

async fn prepare_inputs(
    gamma_abc_g1: &[G1Affine],
    public_inputs: &[Fr],
    builtin_bls381_address: ActorId,
) -> G1Affine {
    if (public_inputs.len() + 1) != gamma_abc_g1.len() {
        panic!("Wrong public inputs or IC length");
    }
    let mut g_ic = gamma_abc_g1[0].into_group();

    let bases: ArkScale<Vec<G1Affine>> = gamma_abc_g1[1..].to_vec().into();
    let scalars: ArkScale<Vec<<G1 as Group>::ScalarField>> = public_inputs.to_vec().into();

    let msm_result_bytes =
        calculate_multi_scalar_mul_g1(bases.encode(), scalars.encode(), builtin_bls381_address)
            .await;
    let msm_result_affine = ArkScaleProjective::<G1>::decode(&mut msm_result_bytes.as_slice())
        .expect("Deserialize error")
        .0;

    g_ic.add_assign(msm_result_affine);

    g_ic.into()
}

pub fn validate_shuffle_chain(
    instances: &[VerificationVariables],
    original_deck: &[EncryptedCard],
    expected_pub_key: &PublicKey,
    final_encrypted_deck: &[EncryptedCard],
) {
    let mut expected_original = original_deck.to_vec();

    for (i, instance) in instances.iter().enumerate() {
        let (original, permuted, pk) = parse_original_and_permuted(&instance.public_input);

        assert!(
            compare_public_keys(expected_pub_key, &pk),
            "Wrong aggregated public key"
        );

        if i == 0 {
            assert_initial_deck_matches(&expected_original, &original);
        } else {
            assert_eq!(original, expected_original, "Mismatch in shuffle chain");
        }

        expected_original = permuted;
    }

    assert_eq!(
        expected_original.len(),
        final_encrypted_deck.len(),
        "Final deck length mismatch"
    );

    for (expected, actual) in expected_original.iter().zip(final_encrypted_deck) {
        if !compare_points(&expected.c0, &actual.c0) || !compare_points(&expected.c1, &actual.c1) {
            panic!("Mismatch in deck");
        }
    }
}

fn assert_initial_deck_matches(expected: &[EncryptedCard], actual: &[EncryptedCard]) {
    assert_eq!(
        expected.len(),
        actual.len(),
        "Deck length mismatch in initial check"
    );

    for (e, a) in expected.iter().zip(actual) {
        if !compare_points(&e.c1, &a.c1) {
            panic!("Mismatch in initial deck");
        }
    }
}

pub fn parse_original_and_permuted(
    public_input: &[Vec<u8>],
) -> (Vec<EncryptedCard>, Vec<EncryptedCard>, PublicKey) {
    let num_cards: usize = 52;
    // c0.X, c0.Y, c0.Z, c1.X, c1.Y, c1.Z
    let num_coords: usize = 6;
    let pk_size: usize = 3;
    let original_offset: usize = pk_size + 1;
    let permuted_offset: usize = original_offset + num_coords * num_cards;

    // Check input length (original + permuted)
    let expected_length = pk_size + num_coords * num_cards * 2 + 1;

    if public_input.len() != expected_length {
        panic!("Invalid length");
    }

    let is_valid = Fq::from_le_bytes_mod_order(&public_input[0]);

    if is_valid != Fq::one() {
        panic!("Invalid proof: is_valid != 1");
    }

    // // pk[3]
    let pk = PublicKey {
        x: public_input[1]
            .clone()
            .try_into()
            .expect("expected 32 bytes for x"),
        y: public_input[2]
            .clone()
            .try_into()
            .expect("expected 32 bytes for y"),
        z: public_input[3]
            .clone()
            .try_into()
            .expect("expected 32 bytes for z"),
    };

    sails_rs::gstd::debug!("PK {:?}", pk);

    // Parsing `original`
    let original = (0..num_cards)
        .map(|card_idx| EncryptedCard {
            c0: [
                public_input[original_offset + 0 * num_cards + card_idx].clone(),
                public_input[original_offset + 1 * num_cards + card_idx].clone(),
                public_input[original_offset + 2 * num_cards + card_idx].clone(),
            ],
            c1: [
                public_input[original_offset + 3 * num_cards + card_idx].clone(),
                public_input[original_offset + 4 * num_cards + card_idx].clone(),
                public_input[original_offset + 5 * num_cards + card_idx].clone(),
            ],
        })
        .collect();
    // Parsing `permuted`
    let permuted = (0..num_cards)
        .map(|card_idx| EncryptedCard {
            c0: [
                public_input[permuted_offset + 0 * num_cards + card_idx].clone(),
                public_input[permuted_offset + 1 * num_cards + card_idx].clone(),
                public_input[permuted_offset + 2 * num_cards + card_idx].clone(),
            ],
            c1: [
                public_input[permuted_offset + 3 * num_cards + card_idx].clone(),
                public_input[permuted_offset + 4 * num_cards + card_idx].clone(),
                public_input[permuted_offset + 5 * num_cards + card_idx].clone(),
            ],
        })
        .collect();
    (original, permuted, pk)
}
