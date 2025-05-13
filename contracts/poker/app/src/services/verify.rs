use crate::services::shuffle_vk_bytes;
use core::ops::AddAssign;
use gbuiltin_bls381::{
    Request, Response,
    ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective as G1, G2Affine},
    ark_ec::{AffineRepr, Group, pairing::Pairing},
    ark_ff::PrimeField,
    ark_scale,
    ark_scale::hazmat::ArkScaleProjective,
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
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

pub fn shuffle_vk_from_consts() -> VerifyingKeyBytes {
    VerifyingKeyBytes {
        alpha_g1_beta_g2: shuffle_vk_bytes::VK_ALPHA_G1_BETA_G2.to_vec(),
        gamma_g2_neg_pc: shuffle_vk_bytes::VK_GAMMA_G2_NEG_PC.to_vec(),
        delta_g2_neg_pc: shuffle_vk_bytes::VK_DELTA_G2_NEG_PC.to_vec(),
        ic: shuffle_vk_bytes::VK_IC
            .iter()
            .map(|row| row.to_vec())
            .collect(),
    }
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

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct VerificationResult {
    pub res: u8,
    pub hit: u8,
}

#[derive(Debug, Encode, Decode, TypeInfo, Clone)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct PublicStartInput {
    pub hash: Vec<u8>,
}

pub async fn verify_batch_shuffle(
    vk: &VerifyingKey,
    instances: Vec<VerificationVariables>,
    builtin_bls381_address: ActorId,
) {
    for instance in instances {
        let VerificationVariables {
            proof_bytes,
            public_input,
        } = instance;
        let prepared_input_bytes =
            get_shuffle_prepared_inputs_bytes(public_input, vk.ic.clone(), builtin_bls381_address)
                .await;

        verify(
            vk,
            proof_bytes,
            prepared_input_bytes,
            builtin_bls381_address,
        )
        .await;
    }
}

pub async fn verify(
    vk: &VerifyingKey,
    proof: ProofBytes,
    prepared_inputs: G1Affine,
    builtin_bls381_address: ActorId,
) {
    let a = G1Affine::deserialize_uncompressed_unchecked(&*proof.a).expect("Deserialize error");

    let b = G2Affine::deserialize_uncompressed_unchecked(&*proof.b).expect("Deserialize error");

    let c = G1Affine::deserialize_uncompressed_unchecked(&*proof.c).expect("Deserialize error");

    let a: ArkScale<Vec<G1Affine>> = vec![a, prepared_inputs, c].into();
    let b: ArkScale<Vec<G2Affine>> = vec![b, vk.gamma_g2_neg_pc, vk.delta_g2_neg_pc].into();
    let miller_out =
        calculate_multi_miller_loop(a.encode(), b.encode(), builtin_bls381_address).await;

    let exp = calculate_exponentiation(miller_out, builtin_bls381_address).await;

    if exp != vk.alpha_g1_beta_g2 {
        ext::panic("Verification failed");
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

pub async fn get_shuffle_prepared_inputs_bytes(
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

// pub async fn get_start_prepared_inputs_bytes(
//     public_input: PublicStartInput,
//     ic: Vec<Vec<u8>>,
// ) -> Vec<u8> {
//     let public_inputs: Vec<Fr> = vec![
//         Fr::deserialize_uncompressed_unchecked(&*public_input.hash).expect("Deserialize error"),
//     ];

//     let gamma_abc_g1: Vec<G1Affine> = ic
//         .into_iter()
//         .map(|ic_element| {
//             G1Affine::deserialize_uncompressed_unchecked(&*ic_element).expect("Deserialize error")
//         })
//         .collect();

//     prepare_inputs(&gamma_abc_g1, &public_inputs).await
// }

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
