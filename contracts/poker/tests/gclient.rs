use gclient::{EventProcessor, GearApi, Result};
use sails_rs::{ActorId, Decode, Encode};
mod utils_gclient;
use crate::zk_loader::{
    VKey, deserialize_g1, deserialize_g2, load_encrypted_table_cards, load_partial_decrypt_proofs,
    load_partial_decryptions, load_player_public_keys, load_shuffle_proofs,
};
use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_ff::{BigInteger256, PrimeField};
use ark_scale::ArkScale;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use core::ops::AddAssign;
use num_bigint::BigUint;
use num_traits::Num;
use poker_client::{EncryptedCard, ProofBytes, PublicKey, VerificationVariables, traits::*};
use sails_rs::collections::HashMap;
use serde::Deserialize;
use std::fs;
use std::ops::Neg;
use std::str::FromStr;
use utils_gclient::*;

fn prepare_inputs(gamma_abc_g1: &[G1Affine], public_inputs: &[Fr]) -> Vec<u8> {
    if public_inputs.len() + 1 != gamma_abc_g1.len() {
        panic!(
            "Invalid number of public inputs: got {}, expected {}",
            public_inputs.len(),
            gamma_abc_g1.len() - 1
        );
    }

    let mut g_ic = gamma_abc_g1[0].into_group();

    for (input, base_point) in public_inputs.iter().zip(gamma_abc_g1.iter().skip(1)) {
        let mul = base_point.mul_bigint(input.into_bigint());
        g_ic.add_assign(&mul);
    }

    let mut prepared_bytes = Vec::new();
    g_ic.serialize_uncompressed(&mut prepared_bytes)
        .expect("Failed to serialize prepared input");

    prepared_bytes
}

fn format_bytes_array_const(name: &str, bytes: &[u8]) -> String {
    let mut out = format!("pub const {}: [u8; {}] = [\n    ", name, bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        out.push_str(&format!("{}, ", b));
        if (i + 1) % 16 == 0 {
            out.push_str("\n    ");
        }
    }
    out.push_str("\n];\n\n");
    out
}

fn format_ic_array_const(name: &str, bytes_vec: &[Vec<u8>]) -> String {
    let mut out = format!("pub const {}: [[u8; 96]; {}] = [\n", name, bytes_vec.len());
    for bytes in bytes_vec {
        out.push_str("    [\n        ");
        for (i, b) in bytes.iter().enumerate() {
            out.push_str(&format!("{}, ", b));
            if (i + 1) % 16 == 0 {
                out.push_str("\n        ");
            }
        }
        out.push_str("],\n");
    }
    out.push_str("];\n\n");
    out
}

#[tokio::test]
async fn test_basic_function() -> Result<()> {
    let pks = load_player_public_keys("/Users/luisa/zk-shuffle-runner/output/player_pks.json");

    let proofs = load_shuffle_proofs("/Users/luisa/zk-shuffle-runner/output/shuffle_proofs.json");
    let deck =
        load_encrypted_table_cards("/Users/luisa/zk-shuffle-runner/output/encrypted_deck.json");

    println!("Deck {:?}", deck.len());
    let decrypt_proofs =
        load_partial_decrypt_proofs("/Users/luisa/zk-shuffle-runner/output/partial_decrypt_proofs.json");
    let pk_cards =
        load_partial_decryptions("/Users/luisa/zk-shuffle-runner/output/partial_decryptions.json");
    let mut pk_to_actor_id: Vec<(PublicKey, ActorId)> = vec![];
    let api = GearApi::dev().await?;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[0].1.clone(), id));

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);
    // Init
    let (message_id, program_id) = init(&api, pks[0].1.clone()).await;
    assert!(listener.message_processed(message_id).await?.succeed());

    // Resgiter
    println!("REGISTER");
    let mut player_name = "Alice".to_string();
    let api = get_new_client(&api, USERS_STR[0]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[1].1.clone(), id));
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Register", payload: (player_name, pks[1].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());

    player_name = "Bob".to_string();
    let api = get_new_client(&api, USERS_STR[1]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[2].1.clone(), id));
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Register", payload: (player_name, pks[2].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());

    // Shuffle deck
    println!("SHUFFLE");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "ShuffleDeck", payload: (deck, proofs));
    assert!(listener.message_processed(message_id).await?.succeed());

    // Start game
    println!("START");
    let api = get_new_client(&api, "//Alice").await;
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "StartGame", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    // Verify partial decryptions
    let cards_by_actor: Vec<(ActorId, [EncryptedCard; 2])> = pk_cards
        .into_iter()
        .map(|(pk, cards)| {
            let id = pk_to_actor_id
                .iter()
                .find(|(pk1, _)| pk1 == &pk)
                .map(|(_, id)| *id)
                .expect("PublicKey not found");
            (id, cards)
        })
        .collect();
    println!("DECRYPT");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitAllPartialDecryptions", payload: (cards_by_actor, decrypt_proofs));

    // let json =
    //     fs::read_to_string("/Users/luisa/zk-shuffle-runner/output/decrypt_vkey.json").unwrap();
    // let vkey: VKey = serde_json::from_str(&json).unwrap();

    // let alpha = deserialize_g1(&vkey.vk_alpha_1);
    // let mut buf = Vec::new();
    // alpha.serialize_compressed(&mut buf).unwrap();

    // let beta = deserialize_g2(&(vkey.vk_beta_2.to_vec())).unwrap();
    // let gamma = deserialize_g2(&vkey.vk_gamma_2).unwrap();
    // let delta = deserialize_g2(&vkey.vk_delta_2).unwrap();

    // // IC: Vec<G1Affine> from [String; 3]
    // let ic_points: Vec<G1Affine> = vkey.IC.iter().map(|p| deserialize_g1(p)).collect();

    // // pairing(alpha, beta)
    // let alpha_g1_beta_g2 = Bls12_381::pairing(alpha, beta).0;

    // let mut alpha_beta_bytes = Vec::new();
    // alpha_g1_beta_g2
    //     .serialize_uncompressed(&mut alpha_beta_bytes)
    //     .unwrap();

    // let gamma_g2_neg_pc = gamma.into_group().neg().into_affine();
    // let delta_g2_neg_pc = delta.into_group().neg().into_affine();

    // let mut gamma_neg_bytes = Vec::new();
    // gamma_g2_neg_pc
    //     .serialize_uncompressed(&mut gamma_neg_bytes)
    //     .unwrap();

    // let mut delta_neg_bytes = Vec::new();
    // delta_g2_neg_pc
    //     .serialize_uncompressed(&mut delta_neg_bytes)
    //     .unwrap();

    // let mut ic_compressed: Vec<Vec<u8>> = vec![];

    // for ic in ic_points.clone() {
    //     let mut buf = Vec::new();
    //     ic.serialize_uncompressed(&mut buf).unwrap();
    //     assert_eq!(buf.len(), 96);
    //     ic_compressed.push(buf);
    // }
    //     let (proof, public_inputs) = load_proof_and_inputs("/Users/luisa/zk-shuffle-runner/proof.json");

    //     let prepared_inputs_bytes = prepare_inputs(&ic_points, &public_inputs);
    //     let prepared_inputs = G1Affine::deserialize_uncompressed_unchecked(&*prepared_inputs_bytes)
    //         .expect("Deserialize error");

    //     let a_prep = <ark_ec::bls12::G1Prepared<ark_bls12_381::Config>>::from(proof.a);
    //     let b_prep = <ark_ec::bls12::G2Prepared<ark_bls12_381::Config>>::from(proof.b);
    //     let c_prep = <ark_ec::bls12::G1Prepared<ark_bls12_381::Config>>::from(proof.c);
    //     let prepared_inputs_prep =
    //         <ark_ec::bls12::G1Prepared<ark_bls12_381::Config>>::from(prepared_inputs);
    //     let gamma_neg_prep = <ark_ec::bls12::G2Prepared<ark_bls12_381::Config>>::from(gamma_g2_neg_pc);
    //     let delta_neg_prep = <ark_ec::bls12::G2Prepared<ark_bls12_381::Config>>::from(delta_g2_neg_pc);

    // let mut output = String::new();
    // output.push_str(&format_bytes_array_const(
    //     "VK_ALPHA_G1_BETA_G2",
    //     &alpha_beta_bytes,
    // ));
    // output.push_str(&format_bytes_array_const(
    //     "VK_GAMMA_G2_NEG_PC",
    //     &gamma_neg_bytes,
    // ));
    // output.push_str(&format_bytes_array_const(
    //     "VK_DELTA_G2_NEG_PC",
    //     &delta_neg_bytes,
    // ));
    // output.push_str(&format_ic_array_const("VK_IC", &ic_compressed));

    // fs::write("decrypt_vk_bytes.rs", output).unwrap();

    //     let qap = <Bls12_381 as Pairing>::multi_miller_loop(
    //         [a_prep, prepared_inputs_prep, c_prep],
    //         [b_prep, gamma_neg_prep, delta_neg_prep],
    //     );
    //     let test = <Bls12_381 as Pairing>::final_exponentiation(qap).unwrap();
    //     println!(
    //         "test.0 == pvk.alpha_g1_beta_g2 {:?}",
    //         test.0 == alpha_g1_beta_g2
    //     );

    //     let proof_bytes = encode_proof(&proof);
    //     let public_input = encode_inputs(&public_inputs);
    //     let verification = VerificationVariables {
    //         proof_bytes,
    //         public_input,
    //     };
    //     let api = GearApi::dev().await?;
    //     let john_api = get_new_client(&api, USERS_STR[0]).await;

    //     let mut listener = api.subscribe().await?;
    //     assert!(listener.blocks_running().await?);

    //     let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "VerifyShuffle", payload: (verification));
    //     assert!(listener.message_processed(message_id).await?.succeed());

    Ok(())
}
