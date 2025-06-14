use std::{thread::sleep, time};

use ark_ec::CurveGroup;
use gclient::EventListener;
use gclient::{GearApi, Result};
use sails_rs::{ActorId, Decode, Encode};
mod utils_gclient;
use crate::zk_loader::decimal_str_to_bytes_32;
use crate::zk_loader::{
    get_vkey, load_cards_with_proofs, load_player_public_keys, load_table_cards_proofs,
    DecryptedCardWithProof,
};
use ark_ec::AffineRepr;
use ark_ed_on_bls12_381_bandersnatch::Fq;
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use gclient::EventProcessor;
use gear_core::ids::prelude::CodeIdExt;
use gear_core::ids::{CodeId, ProgramId};
use num_bigint::BigUint;
use poker_client::EncryptedCard;
use poker_client::PublicKey;
use poker_client::VerificationVariables;
use poker_client::{Action, BettingStage, Card, Participant, Stage, Status, Suit};
use sails_rs::collections::HashMap;
use sails_rs::TypeInfo;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::io::BufWriter;
use std::str::FromStr;
use std::{fs::File, path::Path};
use utils_gclient::*;
use crate::zk_loader::{load_shuffle_proofs, load_encrypted_table_cards, load_partial_decrypt_proofs, load_partial_decryptions};

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct TurnManager {
    active_ids: Vec<ActorId>,
    turn_index: u64,
}

#[tokio::test]
async fn upload_contracts_to_testnet() -> Result<()> {
    let poker_code_path = "../target/wasm32-gear/release/poker.opt.wasm";
    // let api = GearApi::dev().await?;
    let api = GearApi::vara_testnet().await?;
    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);
    let poker_code_id = if let Ok((code_id, _hash)) = api.upload_code_by_path(poker_code_path).await
    {
        code_id
    } else {
        let code =
            fs::read("../target/wasm32-gear/release/poker.opt.wasm").expect("Failed to read file");
        CodeId::generate(code.as_ref())
    };
    let pks = load_player_public_keys("tests/test_data/player_pks.json");

    // PTS
    let path = "../target/wasm32-gear/release/pts.opt.wasm";
    let accural: u128 = 10_000;
    let time_ms_between_balance_receipt: u64 = 10_000;
    let request = [
        "New".encode(),
        (accural, time_ms_between_balance_receipt).encode(),
    ]
    .concat();

    let (message_id, pts_program_id, _hash) = api
        .upload_program_bytes(
            gclient::code_from_os(path).unwrap(),
            gclient::now_micros().to_le_bytes(),
            request,
            740_000_000_000,
            0,
        )
        .await
        .expect("Error upload program bytes");
    assert!(listener.message_processed(message_id).await?.succeed());
    let pts_id_bytes: [u8; 32] = pts_program_id.into();
    let pts_id: ActorId = pts_id_bytes.into();
    println!("pts_program_id {:?}", pts_program_id);

    let shuffle_vkey = get_vkey("tests/test_data/shuffle_vkey.json");
    let decrypt_vkey = get_vkey("tests/test_data/decrypt_vkey.json");

    // Factory

    let path = "../target/wasm32-gear/release/poker_factory.opt.wasm";
    let config = Config {
        lobby_code_id: poker_code_id,
        gas_for_program: 680_000_000_000,
        gas_for_reply_deposit: 10_000_000_000,
    };
    let request = [
        "New".encode(),
        (config, pts_id, shuffle_vkey.encode(), decrypt_vkey.encode()).encode(),
    ]
    .concat();

    let (message_id, factory_program_id, _hash) = api
        .upload_program_bytes(
            gclient::code_from_os(path).unwrap(),
            gclient::now_micros().to_le_bytes(),
            request,
            740_000_000_000,
            10_000_000_000_000,
        )
        .await
        .expect("Error upload program bytes");
    assert!(listener.message_processed(message_id).await?.succeed());

    println!("factory_id {:?}", factory_program_id);

    // make admin in PTS
    println!("add admin");
    let factory_id_bytes: [u8; 32] = factory_program_id.into();
    let factory_id: ActorId = factory_id_bytes.into();
    let message_id = send_request!(api: &api, program_id: pts_program_id, service_name: "Pts", action: "AddAdmin", payload: (factory_id));
    assert!(listener.message_processed(message_id).await?.succeed());

    // mint tokens in PTS
    println!("mint tokens");
    let message_id = send_request!(api: &api, program_id: pts_program_id, service_name: "Pts", action: "GetAccural", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    // create lobby
    println!("create lobby");
    let config = LobbyConfig {
        admin_id: api.get_actor_id(),
        admin_name: "Name".to_string(),
        lobby_name: "Lobby".to_string(),
        small_blind: 5,
        big_blind: 10,
        number_of_participants: 3,
        starting_bank: 1000,
        time_per_move_ms: 15_000,
    };
    let request = [
        "PokerFactory".encode(),
        "CreateLobby".encode(),
        (config.clone(), pks[0].1.clone()).encode(),
    ]
    .concat();
    let gas = api
        .calculate_handle_gas(None, factory_program_id, request, 0, true)
        .await?;
    println!("GAS {:?}", gas);
    let message_id = send_request!(api: &api, program_id: factory_program_id, service_name: "PokerFactory", action: "CreateLobby", payload: (config, pks[0].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());

    Ok(())
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct LobbyConfig {
    admin_id: ActorId,
    admin_name: String,
    lobby_name: String,
    small_blind: u128,
    big_blind: u128,
    number_of_participants: u16,
    starting_bank: u128,
    time_per_move_ms: u64,
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct Config {
    pub lobby_code_id: CodeId,
    pub gas_for_program: u64,
    pub gas_for_reply_deposit: u64,
}

pub fn init_deck_and_card_map() -> (Vec<EdwardsProjective>, HashMap<EdwardsProjective, Card>) {
    let mut encrypted_deck: Vec<EdwardsProjective> = Vec::with_capacity(52);

    let num_cards = 52;
    let base_affine = EdwardsAffine::generator();
    let base_point: EdwardsProjective = base_affine.into();

    for i in 1..=num_cards {
        let scalar = Fr::from(i as u64);
        let point = base_point * scalar;

        encrypted_deck.push(point);
    }

    let card_map = build_card_map(encrypted_deck.clone());

    (encrypted_deck, card_map)
}

pub fn build_card_map(deck: Vec<EdwardsProjective>) -> HashMap<EdwardsProjective, Card> {
    let mut card_map = HashMap::new();

    let suits = [Suit::Hearts, Suit::Diamonds, Suit::Clubs, Suit::Spades];
    let values = 2..=14;

    let mut index = 0;
    for suit in &suits {
        for value in values.clone() {
            card_map.insert(
                deck[index],
                Card {
                    suit: suit.clone(),
                    value,
                },
            );

            index += 1;
        }
    }

    card_map
}

pub fn find_card_by_point(
    card_map: &HashMap<EdwardsProjective, Card>,
    point: &EdwardsProjective,
) -> Option<Card> {
    card_map.iter().find_map(|(p, card)| {
        if (point.x * p.z == p.x * point.z) && (point.y * p.z == p.y * point.z) {
            Some(card.clone())
        } else {
            None
        }
    })
}

pub fn deserialize_bandersnatch_coords(coords: &[Vec<u8>; 3]) -> EdwardsProjective {
    let x = Fq::from_le_bytes_mod_order(&coords[0]);
    let y = Fq::from_le_bytes_mod_order(&coords[1]);
    let z = Fq::from_le_bytes_mod_order(&coords[2]);
    let t = x * y;

    EdwardsProjective::new(x, y, t, z)
}

pub fn build_player_card_disclosure(
    data: Vec<(PublicKey, Vec<DecryptedCardWithProof>)>,
    card_map: &HashMap<EdwardsProjective, Card>,
) -> Vec<(PublicKey, Vec<(Card, VerificationVariables)>)> {
    let mut result = Vec::new();

    for (pk, decs) in data {
        let mut verified = Vec::new();

        for entry in decs {
            let point = deserialize_bandersnatch_coords(&entry.decrypted);
            let card =
                find_card_by_point(card_map, &point).expect("Card not found for decrypted point");

            verified.push((card, entry.proof));
        }

        result.push((pk, verified));
    }

    result
}

#[tokio::test]
async fn test_basic_workflow() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, pk_to_actor_id) = make_zk_actions(&api, &mut listener).await?;

    let api_0 = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");
    let api_1 = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");
    let api_2 = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());

    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Check));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(
        status,
        Status::Play {
            stage: Stage::WaitingTableCardsAfterPreFlop
        }
    );
    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    assert_eq!(stage.last_active_time, None);
    assert_eq!(stage.acted_players, vec![]);
    assert_eq!(stage.current_bet, 0);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 990);
    assert_eq!(participants[1].1.balance, 990);
    assert_eq!(participants[2].1.balance, 990);

    // decrypt table cards (first 3 cards)
    println!("decrypt 3 cards after preflop");
    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data/table_decryptions_after_preflop.json");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (_, proofs))) = entry {
            let proofs: Vec<_> = proofs[..3].to_vec();
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    // get revealed cards
    let table_cards = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "RevealedTableCards", return_type: Vec<Card>, payload: ());
    println!("table_cards after preflop: {:?}", table_cards);

    // Flop
    // check: Raise -> Raise -> Call -> Call

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Raise { bet: 50 }));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Raise { bet: 100 }));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(
        status,
        Status::Play {
            stage: Stage::WaitingTableCardsAfterFlop
        }
    );
    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    assert_eq!(stage.last_active_time, None);
    assert_eq!(stage.acted_players, vec![]);
    assert_eq!(stage.current_bet, 0);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 890);
    assert_eq!(participants[1].1.balance, 890);
    assert_eq!(participants[2].1.balance, 890);

    // decrypt table cards (4th card)
    println!("decrypt 1 card after flop");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (_, proofs))) = entry {
            let proofs: Vec<_> = proofs[3..4].to_vec();
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    // get revealed cards
    let table_cards = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "RevealedTableCards", return_type: Vec<Card>, payload: ());
    println!("table_cards after flop: {:?}", table_cards);

    all_players_check(&api, &program_id, &mut listener).await?;
    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    assert_eq!(
        status,
        Status::Play {
            stage: Stage::WaitingTableCardsAfterTurn
        }
    );

    println!("decrypt 1 card after turn");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (_, proofs))) = entry {
            let proofs: Vec<_> = proofs[4..5].to_vec();
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    // get revealed cards
    let table_cards = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "RevealedTableCards", return_type: Vec<Card>, payload: ());
    println!("table_cards after turn: {:?}", table_cards);

    all_players_check(&api, &program_id, &mut listener).await?;
    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(status, Status::WaitingForCardsToBeDisclosed);

    println!("Players reveal their cards..");

    let player_cards = load_cards_with_proofs("tests/test_data/player_decryptions.json");

    let (_, card_map) = init_deck_and_card_map();

    let hands = build_player_card_disclosure(player_cards, &card_map);

    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = hands.iter().find(|(stored_pk, _)| stored_pk == pk);

        if let Some((pk, instances)) = entry {
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "CardDisclosure", payload: (instances));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No cards found for public key: {:?}", pk);
        }
    }

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(
        status,
        Status::Finished {
            winners: vec![api_1.get_actor_id()],
            cash_prize: vec![330]
        }
    );

    Ok(())
}

async fn all_players_check(
    api: &GearApi,
    program_id: &ProgramId,
    listener: &mut EventListener,
) -> Result<()> {
    for i in 0..3 {
        let api = api
            .clone()
            .with(USERS_STR[i])
            .expect("Unable to change signer.");

        let message_id = send_request!(api: &api, program_id: *program_id, service_name: "Poker", action: "Turn", payload: (Action::Check));
        assert!(listener.message_processed(message_id).await?.succeed());
    }
    Ok(())
}

#[tokio::test]
async fn test_time_limit() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, _) = make_zk_actions(&api, &mut listener).await?;
    let time_skip = time::Duration::from_secs(60);
    sleep(time_skip);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let api = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);
    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(
        status,
        Status::Finished {
            winners: vec![api.get_actor_id()],
            cash_prize: vec![15]
        }
    );
    
    Ok(())
}

// #[tokio::test]
// async fn test_time_limit_only_one_player_stayed() -> Result<()> {
//     let api = GearApi::dev().await?;

//     let mut listener = api.subscribe().await?;
//     assert!(listener.blocks_running().await?);

//     let (program_id, _) = make_zk_actions(&api, &mut listener).await?;
//     let time_skip = time::Duration::from_secs(60);
//     sleep(time_skip);
//     let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
//     println!("stage: {:?}", stage);

//     let api = api
//         .clone()
//         .with(USERS_STR[1])
//         .expect("Unable to change signer.");
//     let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Check));
//     assert!(listener.message_processed(message_id).await?.succeed());
//     let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
//     println!("stage: {:?}", stage);
//     let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
//     println!("status: {:?}", status);
//     let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
//     println!("participants: {:?}", participants);
//     Ok(())
// }

#[tokio::test]
async fn test_registration() -> Result<()> {
    use crate::zk_loader::{
        load_encrypted_table_cards, load_partial_decrypt_proofs, load_partial_decryptions,
        load_player_secret_keys, load_shuffle_proofs,
    };
    use ark_ed_on_bls12_381_bandersnatch::Fr;
    use poker_client::PublicKey;

    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let pks = load_player_public_keys("tests/test_data/player_pks.json");
    let sks = load_player_secret_keys("tests/test_data/player_sks.json");

    let mut pk_to_actor_id: Vec<(PublicKey, Fr, ActorId, &str)> = vec![];
    let api = get_new_client(&api, USERS_STR[0]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[0].1.clone(), sks[0].1.clone(), id, USERS_STR[0]));

    // Init
    let (pts_id, program_id) = init(&api, pks[0].1.clone(), &mut listener).await?;

    // Resgiter
    println!("REGISTER");
    let mut player_name = "Alice".to_string();
    let api = get_new_client(&api, USERS_STR[1]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[1].1.clone(), sks[1].1.clone(), id, USERS_STR[1]));
    let message_id = send_request!(api: &api, program_id: pts_id, service_name: "Pts", action: "GetAccural", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Register", payload: (player_name, pks[1].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    assert_eq!(participants.len(), 2);

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "CancelRegistration", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    assert_eq!(participants.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_delete_player() -> Result<()> {
    use crate::zk_loader::{
        load_encrypted_table_cards, load_partial_decrypt_proofs, load_partial_decryptions,
        load_player_secret_keys, load_shuffle_proofs,
    };
    use ark_ed_on_bls12_381_bandersnatch::Fr;
    use poker_client::PublicKey;

    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let pks = load_player_public_keys("tests/test_data/player_pks.json");
    let sks = load_player_secret_keys("tests/test_data/player_sks.json");

    let mut pk_to_actor_id: Vec<(PublicKey, Fr, ActorId, &str)> = vec![];
    let api = get_new_client(&api, USERS_STR[0]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[0].1.clone(), sks[0].1.clone(), id, USERS_STR[0]));

    // Init
    let (pts_id, program_id) = init(&api, pks[0].1.clone(), &mut listener).await?;

    // Resgiter
    println!("REGISTER");
    let mut player_name = "Alice".to_string();
    let api = get_new_client(&api, USERS_STR[1]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[1].1.clone(), sks[1].1.clone(), id, USERS_STR[1]));
    let message_id = send_request!(api: &api, program_id: pts_id, service_name: "Pts", action: "GetAccural", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Register", payload: (player_name, pks[1].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    assert_eq!(participants.len(), 2);

    let player_to_delete = api.get_actor_id();
    let api = get_new_client(&api, USERS_STR[0]).await;
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "DeletePlayer", payload: (player_to_delete));
    assert!(listener.message_processed(message_id).await?.succeed());
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    assert_eq!(participants.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_all_in_case_1() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, pk_to_actor_id) = make_zk_actions(&api, &mut listener).await?;

    let api_0 = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");
    let api_1 = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");
    let api_2 = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());

    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);

    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 0);
    assert_eq!(participants[1].1.balance, 0);
    assert_eq!(participants[2].1.balance, 0);

    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data/table_decryptions_after_preflop.json");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (_, proofs))) = entry {
            let proofs: Vec<_> = proofs[..5].to_vec();
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    // get revealed cards
    let table_cards = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "RevealedTableCards", return_type: Vec<Card>, payload: ());

    println!(" revealed table_cards: {:?}", table_cards);

    println!("Players reveal their cards..");

    reveal_player_cards(program_id, &api, &mut listener, pk_to_actor_id).await?;

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);

    assert_eq!(
        status,
        Status::Finished {
            winners: vec![api_1.get_actor_id()],
            cash_prize: vec![3000]
        }
    );

    Ok(())
}

#[tokio::test]
async fn test_all_in_case_2() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, pk_to_actor_id) = make_zk_actions(&api, &mut listener).await?;

    let api_0 = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");
    let api_1 = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");
    let api_2 = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());

    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Check));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(
        status,
        Status::Play {
            stage: Stage::WaitingTableCardsAfterPreFlop
        }
    );
    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    assert_eq!(stage.last_active_time, None);
    assert_eq!(stage.acted_players, vec![]);
    assert_eq!(stage.current_bet, 0);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 990);
    assert_eq!(participants[1].1.balance, 990);
    assert_eq!(participants[2].1.balance, 990);

    // decrypt table cards (first 3 cards)
    println!("decrypt 3 cards after preflop");
    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data/table_decryptions_after_preflop.json");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (_, proofs))) = entry {
            let proofs: Vec<_> = proofs[..3].to_vec();
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    // get revealed cards
    let table_cards = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "RevealedTableCards", return_type: Vec<Card>, payload: ());
    println!("table_cards after preflop: {:?}", table_cards);

    // Flop
    // check: Raise -> Raise -> Call -> Call

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Raise { bet: 50 }));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Raise { bet: 100 }));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);

    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 0);
    assert_eq!(participants[1].1.balance, 0);
    assert_eq!(participants[2].1.balance, 0);

    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data/table_decryptions_after_preflop.json");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (_, proofs))) = entry {
            let proofs: Vec<_> = proofs[3..5].to_vec();
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    // get revealed cards
    let table_cards = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "RevealedTableCards", return_type: Vec<Card>, payload: ());

    println!(" revealed table_cards: {:?}", table_cards);

    println!("Players reveal their cards..");

    reveal_player_cards(program_id, &api, &mut listener, pk_to_actor_id).await?;

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);

    assert_eq!(
        status,
        Status::Finished {
            winners: vec![api_1.get_actor_id()],
            cash_prize: vec![3000]
        }
    );

    Ok(())
}

#[tokio::test]
async fn test_restart_and_all_in_case() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, pk_to_actor_id) = make_zk_actions(&api, &mut listener).await?;

    let api_0 = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");
    let api_1 = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");
    let api_2 = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Fold));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Fold));
    assert!(listener.message_processed(message_id).await?.succeed());

    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);

    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 995);
    assert_eq!(participants[1].1.balance, 1005);
    assert_eq!(participants[2].1.balance, 1000);

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "RestartGame", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    let proofs = load_shuffle_proofs("tests/test_data/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data/encrypted_deck.json");
    let decrypt_proofs = load_partial_decrypt_proofs("tests/test_data/partial_decrypt_proofs.json");
    let pk_cards = load_partial_decryptions("tests/test_data/partial_decryptions.json");

    // Shuffle deck
    println!("SHUFFLE");
    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "ShuffleDeck", payload: (deck, proofs));
    assert!(listener.message_processed(message_id).await?.succeed());

    // Start game
    println!("START");
    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "StartGame", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    // Verify partial decryptions
    let cards_by_actor: Vec<(ActorId, [EncryptedCard; 2])> = pk_cards
        .into_iter()
        .map(|(pk, cards)| {
            let id = pk_to_actor_id
                .iter()
                .find(|(pk1, _, _, _)| pk1 == &pk)
                .map(|(_, _, id, _)| *id)
                .expect("PublicKey not found");
            (id, cards)
        })
        .collect();

    println!("DECRYPT");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitAllPartialDecryptions", payload: (decrypt_proofs));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());

    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::AllIn));
    assert!(listener.message_processed(message_id).await?.succeed());

    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_1, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);

    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ()).unwrap();
    println!("stage: {:?}", stage);

    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 0);
    assert_eq!(participants[1].1.balance, 5);
    assert_eq!(participants[2].1.balance, 0);


    Ok(())
}

#[tokio::test]
async fn test_cancel_game() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, pk_to_actor_id) = make_zk_actions(&api, &mut listener).await?;

    let api_0 = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");
    let api_1 = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");
    let api_2 = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api_2, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Fold));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let message_id = send_request!(api: &api_0, program_id: program_id, service_name: "Poker", action: "CancelGame", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    assert_eq!(status, Status::WaitingShuffleVerification);
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    assert_eq!(participants[0].1.balance, 1000);
    assert_eq!(participants[1].1.balance, 1000);
    assert_eq!(participants[2].1.balance, 1000);

    Ok(())
}


async fn reveal_player_cards(
    program_id: ProgramId,
    api: &GearApi,
    listener: &mut EventListener,
    pk_to_actor_id: Vec<(PublicKey, Fr, ActorId, &'static str)>,
) -> Result<()> {
    let player_cards = load_cards_with_proofs("tests/test_data/player_decryptions.json");

    let (_, card_map) = init_deck_and_card_map();

    let hands = build_player_card_disclosure(player_cards, &card_map);

    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = hands.iter().find(|(stored_pk, _)| stored_pk == pk);

        if let Some((pk, instances)) = entry {
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "CardDisclosure", payload: (instances));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No cards found for public key: {:?}", pk);
        }
    }
    Ok(())
}
