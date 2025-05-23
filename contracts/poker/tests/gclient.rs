use std::{thread::sleep, time};

use gclient::{GearApi, Result};
use sails_rs::{ActorId, Decode, Encode};
mod utils_gclient;
use crate::zk_loader::{get_vkey, load_player_public_keys, load_table_cards_proofs};
use gclient::EventProcessor;
use poker_client::{Action, BettingStage, Participant, Status};
use sails_rs::CodeId;
use sails_rs::TypeInfo;
use utils_gclient::*;
#[tokio::test]
async fn upload_contracts_to_testnet() -> Result<()> {
    let pks = load_player_public_keys("tests/test_data/player_pks.json");
    let api = GearApi::vara_testnet().await?;
    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    // PTS
    let path = "../pts/target/wasm32-gear/release/pts.opt.wasm";
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

    let lobby_code_id: CodeId =
        hex_literal::hex!("d11a80c81de9d1ad5a721a5dad3ba6af4eb01d5f66702e78f103881e256ab9bf")
            .into();

    println!("CodeId {:?}", lobby_code_id);
    // // Poker
    let path = "./target/wasm32-gear/release/poker.opt.wasm";
    let config = LobbyConfig {
        admin_id: api.get_actor_id(),
        admin_name: "Name".to_string(),
        lobby_name: "Lobby".to_string(),
        small_blind: 5,
        big_blind: 10,
        number_of_participants: 3,
        starting_bank: 1000,
    };
    let constructor = (config, pts_id, pks[0].1.clone(), shuffle_vkey, decrypt_vkey);
    let request = ["New".encode(), constructor.encode()].concat();

    let (message_id, program_id, hash) = api
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
    println!("poker_id {:?}", program_id);

    // // Factory

    // let path = "../poker_factory/target/wasm32-gear/release/poker_factory.opt.wasm";
    // let config = Config {
    //     lobby_code_id,
    //     gas_for_program: 200_000_000_000,
    //     gas_for_reply_deposit: 10_000_000_000,
    // };
    // let request = [
    //     "New".encode(),
    //     (config, pts_id, shuffle_vkey, decrypt_vkey).encode(),
    // ]
    // .concat();

    // let (message_id, factory_program_id, _hash) = api
    //     .upload_program_bytes(
    //         gclient::code_from_os(path).unwrap(),
    //         gclient::now_micros().to_le_bytes(),
    //         request,
    //         740_000_000_000,
    //         0,
    //     )
    //     .await
    //     .expect("Error upload program bytes");
    // assert!(listener.message_processed(message_id).await?.succeed());

    // println!("factory_id {:?}", factory_program_id);

    // // make admin in PTS
    // println!("add admin");
    // let factory_id_bytes: [u8; 32] = factory_program_id.into();
    // let factory_id: ActorId = factory_id_bytes.into();
    // let message_id = send_request!(api: &api, program_id: pts_program_id, service_name: "Pts", action: "AddAdmin", payload: (factory_id));
    // assert!(listener.message_processed(message_id).await?.succeed());

    // // mint tokens in PTS
    // println!("mint tokens");
    // let message_id = send_request!(api: &api, program_id: pts_program_id, service_name: "Pts", action: "GetAccural", payload: ());
    // assert!(listener.message_processed(message_id).await?.succeed());

    // // create lobby
    // println!("create lobby");
    // let config = LobbyConfig {
    //     admin_id: api.get_actor_id(),
    //     admin_name: "Name".to_string(),
    //     lobby_name: "Lobby".to_string(),
    //     small_blind: 5,
    //     big_blind: 10,
    //     number_of_participants: 3,
    //     starting_bank: 1000,
    // };
    // let message_id = send_request!(api: &api, program_id: factory_program_id, service_name: "PokerFactory", action: "CreateLobby", payload: (config, pks[0].1.clone()));
    // assert!(listener.message_processed(message_id).await?.succeed());

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
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct Config {
    pub lobby_code_id: CodeId,
    pub gas_for_program: u64,
    pub gas_for_reply_deposit: u64,
}
#[tokio::test]
async fn test_basic_function() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, pk_to_actor_id) = make_zk_actions(&api, &mut listener).await?;

    // let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    // println!("status: {:?}", status);
    // let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    // println!("bank: {:?}", bank);
    // let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    // println!("stage: {:?}", stage);
    // let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    // println!("participants: {:?}", participants);

    let api = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);
    let api = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);
    let api = api
        .clone()
        .with(USERS_STR[1])
        .expect("Unable to change signer.");

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Check));
    assert!(listener.message_processed(message_id).await?.succeed());

    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    let bank = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "BettingBank", return_type: Vec<(ActorId, u128)>, payload: ());
    println!("bank: {:?}", bank);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);

    // decrypt table cards
    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data/table_decryptions_after_preflop.json");
    for (pk, _, _, name) in pk_to_actor_id.iter() {
        let entry = table_cards_proofs
            .iter()
            .find(|(stored_pk, _)| stored_pk == pk);

        if let Some((_, (decryptions, proofs))) = entry {
            let api = api.clone().with(name).expect("Unable to change signer.");
            let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitTablePartialDecryptions", payload: (decryptions, proofs));
            assert!(listener.message_processed(message_id).await?.succeed());
        } else {
            panic!("No decryptions found for public key: {:?}", pk);
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_time_limit() -> Result<()> {
    let api = GearApi::dev().await?;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    let (program_id, _) = make_zk_actions(&api, &mut listener).await?;
    let time_skip = time::Duration::from_secs(90);
    sleep(time_skip);
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);

    let api = api
        .clone()
        .with(USERS_STR[2])
        .expect("Unable to change signer.");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Call));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    assert_eq!(stage, None::<BettingStage>);
    println!("stage: {:?}", stage);
    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    assert_eq!(
        status,
        Status::Finished {
            winners: vec![],
            cash_prize: vec![]
        }
    );
    println!("status: {:?}", status);
    Ok(())
}

#[tokio::test]
async fn test_time_limit_only_one_player_stayed() -> Result<()> {
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
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Turn", payload: (Action::Check));
    assert!(listener.message_processed(message_id).await?.succeed());
    let stage = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Betting", return_type: Option<BettingStage>, payload: ());
    println!("stage: {:?}", stage);
    let status = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Status", return_type: Status, payload: ());
    println!("status: {:?}", status);
    let participants = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "Participants", return_type:  Vec<(ActorId, Participant)>, payload: ());
    println!("participants: {:?}", participants);
    Ok(())
}
