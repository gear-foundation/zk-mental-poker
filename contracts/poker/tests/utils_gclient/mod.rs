use crate::send_request;
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gear_core::ids::{MessageId, ProgramId};
use poker_client::{Card, Config, EncryptedCard, PublicKey, Status, Suit, traits::*};
use sails_rs::{ActorId, Encode};
pub mod zk_loader;
use zk_loader::{
    get_vkey, load_encrypted_table_cards, load_partial_decrypt_proofs, load_partial_decryptions,
    load_player_public_keys, load_shuffle_proofs,
};
pub const USERS_STR: &[&str] = &["//John", "//Mike", "//Dan"];

pub trait ApiUtils {
    fn get_actor_id(&self) -> ActorId;
    fn get_specific_actor_id(&self, value: impl AsRef<str>) -> ActorId;
}

impl ApiUtils for GearApi {
    fn get_actor_id(&self) -> ActorId {
        ActorId::new(
            self.account_id()
                .encode()
                .try_into()
                .expect("Unexpected invalid account id length."),
        )
    }
    fn get_specific_actor_id(&self, value: impl AsRef<str>) -> ActorId {
        let api_temp = self
            .clone()
            .with(value)
            .expect("Unable to build `GearApi` instance with provided signer.");
        api_temp.get_actor_id()
    }
}

pub async fn get_new_client(api: &GearApi, name: &str) -> GearApi {
    let alice_balance = api
        .total_balance(api.account_id())
        .await
        .expect("Error total balance");
    let amount = alice_balance / 10;
    api.transfer_keep_alive(
        api.get_specific_actor_id(name)
            .encode()
            .as_slice()
            .try_into()
            .expect("Unexpected invalid `ProgramId`."),
        amount,
    )
    .await
    .expect("Error transfer");

    api.clone().with(name).expect("Unable to change signer.")
}

pub async fn init(
    api: &GearApi,
    pk: PublicKey,
    listener: &mut EventListener,
) -> Result<(ProgramId, ProgramId)> {
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

    // POKER
    let config = Config {
        admin_id: api.get_actor_id(),
        admin_name: "Name".to_string(),
        lobby_name: "Lobby".to_string(),
        small_blind: 10,
        big_blind: 100,
        number_of_participants: 3,
        starting_bank: 10,
    };
    let pts_id_bytes: [u8; 32] = pts_program_id.into();
    let pts_id: ActorId = pts_id_bytes.into();
    let shuffle_vkey = get_vkey("tests/test_data/shuffle_vkey.json");
    let decrypt_vkey = get_vkey("tests/test_data/decrypt_vkey.json");
    let constructor = (config, pts_id, pk, shuffle_vkey, decrypt_vkey);
    let request = ["New".encode(), constructor.encode()].concat();

    let path = "./target/wasm32-gear/release/poker.opt.wasm";

    let (message_id, program_id, _hash) = api
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

    let poker_id_bytes: [u8; 32] = program_id.into();
    let poker_id: ActorId = poker_id_bytes.into();

    // add poker to admins in pts
    let message_id = send_request!(api: &api, program_id: pts_program_id, service_name: "Pts", action: "AddAdmin", payload: (poker_id));
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api, program_id: pts_program_id, service_name: "Pts", action: "GetAccural", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    Ok((pts_program_id, program_id))
}

pub async fn make_zk_actions(api: &GearApi, listener: &mut EventListener) -> Result<()> {
    let pks = load_player_public_keys("tests/test_data/player_pks.json");
    let proofs = load_shuffle_proofs("tests/test_data/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data/encrypted_deck.json");

    let decrypt_proofs = load_partial_decrypt_proofs("tests/test_data/partial_decrypt_proofs.json");
    let pk_cards = load_partial_decryptions("tests/test_data/partial_decryptions.json");

    let mut pk_to_actor_id: Vec<(PublicKey, ActorId)> = vec![];
    let api = get_new_client(&api, USERS_STR[0]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[0].1.clone(), id));

    // Init
    let (pts_id, program_id) = init(&api, pks[0].1.clone(), listener).await?;

    // Resgiter
    println!("REGISTER");
    let mut player_name = "Alice".to_string();
    let api = get_new_client(&api, USERS_STR[1]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[1].1.clone(), id));
    let message_id = send_request!(api: &api, program_id: pts_id, service_name: "Pts", action: "GetAccural", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Register", payload: (player_name, pks[1].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());

    player_name = "Bob".to_string();
    let api = get_new_client(&api, USERS_STR[2]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[2].1.clone(), id));

    let message_id = send_request!(api: &api, program_id: pts_id, service_name: "Pts", action: "GetAccural", payload: ());
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "Register", payload: (player_name, pks[2].1.clone()));
    assert!(listener.message_processed(message_id).await?.succeed());

    // Shuffle deck
    println!("SHUFFLE");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "ShuffleDeck", payload: (deck, proofs));
    assert!(listener.message_processed(message_id).await?.succeed());

    // Start game
    println!("START");
    let api = api
        .clone()
        .with(USERS_STR[0])
        .expect("Unable to change signer.");
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
    assert!(listener.message_processed(message_id).await?.succeed());
    Ok(())
}
#[macro_export]
macro_rules! send_request {
    (api: $api:expr, program_id: $program_id:expr, service_name: $name:literal, action: $action:literal, payload: ($($val:expr),*)) => {
        $crate::send_request!(api: $api, program_id: $program_id, service_name: $name, action: $action, payload: ($($val),*), value: 0)
    };

    (api: $api:expr, program_id: $program_id:expr, service_name: $name:literal, action: $action:literal, payload: ($($val:expr),*), value: $value:expr) => {
        {
            let request = [
                $name.encode(),
                $action.to_string().encode(),
                ($($val),*).encode(),
            ].concat();

            let (message_id, _) = $api
                .send_message_bytes($program_id, request.clone(), 749_000_000_000, $value)
                .await?;

            message_id
        }
    };
}

#[macro_export]
macro_rules! get_state {

    (api: $api:expr, listener: $listener:expr, program_id: $program_id:expr, service_name: $name:literal, action: $action:literal, return_type: $return_type:ty, payload: ($($val:expr),*)) => {
        {
            let request = [
                $name.encode(),
                $action.to_string().encode(),
                ($($val),*).encode(),
            ].concat();

            let gas_info = $api
                .calculate_handle_gas(None, $program_id, request.clone(), 0, true)
                .await
                .expect("Error send message bytes");

            let (message_id, _) = $api
                .send_message_bytes($program_id, request.clone(), gas_info.min_limit, 0)
                .await
                .expect("Error listen reply");

            let (_, raw_reply, _) = $listener
                .reply_bytes_on(message_id)
                .await
                .expect("Error listen reply");

            let decoded_reply = <(String, String, $return_type)>::decode(&mut raw_reply.unwrap().as_slice()).expect("Erroe decode reply");
            decoded_reply.2
        }
    };
}
