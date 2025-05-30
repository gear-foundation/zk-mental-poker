use crate::{get_state, send_request};
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gear_core::ids::{MessageId, ProgramId};
use poker_client::{Card, Config, EncryptedCard, PublicKey, Status, Suit, traits::*};
use sails_rs::{ActorId, Encode};
pub mod zk_loader;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInt, PrimeField};
use num_bigint::BigUint;
use sails_rs::Decode;
use sails_rs::collections::HashMap;
use zk_loader::{
    get_vkey, load_encrypted_table_cards, load_partial_decrypt_proofs, load_partial_decryptions,
    load_player_public_keys, load_player_secret_keys, load_shuffle_proofs,
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
        time_per_move_ms: 10_000_000,
        admin_id: api.get_actor_id(),
        admin_name: "Name".to_string(),
        lobby_name: "Lobby".to_string(),
        small_blind: 5,
        big_blind: 10,
        number_of_participants: 3,
        starting_bank: 1000,
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

pub async fn make_zk_actions(
    api: &GearApi,
    listener: &mut EventListener,
) -> Result<(ProgramId, Vec<(PublicKey, Fr, ActorId, &'static str)>)> {
    let pks = load_player_public_keys("tests/test_data/player_pks.json");
    let sks = load_player_secret_keys("tests/test_data/player_sks.json");
    let proofs = load_shuffle_proofs("tests/test_data/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data/encrypted_deck.json");

    let decrypt_proofs = load_partial_decrypt_proofs("tests/test_data/partial_decrypt_proofs.json");
    let pk_cards = load_partial_decryptions("tests/test_data/partial_decryptions.json");

    let mut pk_to_actor_id: Vec<(PublicKey, Fr, ActorId, &str)> = vec![];
    let api = get_new_client(&api, USERS_STR[0]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[0].1.clone(), sks[0].1.clone(), id, USERS_STR[0]));

    // Init
    let (pts_id, program_id) = init(&api, pks[0].1.clone(), listener).await?;

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

    player_name = "Bob".to_string();
    let api = get_new_client(&api, USERS_STR[2]).await;
    let id = api.get_actor_id();
    pk_to_actor_id.push((pks[2].1.clone(), sks[2].1.clone(), id, USERS_STR[2]));

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
                .find(|(pk1, _, _, _)| pk1 == &pk)
                .map(|(_, _, id, _)| *id)
                .expect("PublicKey not found");
            (id, cards)
        })
        .collect();

    println!("DECRYPT");
    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "SubmitAllPartialDecryptions", payload: (cards_by_actor, decrypt_proofs));
    assert!(listener.message_processed(message_id).await?.succeed());

    // let card_map = init_deck_and_card_map();
    // for (_, sk, id) in pk_to_actor_id.iter() {
    //     let result = get_state!(api: &api, listener: listener, program_id: program_id, service_name: "Poker", action: "PlayerCards", return_type: Option<[EncryptedCard; 2]>, payload: (id));
    //     let encrypted_cards = result.unwrap();

    //     for card in encrypted_cards {
    //         let c0_point = deserialize_bandersnatch_coords(&card.c0);
    //         let c1_point = deserialize_bandersnatch_coords(&card.c1);

    //         let sk_c0 = c0_point * sk;
    //         let decrypted_point = c1_point - sk_c0;
    //         println!("card {:?}", find_card_by_point(&card_map, &decrypted_point));
    //     }
    // }
    Ok((program_id, pk_to_actor_id))
}

fn deserialize_bandersnatch_coords(coords: &[Vec<u8>; 3]) -> EdwardsProjective {
    let x = Fq::from_be_bytes_mod_order(&coords[0]);
    let y = Fq::from_be_bytes_mod_order(&coords[1]);
    let z = Fq::from_be_bytes_mod_order(&coords[2]);
    let t = x * y;
    EdwardsProjective::new(x, y, t, z)
}

pub fn init_deck_and_card_map() -> HashMap<EdwardsProjective, Card> {
    let mut points_for_map = vec![vec![]; 3];

    let num_cards = 52;
    let base_affine = EdwardsAffine::generator();
    let base_point: EdwardsProjective = base_affine.into();

    for i in 1..=num_cards {
        let scalar = Fr::from(i as u64);
        let point = base_point * scalar;

        // Save point coordinates for map building
        points_for_map[0].push(point.x.into_bigint());
        points_for_map[1].push(point.y.into_bigint());
        points_for_map[2].push(point.z.into_bigint());
    }

    let card_map = build_card_map(points_for_map).expect("Invalid deck format");
    card_map
}

pub fn build_card_map(
    deck: Vec<Vec<BigInt<4>>>,
) -> Result<HashMap<EdwardsProjective, Card>, String> {
    let num_cards = 52;

    if deck.len() != 3 || deck[0].len() != num_cards {
        return Err("Invalid deck shape".to_string());
    }

    let mut card_map = HashMap::new();

    let suits = [Suit::Hearts, Suit::Diamonds, Suit::Clubs, Suit::Spades];
    let values = 2..=14;

    let mut index = 0;
    for suit in &suits {
        for value in values.clone() {
            let x = Fq::from_bigint(deck[0][index].clone()).expect("invalid x");
            let y = Fq::from_bigint(deck[1][index].clone()).expect("invalid y");
            let z = Fq::from_bigint(deck[2][index].clone()).expect("invalid z");

            let point = EdwardsProjective::new(x, y, x * y, z); // t = x * y
            card_map.insert(
                point,
                Card {
                    suit: suit.clone(),
                    value,
                },
            );

            index += 1;
        }
    }

    Ok(card_map)
}

pub fn find_card_by_point(
    card_map: &HashMap<EdwardsProjective, Card>,
    point: &EdwardsProjective,
) -> Option<Card> {
    let affine = point.into_affine();
    card_map.iter().find_map(|(p, card)| {
        if p.into_affine() == affine {
            Some(card.clone())
        } else {
            None
        }
    })
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
