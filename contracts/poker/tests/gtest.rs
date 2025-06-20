use gclient::metadata::runtime_types::gear_core::program;
use gtest::Program;
use gtest::WasmProgram;
use hex_literal::hex;
use poker_app::services::verify::VerifyingKey;
use poker_app::services::VerifyingKeyBytes;
use poker_client::{traits::*, Card, Config, Status, Suit};
use pts_client::traits::{Pts, PtsFactory};
use sails_rs::ActorId;
use sails_rs::{
    calls::*,
    gtest::{calls::*, System},
};
mod utils_gclient;
use utils_gclient::{build_player_card_disclosure, init_deck_and_card_map};
use utils_gclient::zk_loader::{
    get_vkey, load_cards_with_proofs, load_encrypted_table_cards, load_partial_decrypt_proofs,
    load_player_public_keys, load_shuffle_proofs, load_table_cards_proofs,
};

const USERS: [u64; 6] = [42, 43, 44, 45, 46, 47];

const BUILTIN_BLS381: ActorId = ActorId::new(hex!(
    "6b6e292c382945e80bf51af2ba7fe9f458dcff81ae6075c46f9095e1bbecdc37"
));

use gbuiltin_bls381::{
    ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2},
    ark_ec::{
        pairing::{MillerLoopOutput, Pairing},
        AffineRepr, CurveGroup, Group, VariableBaseMSM,
    },
    ark_ff::Field,
    ark_scale,
    ark_scale::hazmat::ArkScaleProjective,
    ark_serialize::CanonicalDeserialize,
    Request, Response,
};

use gstd::prelude::*;
type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;
type Gt = <Bls12_381 as Pairing>::TargetField;

type Bases = Vec<u8>;
type Scalars = Vec<u8>;
type MsmOut = Vec<u8>;
#[derive(Debug)]
struct BlsBuiltinMock {
    pub msm: Vec<((Bases, Scalars), MsmOut)>,
}
impl WasmProgram for BlsBuiltinMock {
    fn init(&mut self, payload: Vec<u8>) -> Result<Option<Vec<u8>>, &'static str> {
        Ok(Some(vec![]))
    }

    fn handle(&mut self, payload: Vec<u8>) -> Result<Option<Vec<u8>>, &'static str> {
        let request = Request::decode(&mut payload.as_slice()).expect("Unable to decode payload");
        let result = match request {
            Request::MultiMillerLoop { a, b } => {
                let points_g1 = ArkScale::<Vec<G1Affine>>::decode(&mut a.as_slice())
                    .expect("Unable to decode to Vec<G1>");
                let points_g2 = ArkScale::<Vec<G2Affine>>::decode(&mut b.as_slice())
                    .expect("Unable to decode to Vec<G2>");

                let miller_result: ArkScale<Gt> =
                    Bls12_381::multi_miller_loop(&points_g1.0, &points_g2.0)
                        .0
                        .into();
                Response::MultiMillerLoop(miller_result.encode()).encode()
            }
            Request::FinalExponentiation { f } => {
                let f = ArkScale::<Gt>::decode(&mut f.as_slice()).expect("Unable to decode to Gt");
                let exp_result: ArkScale<Gt> =
                    Bls12_381::final_exponentiation(MillerLoopOutput(f.0))
                        .unwrap()
                        .0
                        .into();
                Response::FinalExponentiation(exp_result.encode()).encode()
            }
            Request::MultiScalarMultiplicationG1 { bases, scalars } => {
                let bases = ArkScale::<Vec<G1Affine>>::decode(&mut bases.as_slice())
                    .expect("Unable to decode to Vec<G1>");
                let scalars =
                    ArkScale::<Vec<<G1 as Group>::ScalarField>>::decode(&mut scalars.as_slice())
                        .expect("Unable to decode to Vec<G2>");
                let result: ArkScaleProjective<G1> = G1::msm(&bases.0, &scalars.0).unwrap().into();
                Response::MultiScalarMultiplicationG1(result.encode()).encode()
            }
            _ => unreachable!(),
        };
        Ok(Some(result))
    }

    fn handle_reply(&mut self, payload: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }
    /// Signal handler with given `payload`.
    fn handle_signal(&mut self, payload: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }
    /// State of wasm program.
    ///
    /// See [`Program::read_state`] for the usage.
    fn state(&mut self) -> Result<Vec<u8>, &'static str> {
        Ok(vec![])
    }

    fn debug(&mut self, data: &str) {}
}

async fn check_status(
    service_client: &mut poker_client::Poker<GTestRemoting>,
    program_id: ActorId,
    expected_status: Status,
) {
    let result = service_client.status().recv(program_id).await.unwrap();
    assert_eq!(result, expected_status);
}

#[tokio::test]
async fn gtest_basic_workflow() {
    let system = System::new();
    system.init_logger();
    for i in 0..USERS.len() {
        system.mint_to(USERS[i], 1_000_000_000_000_000);
    }

    let builtin_mock = BlsBuiltinMock { msm: Vec::new() };
    let builtin_program = Program::mock_with_id(&system, BUILTIN_BLS381, builtin_mock);

    let init_message_id = builtin_program.send_bytes(USERS[0], b"Doesn't matter");
    let block_run_result = system.run_next_block();
    assert!(block_run_result.succeed.contains(&init_message_id));

    let remoting = GTestRemoting::new(system, USERS[0].into());
    let pks = load_player_public_keys("tests/test_data_gtest/player_pks.json");

    let shuffle_vkey_bytes = get_vkey("tests/test_data/shuffle_vkey.json");
    let decrypt_vkey_bytes = get_vkey("tests/test_data/decrypt_vkey.json");

    // Upload pts
    let pts_code_id = remoting.system().submit_code(pts::WASM_BINARY);
    let pts_factory = pts_client::PtsFactory::new(remoting.clone());
    let accural: u128 = 10_000;
    let time_ms_between_balance_receipt: u64 = 10_000;
    let pts_id = pts_factory
        .new(accural, time_ms_between_balance_receipt)
        .send_recv(pts_code_id, b"salt")
        .await
        .unwrap();

    let mut pts_service_client = pts_client::Pts::new(remoting.clone());
    for i in 0..USERS.len() {
        pts_service_client
            .get_accural()
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(pts_id)
            .await
            .unwrap();
    }
    for i in 0..USERS.len() {
        let balance = pts_service_client
            .get_balance(USERS[i].into())
            .recv(pts_id)
            .await
            .unwrap();

        assert_eq!(balance, accural);
    }
    // Submit program code into the system
    let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);

    let program_factory = poker_client::PokerFactory::new(remoting.clone());

    let program_id = program_factory
        .new(
            Config {
                admin_id: USERS[0].into(),
                admin_name: "Player_1".to_string(),
                lobby_name: "Lobby name".to_string(),
                small_blind: 5,
                big_blind: 10,
                starting_bank: 1000,
                time_per_move_ms: 30_000,
            },
            pts_id,
            pks[0].1.clone(),
            shuffle_vkey_bytes,
            decrypt_vkey_bytes,
        )
        .send_recv(program_code_id, b"salt")
        .await
        .unwrap();

    pts_service_client
        .add_admin(program_id)
        .send_recv(pts_id)
        .await
        .unwrap();
    let mut service_client = poker_client::Poker::new(remoting.clone());

    // REGISTER
    println!("REGISTER");

    for i in 1..USERS.len() {
        service_client
            .register("Player".to_string(), pks[i].1.clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();

        let balance = pts_service_client
            .get_balance(USERS[i].into())
            .recv(pts_id)
            .await
            .unwrap();

        assert_eq!(balance, accural - 1000);
    }

    // start game
    println!("START GAME");
    service_client
        .start_game()
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::WaitingShuffleVerification,
    )
    .await;

    // Shuffle deck
    println!("SHUFFLE");
    let proofs = load_shuffle_proofs("tests/test_data_gtest/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data_gtest/encrypted_deck.json");
    service_client
        .shuffle_deck(deck, proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::WaitingPartialDecryptionsForPlayersCards,
    )
    .await;

    println!("DECRYPT");
    let decrypt_proofs =
        load_partial_decrypt_proofs("tests/test_data_gtest/partial_decrypt_proofs.json");
    service_client
        .submit_all_partial_decryptions(decrypt_proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::PreFlop,
        },
    )
    .await;

    // Game logic
    let players_amount = USERS.len();
    for i in 2..players_amount {
        service_client
            .turn(poker_client::Action::Call)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }
    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Check)
        .with_args(GTestArgs::new(USERS[1].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::WaitingTableCardsAfterPreFlop,
        },
    )
    .await;

    println!("Decrypt 3 cards after preflop");
    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data_gtest/table_decryptions.json");
    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[..3].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::Flop,
        },
    )
    .await;

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    // game logic
    let actions = vec![
        poker_client::Action::Raise { bet: 50 },  // player 0
        poker_client::Action::Raise { bet: 100 }, // player 1
        poker_client::Action::Call,               // player 2
        poker_client::Action::Call,               // player 3
        poker_client::Action::Call,               // player 4
        poker_client::Action::Call,               // player 5
    ];
    for i in 0..players_amount {
        service_client
            .turn(actions[i].clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::WaitingTableCardsAfterFlop,
        },
    )
    .await;

    println!("Decrypt 1 cards after flop");

    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[3..4].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::Turn,
        },
    )
    .await;

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    for i in 0..players_amount {
        service_client
            .turn(poker_client::Action::Check)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::WaitingTableCardsAfterTurn,
        },
    )
    .await;

    println!("Decrypt 1 cards after turn");

    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[4..5].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::River,
        },
    )
    .await;

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    println!("Players reveal their cards..");
    let player_cards = load_cards_with_proofs("tests/test_data_gtest/player_decryptions.json");
    let (_, card_map) = init_deck_and_card_map();
    let hands = build_player_card_disclosure(player_cards, &card_map);
    
    for i in 0..USERS.len() {
        let proofs = hands[i].1.clone();
        service_client
            .card_disclosure(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }
    let result = service_client.status().recv(program_id).await.unwrap();
    println!("result {:?}", result);
    if !matches!(result, Status::Finished {..}) {
        assert!(true, "Wrong Status!");
    }
    let participants = service_client.participants().recv(program_id).await.unwrap();
    if let Status::Finished {winners, cash_prize} = result {
        for (winner, prize) in winners.iter().zip(cash_prize) {
            participants.iter().map(|(id, info)| {
                if winner == id {
                    if info.balance != 1000 - 10 - 100 + prize {
                        assert!(true, "Wrong balance!");
                    } 
                } else {
                    if info.balance != 1000 - 10 - 100 {
                        assert!(true, "Wrong balance!");
                    } 
                }
            });
        }
    }
    println!("participants {:?}", participants);
}



#[tokio::test]
async fn gtest_check_null_balance() {
    let system = System::new();
    system.init_logger();
    for i in 0..USERS.len() {
        system.mint_to(USERS[i], 1_000_000_000_000_000);
    }

    let builtin_mock = BlsBuiltinMock { msm: Vec::new() };
    let builtin_program = Program::mock_with_id(&system, BUILTIN_BLS381, builtin_mock);

    let init_message_id = builtin_program.send_bytes(USERS[0], b"Doesn't matter");
    let block_run_result = system.run_next_block();
    assert!(block_run_result.succeed.contains(&init_message_id));

    let remoting = GTestRemoting::new(system, USERS[0].into());
    let pks = load_player_public_keys("tests/test_data_gtest/player_pks.json");

    let shuffle_vkey_bytes = get_vkey("tests/test_data/shuffle_vkey.json");
    let decrypt_vkey_bytes = get_vkey("tests/test_data/decrypt_vkey.json");

    // Upload pts
    let pts_code_id = remoting.system().submit_code(pts::WASM_BINARY);
    let pts_factory = pts_client::PtsFactory::new(remoting.clone());
    let accural: u128 = 10_000;
    let time_ms_between_balance_receipt: u64 = 10_000;
    let pts_id = pts_factory
        .new(accural, time_ms_between_balance_receipt)
        .send_recv(pts_code_id, b"salt")
        .await
        .unwrap();

    let mut pts_service_client = pts_client::Pts::new(remoting.clone());
    for i in 0..USERS.len() {
        pts_service_client
            .get_accural()
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(pts_id)
            .await
            .unwrap();
    }
    for i in 0..USERS.len() {
        let balance = pts_service_client
            .get_balance(USERS[i].into())
            .recv(pts_id)
            .await
            .unwrap();

        assert_eq!(balance, accural);
    }
    // Submit program code into the system
    let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);

    let program_factory = poker_client::PokerFactory::new(remoting.clone());

    let program_id = program_factory
        .new(
            Config {
                admin_id: USERS[0].into(),
                admin_name: "Player_1".to_string(),
                lobby_name: "Lobby name".to_string(),
                small_blind: 5,
                big_blind: 10,
                starting_bank: 1000,
                time_per_move_ms: 30_000,
            },
            pts_id,
            pks[0].1.clone(),
            shuffle_vkey_bytes,
            decrypt_vkey_bytes,
        )
        .send_recv(program_code_id, b"salt")
        .await
        .unwrap();

    pts_service_client
        .add_admin(program_id)
        .send_recv(pts_id)
        .await
        .unwrap();
    let mut service_client = poker_client::Poker::new(remoting.clone());

    // REGISTER
    println!("REGISTER");

    for i in 1..USERS.len() {
        service_client
            .register("Player".to_string(), pks[i].1.clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    // start game
    println!("START GAME");
    service_client
        .start_game()
        .send_recv(program_id)
        .await
        .unwrap();

    // Shuffle deck
    println!("SHUFFLE");
    let proofs = load_shuffle_proofs("tests/test_data_gtest/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data_gtest/encrypted_deck.json");
    service_client
        .shuffle_deck(deck, proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    println!("DECRYPT");
    let decrypt_proofs =
        load_partial_decrypt_proofs("tests/test_data_gtest/partial_decrypt_proofs.json");
    service_client
        .submit_all_partial_decryptions(decrypt_proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    // Game logic
    let players_amount = USERS.len();
    for i in 2..players_amount {
        service_client
            .turn(poker_client::Action::Call)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }
    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Check)
        .with_args(GTestArgs::new(USERS[1].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    println!("Decrypt 3 cards after preflop");
    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data_gtest/table_decryptions.json");
    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[..3].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    // game logic
    let actions = vec![
        poker_client::Action::Raise { bet: 50 },  // player 0
        poker_client::Action::Raise { bet: 100 }, // player 1
        poker_client::Action::Call,               // player 2
        poker_client::Action::Call,               // player 3
        poker_client::Action::Call,               // player 4
        poker_client::Action::Call,               // player 5
    ];
    for i in 0..players_amount {
        service_client
            .turn(actions[i].clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    println!("Decrypt 1 cards after flop");

    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[3..4].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    for i in 0..players_amount {
        service_client
            .turn(poker_client::Action::AllIn)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    println!("Decrypt 1 cards after turn");

    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[4..5].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    println!("Players reveal their cards..");
    let player_cards = load_cards_with_proofs("tests/test_data_gtest/player_decryptions.json");
    let (_, card_map) = init_deck_and_card_map();
    let hands = build_player_card_disclosure(player_cards, &card_map);
    
    for i in 0..USERS.len() {
        let proofs = hands[i].1.clone();
        service_client
            .card_disclosure(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }
    let result = service_client.status().recv(program_id).await.unwrap();
    println!("result {:?}", result);
    if !matches!(result, Status::Finished {..}) {
        assert!(true, "Wrong Status!");
    }
    let participants = service_client.participants().recv(program_id).await.unwrap();
    assert_eq!(participants.len(), 2);

    if let Status::Finished {winners, cash_prize} = result {
        for (winner, prize) in winners.iter().zip(cash_prize) {
            participants.iter().map(|(id, info)| {
                if winner == id {
                    if info.balance != prize {
                        assert!(true, "Wrong balance!");
                    } 
                }
            });
        }
    }
    println!("participants {:?}", participants);

}



#[tokio::test]
async fn gtest_check_restart_and_turn() {
    let system = System::new();
    system.init_logger();
    for i in 0..USERS.len() {
        system.mint_to(USERS[i], 1_000_000_000_000_000);
    }

    let builtin_mock = BlsBuiltinMock { msm: Vec::new() };
    let builtin_program = Program::mock_with_id(&system, BUILTIN_BLS381, builtin_mock);

    let init_message_id = builtin_program.send_bytes(USERS[0], b"Doesn't matter");
    let block_run_result = system.run_next_block();
    assert!(block_run_result.succeed.contains(&init_message_id));

    let remoting = GTestRemoting::new(system, USERS[0].into());
    let pks = load_player_public_keys("tests/test_data_gtest/player_pks.json");

    let shuffle_vkey_bytes = get_vkey("tests/test_data/shuffle_vkey.json");
    let decrypt_vkey_bytes = get_vkey("tests/test_data/decrypt_vkey.json");

    // Upload pts
    let pts_code_id = remoting.system().submit_code(pts::WASM_BINARY);
    let pts_factory = pts_client::PtsFactory::new(remoting.clone());
    let accural: u128 = 10_000;
    let time_ms_between_balance_receipt: u64 = 10_000;
    let pts_id = pts_factory
        .new(accural, time_ms_between_balance_receipt)
        .send_recv(pts_code_id, b"salt")
        .await
        .unwrap();

    let mut pts_service_client = pts_client::Pts::new(remoting.clone());
    for i in 0..USERS.len() {
        pts_service_client
            .get_accural()
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(pts_id)
            .await
            .unwrap();
    }
    for i in 0..USERS.len() {
        let balance = pts_service_client
            .get_balance(USERS[i].into())
            .recv(pts_id)
            .await
            .unwrap();

        assert_eq!(balance, accural);
    }
    // Submit program code into the system
    let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);

    let program_factory = poker_client::PokerFactory::new(remoting.clone());

    let program_id = program_factory
        .new(
            Config {
                admin_id: USERS[0].into(),
                admin_name: "Player_1".to_string(),
                lobby_name: "Lobby name".to_string(),
                small_blind: 5,
                big_blind: 10,
                starting_bank: 1000,
                time_per_move_ms: 30_000,
            },
            pts_id,
            pks[0].1.clone(),
            shuffle_vkey_bytes,
            decrypt_vkey_bytes,
        )
        .send_recv(program_code_id, b"salt")
        .await
        .unwrap();

    pts_service_client
        .add_admin(program_id)
        .send_recv(pts_id)
        .await
        .unwrap();
    let mut service_client = poker_client::Poker::new(remoting.clone());

    // REGISTER
    println!("REGISTER");

    for i in 1..USERS.len() {
        service_client
            .register("Player".to_string(), pks[i].1.clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    // start game
    println!("START GAME");
    service_client
        .start_game()
        .send_recv(program_id)
        .await
        .unwrap();

    // Shuffle deck
    println!("SHUFFLE");
    let proofs = load_shuffle_proofs("tests/test_data_gtest/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data_gtest/encrypted_deck.json");
    service_client
        .shuffle_deck(deck, proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    println!("DECRYPT");
    let decrypt_proofs =
        load_partial_decrypt_proofs("tests/test_data_gtest/partial_decrypt_proofs.json");
    service_client
        .submit_all_partial_decryptions(decrypt_proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    // Game logic
    let players_amount = USERS.len();
    for i in 2..players_amount {
        service_client
            .turn(poker_client::Action::Fold)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }
    service_client
        .turn(poker_client::Action::Fold)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    
    let result = service_client.status().recv(program_id).await.unwrap();
    println!("result {:?}", result);
    if !matches!(result, Status::Finished {..}) {
        assert!(true, "Wrong Status!");
    }

    service_client
        .restart_game()
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Registration,
    )
    .await;
    // start game
    println!("START GAME");
    service_client
        .start_game()
        .send_recv(program_id)
        .await
        .unwrap();

    // Shuffle deck
    println!("SHUFFLE");
    let proofs = load_shuffle_proofs("tests/test_data_gtest/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data_gtest/encrypted_deck.json");
    service_client
        .shuffle_deck(deck, proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    println!("DECRYPT");
    let decrypt_proofs =
        load_partial_decrypt_proofs("tests/test_data_gtest/partial_decrypt_proofs.json");
    service_client
        .submit_all_partial_decryptions(decrypt_proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::PreFlop,
        },
    )
    .await;

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[3].into()))
        .send_recv(program_id)
        .await
        .unwrap();

}



#[tokio::test]
async fn gtest_one_player_left() {
    let system = System::new();
    system.init_logger();
    for i in 0..USERS.len() {
        system.mint_to(USERS[i], 1_000_000_000_000_000);
    }

    let builtin_mock = BlsBuiltinMock { msm: Vec::new() };
    let builtin_program = Program::mock_with_id(&system, BUILTIN_BLS381, builtin_mock);

    let init_message_id = builtin_program.send_bytes(USERS[0], b"Doesn't matter");
    let block_run_result = system.run_next_block();
    assert!(block_run_result.succeed.contains(&init_message_id));

    let remoting = GTestRemoting::new(system, USERS[0].into());
    let pks = load_player_public_keys("tests/test_data_gtest/player_pks.json");

    let shuffle_vkey_bytes = get_vkey("tests/test_data/shuffle_vkey.json");
    let decrypt_vkey_bytes = get_vkey("tests/test_data/decrypt_vkey.json");

    // Upload pts
    let pts_code_id = remoting.system().submit_code(pts::WASM_BINARY);
    let pts_factory = pts_client::PtsFactory::new(remoting.clone());
    let accural: u128 = 10_000;
    let time_ms_between_balance_receipt: u64 = 10_000;
    let pts_id = pts_factory
        .new(accural, time_ms_between_balance_receipt)
        .send_recv(pts_code_id, b"salt")
        .await
        .unwrap();

    let mut pts_service_client = pts_client::Pts::new(remoting.clone());
    for i in 0..USERS.len() {
        pts_service_client
            .get_accural()
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(pts_id)
            .await
            .unwrap();
    }
    for i in 0..USERS.len() {
        let balance = pts_service_client
            .get_balance(USERS[i].into())
            .recv(pts_id)
            .await
            .unwrap();

        assert_eq!(balance, accural);
    }
    // Submit program code into the system
    let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);

    let program_factory = poker_client::PokerFactory::new(remoting.clone());

    let program_id = program_factory
        .new(
            Config {
                admin_id: USERS[0].into(),
                admin_name: "Player_1".to_string(),
                lobby_name: "Lobby name".to_string(),
                small_blind: 5,
                big_blind: 10,
                starting_bank: 1000,
                time_per_move_ms: 30_000,
            },
            pts_id,
            pks[0].1.clone(),
            shuffle_vkey_bytes,
            decrypt_vkey_bytes,
        )
        .send_recv(program_code_id, b"salt")
        .await
        .unwrap();

    pts_service_client
        .add_admin(program_id)
        .send_recv(pts_id)
        .await
        .unwrap();
    let mut service_client = poker_client::Poker::new(remoting.clone());

    // REGISTER
    println!("REGISTER");

    for i in 1..USERS.len() {
        service_client
            .register("Player".to_string(), pks[i].1.clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();

        let balance = pts_service_client
            .get_balance(USERS[i].into())
            .recv(pts_id)
            .await
            .unwrap();

        assert_eq!(balance, accural - 1000);
    }

    // start game
    println!("START GAME");
    service_client
        .start_game()
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::WaitingShuffleVerification,
    )
    .await;

    // Shuffle deck
    println!("SHUFFLE");
    let proofs = load_shuffle_proofs("tests/test_data_gtest/shuffle_proofs.json");
    let deck = load_encrypted_table_cards("tests/test_data_gtest/encrypted_deck.json");
    service_client
        .shuffle_deck(deck, proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::WaitingPartialDecryptionsForPlayersCards,
    )
    .await;

    println!("DECRYPT");
    let decrypt_proofs =
        load_partial_decrypt_proofs("tests/test_data_gtest/partial_decrypt_proofs.json");
    service_client
        .submit_all_partial_decryptions(decrypt_proofs)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::PreFlop,
        },
    )
    .await;

    // Game logic
    let players_amount = USERS.len();
    for i in 2..players_amount {
        service_client
            .turn(poker_client::Action::Call)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }
    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Check)
        .with_args(GTestArgs::new(USERS[1].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::WaitingTableCardsAfterPreFlop,
        },
    )
    .await;

    println!("Decrypt 3 cards after preflop");
    let table_cards_proofs =
        load_table_cards_proofs("tests/test_data_gtest/table_decryptions.json");
    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[..3].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::Flop,
        },
    )
    .await;

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    // game logic
    let actions = vec![
        poker_client::Action::Raise { bet: 50 },  // player 0
        poker_client::Action::Raise { bet: 100 }, // player 1
        poker_client::Action::Call,               // player 2
        poker_client::Action::Call,               // player 3
        poker_client::Action::Call,               // player 4
        poker_client::Action::Call,               // player 5
    ];
    for i in 0..players_amount {
        service_client
            .turn(actions[i].clone())
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USERS[0].into()))
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::WaitingTableCardsAfterFlop,
        },
    )
    .await;

    println!("Decrypt 1 cards after flop");

    for i in 0..USERS.len() {
        let proofs: Vec<_> = table_cards_proofs[i].1 .1[3..4].to_vec();
        service_client
            .submit_table_partial_decryptions(proofs)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    check_status(
        &mut service_client,
        program_id,
        Status::Play {
            stage: poker_client::Stage::Turn,
        },
    )
    .await;

    let table_cards = service_client
        .revealed_table_cards()
        .recv(program_id)
        .await
        .unwrap();
    println!("Cards on table {:?}", table_cards);

    for i in 0..players_amount-1 {
        service_client
            .turn(poker_client::Action::Fold)
            .with_args(GTestArgs::new(USERS[i].into()))
            .send_recv(program_id)
            .await
            .unwrap();
    }

    let result = service_client.status().recv(program_id).await.unwrap();
    println!("result {:?}", result);
    if !matches!(result, Status::Finished {..}) {
        assert!(true, "Wrong Status!");
    }
    let participants = service_client.participants().recv(program_id).await.unwrap();
    if let Status::Finished {winners, cash_prize} = result {
        for (winner, prize) in winners.iter().zip(cash_prize) {
            participants.iter().map(|(id, info)| {
                if winner == id {
                    if info.balance != 1000 - 10 - 100 + prize {
                        assert!(true, "Wrong balance!");
                    } 
                } else {
                    if info.balance != 1000 - 10 - 100 {
                        assert!(true, "Wrong balance!");
                    } 
                }
            });
        }
    }
    println!("participants {:?}", participants);
}

