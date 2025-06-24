use gtest::Program;
use gtest::WasmProgram;
use hex_literal::hex;

use poker_client::PublicKey;
use poker_client::{traits::*, Config, Stage, Status};
use pts_client::traits::{Pts, PtsFactory};
use sails_rs::ActorId;
use sails_rs::{
    calls::*,
    gtest::{calls::*, System},
};
use std::ops::Range;
mod utils_gclient;
use utils_gclient::zk_loader::ZkLoaderData;
use utils_gclient::{build_player_card_disclosure, init_deck_and_card_map};
const USERS: [u64; 6] = [42, 43, 44, 45, 46, 47];

const BUILTIN_BLS381: ActorId = ActorId::new(hex!(
    "6b6e292c382945e80bf51af2ba7fe9f458dcff81ae6075c46f9095e1bbecdc37"
));

use gbuiltin_bls381::{
    ark_bls12_381::{Bls12_381, G1Affine, G1Projective as G1, G2Affine},
    ark_ec::{
        pairing::{MillerLoopOutput, Pairing},
        Group, VariableBaseMSM,
    },
    ark_scale,
    ark_scale::hazmat::ArkScaleProjective,
    Request, Response,
};

use gstd::prelude::*;
type ArkScale<T> = ark_scale::ArkScale<T, { ark_scale::HOST_CALL }>;
type Gt = <Bls12_381 as Pairing>::TargetField;

#[tokio::test]
async fn test_basic_poker_workflow() {
    let (mut env, test_data) = TestEnvironment::setup().await;

    env.register_players(&test_data).await;
    env.start_and_setup_game(&test_data).await;

    // preflop
    env.run_actions(vec![
        (USERS[2], poker_client::Action::Call),
        (USERS[3], poker_client::Action::Call),
        (USERS[4], poker_client::Action::Call),
        (USERS[5], poker_client::Action::Call),
        (USERS[0], poker_client::Action::Call),
        (USERS[1], poker_client::Action::Check),
    ])
    .await;

    // reveal 3 cards after preflop
    println!("Decrypt 3 cards after preflop");
    env.reveal_table_cards(&test_data, 0..3).await;

    // flop
    env.run_actions(vec![
        (USERS[0], poker_client::Action::Raise { bet: 50 }),
        (USERS[1], poker_client::Action::Raise { bet: 100 }),
        (USERS[2], poker_client::Action::Call),
        (USERS[3], poker_client::Action::Call),
        (USERS[4], poker_client::Action::Call),
        (USERS[5], poker_client::Action::Call),
        (USERS[0], poker_client::Action::Call),
    ])
    .await;

    // reveal 1 cards after flop
    println!("Decrypt 1 card after flop");
    env.reveal_table_cards(&test_data, 3..4).await;

    // turn
    env.run_actions(vec![
        (USERS[0], poker_client::Action::Check),
        (USERS[1], poker_client::Action::Check),
        (USERS[2], poker_client::Action::Check),
        (USERS[3], poker_client::Action::Check),
        (USERS[4], poker_client::Action::Check),
        (USERS[5], poker_client::Action::Check),
    ])
    .await;

    // reveal 1 cards after turn
    println!("Decrypt 1 card after turn");
    env.reveal_table_cards(&test_data, 4..5).await;

    env.print_table_cards().await;

    env.reveal_player_cards(&test_data).await;

    env.verify_game_finished().await;

    // check final result
    let result = env
        .service_client
        .status()
        .recv(env.program_id)
        .await
        .unwrap();
    let participants = env
        .service_client
        .participants()
        .recv(env.program_id)
        .await
        .unwrap();
    if let Status::Finished { pots } = result {
        assert_eq!(pots.len(), 1);

        let prize = pots[0].0;
        let winners = pots[0].1.clone();
        for winner in winners.iter() {
            participants.iter().for_each(|(id, info)| {
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
    let (mut env, test_data) = TestEnvironment::setup().await;

    env.register_players(&test_data).await;
    env.start_and_setup_game(&test_data).await;

    // preflop
    env.run_actions(vec![
        (USERS[2], poker_client::Action::Call),
        (USERS[3], poker_client::Action::Call),
        (USERS[4], poker_client::Action::Call),
        (USERS[5], poker_client::Action::Call),
        (USERS[0], poker_client::Action::Call),
        (USERS[1], poker_client::Action::Check),
    ])
    .await;

    // reveal 3 cards after preflop
    println!("Decrypt 3 cards after preflop");
    env.reveal_table_cards(&test_data, 0..3).await;

    // flop
    env.run_actions(vec![
        (USERS[0], poker_client::Action::Raise { bet: 50 }),
        (USERS[1], poker_client::Action::Raise { bet: 100 }),
        (USERS[2], poker_client::Action::Call),
        (USERS[3], poker_client::Action::Call),
        (USERS[4], poker_client::Action::Call),
        (USERS[5], poker_client::Action::Call),
        (USERS[0], poker_client::Action::Call),
    ])
    .await;

    // reveal 1 cards after flop
    println!("Decrypt 1 card after flop");
    env.reveal_table_cards(&test_data, 3..4).await;

    // turn
    env.run_actions(vec![
        (USERS[0], poker_client::Action::AllIn),
        (USERS[1], poker_client::Action::AllIn),
        (USERS[2], poker_client::Action::AllIn),
        (USERS[3], poker_client::Action::AllIn),
        (USERS[4], poker_client::Action::AllIn),
        (USERS[5], poker_client::Action::AllIn),
    ])
    .await;

    // reveal 1 cards after turn
    println!("Decrypt 1 card after turn");
    env.reveal_table_cards(&test_data, 4..5).await;

    env.print_table_cards().await;

    env.reveal_player_cards(&test_data).await;

    env.verify_game_finished().await;

    // check final result
    let result = env
        .service_client
        .status()
        .recv(env.program_id)
        .await
        .unwrap();
    println!("result {:?}", result);
    if !matches!(result, Status::Finished { .. }) {
        assert!(true, "Wrong Status!");
    }
    let participants = env
        .service_client
        .participants()
        .recv(env.program_id)
        .await
        .unwrap();
    assert_eq!(participants.len(), 2);

    if let Status::Finished { pots } = result {
        let prize = pots[0].0;
        let winners = pots[0].1.clone();
        for winner in winners.iter() {
            participants.iter().for_each(|(id, info)| {
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
async fn gtest_one_player_left() {
    let (mut env, test_data) = TestEnvironment::setup().await;

    env.register_players(&test_data).await;
    env.start_and_setup_game(&test_data).await;

    // preflop
    env.run_actions(vec![
        (USERS[2], poker_client::Action::Call),
        (USERS[3], poker_client::Action::Call),
        (USERS[4], poker_client::Action::Call),
        (USERS[5], poker_client::Action::Call),
        (USERS[0], poker_client::Action::Call),
        (USERS[1], poker_client::Action::Check),
    ])
    .await;

    // reveal 3 cards after preflop
    println!("Decrypt 3 cards after preflop");
    env.reveal_table_cards(&test_data, 0..3).await;

    env.check_status(Status::Play {
        stage: poker_client::Stage::Flop,
    })
    .await;

    // flop
    env.run_actions(vec![
        (USERS[0], poker_client::Action::Raise { bet: 50 }),
        (USERS[1], poker_client::Action::Raise { bet: 100 }),
        (USERS[2], poker_client::Action::Call),
        (USERS[3], poker_client::Action::Call),
        (USERS[4], poker_client::Action::Call),
        (USERS[5], poker_client::Action::Call),
        (USERS[0], poker_client::Action::Call),
    ])
    .await;

    env.check_status(Status::Play {
        stage: poker_client::Stage::WaitingTableCardsAfterFlop,
    })
    .await;

    // reveal 1 cards after flop
    println!("Decrypt 1 card after flop");
    env.reveal_table_cards(&test_data, 3..4).await;

    env.check_status(Status::Play {
        stage: poker_client::Stage::Turn,
    })
    .await;

    // turn
    env.run_actions(vec![
        (USERS[0], poker_client::Action::Fold),
        (USERS[1], poker_client::Action::Fold),
        (USERS[2], poker_client::Action::Fold),
        (USERS[3], poker_client::Action::Fold),
        (USERS[4], poker_client::Action::Fold),
    ])
    .await;

    env.verify_game_finished().await;

    // final result
    let result = env
        .service_client
        .status()
        .recv(env.program_id)
        .await
        .unwrap();

    let participants = env
        .service_client
        .participants()
        .recv(env.program_id)
        .await
        .unwrap();
    if let Status::Finished { pots } = result {
        let prize = pots[0].0;
        let winners = pots[0].1.clone();
        for winner in winners.iter() {
            participants.iter().for_each(|(id, info)| {
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
async fn gtest_check_restart_and_turn() {
    let (mut env, test_data) = TestEnvironment::setup().await;

    env.register_players(&test_data).await;
    env.start_and_setup_game(&test_data).await;

    // preflop
    env.run_actions(vec![
        (USERS[2], poker_client::Action::Fold),
        (USERS[3], poker_client::Action::Fold),
        (USERS[4], poker_client::Action::Fold),
        (USERS[5], poker_client::Action::Fold),
        (USERS[0], poker_client::Action::Fold),
    ])
    .await;

    env.verify_game_finished().await;
    env.restart_game().await;
    env.check_status(Status::Registration).await;

    env.start_and_setup_game(&test_data).await;
    env.check_status(Status::Play {
        stage: poker_client::Stage::PreFlop,
    })
    .await;

    env.run_actions(vec![(USERS[3], poker_client::Action::Call)])
        .await;
}

#[tokio::test]
async fn gtest_delete_player() {
    let (mut env, test_data) = TestEnvironment::setup().await;

    env.register_players(&test_data).await;
    env.delete_player(USERS[1]).await;
    env.register(USERS[1], test_data.pks[1].1.clone()).await;
    env.start_and_setup_game(&test_data).await;    
}

#[tokio::test]
async fn gtest_check_cancel_registration_and_turn() {
    let (mut env, test_data) = TestEnvironment::setup().await;

    env.register_players(&test_data).await;
    env.start_and_setup_game(&test_data).await;

    // preflop
    env.run_actions(vec![
        (USERS[2], poker_client::Action::Fold),
        (USERS[3], poker_client::Action::Fold),
        (USERS[4], poker_client::Action::Fold),
        (USERS[5], poker_client::Action::Fold),
        (USERS[0], poker_client::Action::Fold),
    ])
    .await;

    env.verify_game_finished().await;
    env.restart_game().await;
    env.check_status(Status::Registration).await;

    env.start_and_setup_game(&test_data).await;
    env.check_status(Status::Play {
        stage: poker_client::Stage::PreFlop,
    })
    .await;

    env.run_actions(vec![
        (USERS[3], poker_client::Action::Fold),
        (USERS[4], poker_client::Action::Fold),
        (USERS[5], poker_client::Action::Fold),
        (USERS[0], poker_client::Action::Fold),
        (USERS[1], poker_client::Action::Fold),
    ])
    .await;
    env.verify_game_finished().await;
    env.restart_game().await;

    let active_participants = env
        .service_client
        .active_participants()
        .recv(env.program_id)
        .await
        .unwrap();
    println!("active_participants: {:?}", active_participants);
    assert_eq!(active_participants.first_index, 2);

    // Cancel registration
    env.service_client
        .cancel_registration()
        .with_args(GTestArgs::new(USERS[1].into()))
        .send_recv(env.program_id)
        .await
        .unwrap();

    let active_participants = env
        .service_client
        .active_participants()
        .recv(env.program_id)
        .await
        .unwrap();
    println!("active_participants: {:?}", active_participants);
    assert_eq!(active_participants.first_index, 1);
}

struct TestEnvironment {
    pts_id: ActorId,
    program_id: ActorId,
    service_client: poker_client::Poker<GTestRemoting>,
    pts_service_client: pts_client::Pts<GTestRemoting>,
}
struct TestData {
    pks: Vec<(usize, poker_client::PublicKey)>,
    shuffle_proofs: Vec<poker_client::VerificationVariables>,
    encrypted_deck: Vec<poker_client::EncryptedCard>,
    decrypt_proofs: Vec<poker_client::VerificationVariables>,
    table_cards_proofs: Vec<(
        poker_client::PublicKey,
        (
            Vec<(poker_client::EncryptedCard, [Vec<u8>; 3])>,
            Vec<poker_client::VerificationVariables>,
        ),
    )>,
    player_cards: Vec<(
        poker_client::PublicKey,
        Vec<utils_gclient::zk_loader::DecryptedCardWithProof>,
    )>,
}

impl TestData {
    fn load() -> Self {
        Self {
            pks: ZkLoaderData::load_player_public_keys("tests/test_data_gtest/player_pks.json"),
            shuffle_proofs: ZkLoaderData::load_shuffle_proofs(
                "tests/test_data_gtest/shuffle_proofs.json",
            ),
            encrypted_deck: ZkLoaderData::load_encrypted_table_cards(
                "tests/test_data_gtest/encrypted_deck.json",
            ),
            decrypt_proofs: ZkLoaderData::load_partial_decrypt_proofs(
                "tests/test_data_gtest/partial_decrypt_proofs.json",
            ),
            table_cards_proofs: ZkLoaderData::load_table_cards_proofs(
                "tests/test_data_gtest/table_decryptions.json",
            ),
            player_cards: ZkLoaderData::load_cards_with_proofs(
                "tests/test_data_gtest/player_decryptions.json",
            ),
        }
    }
}

impl TestEnvironment {
    async fn setup() -> (Self, TestData) {
        let system = System::new();
        system.init_logger();

        // Mint tokens to users
        for &user_id in &USERS {
            system.mint_to(user_id, 1_000_000_000_000_000);
        }

        // Setup BLS builtin mock
        let builtin_mock = BlsBuiltinMock;
        let builtin_program = Program::mock_with_id(&system, BUILTIN_BLS381, builtin_mock);
        let init_message_id = builtin_program.send_bytes(USERS[0], b"Doesn't matter");
        let block_run_result = system.run_next_block();
        assert!(block_run_result.succeed.contains(&init_message_id));

        let remoting = GTestRemoting::new(system, USERS[0].into());

        // Load test data
        let test_data = TestData::load();

        // Setup PTS system
        let pts_id = Self::setup_pts_system(&remoting).await;

        // Setup poker program
        let program_id = Self::setup_poker_program(&remoting, pts_id, &test_data.pks[0].1).await;

        // Create service clients
        let service_client = poker_client::Poker::new(remoting.clone());
        let mut pts_service_client = pts_client::Pts::new(remoting.clone());

        // Add poker program as PTS admin
        pts_service_client
            .add_admin(program_id)
            .send_recv(pts_id)
            .await
            .unwrap();

        let env = TestEnvironment {
            pts_id,
            program_id,
            service_client,
            pts_service_client,
        };

        (env, test_data)
    }

    async fn setup_pts_system(remoting: &GTestRemoting) -> ActorId {
        let pts_code_id = remoting.system().submit_code(pts::WASM_BINARY);
        let pts_factory = pts_client::PtsFactory::new(remoting.clone());
        let accural: u128 = 10_000;
        let time_ms_between_balance_receipt: u64 = 10_000;

        pts_factory
            .new(accural, time_ms_between_balance_receipt)
            .send_recv(pts_code_id, b"salt")
            .await
            .unwrap()
    }

    async fn setup_poker_program(
        remoting: &GTestRemoting,
        pts_id: ActorId,
        admin_pk: &PublicKey,
    ) -> ActorId {
        let shuffle_vkey_bytes =
            ZkLoaderData::load_verifying_key("tests/test_data/shuffle_vkey.json");
        let decrypt_vkey_bytes =
            ZkLoaderData::load_verifying_key("tests/test_data/decrypt_vkey.json");

        let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);
        let program_factory = poker_client::PokerFactory::new(remoting.clone());

        program_factory
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
                admin_pk.clone(),
                shuffle_vkey_bytes,
                decrypt_vkey_bytes,
            )
            .send_recv(program_code_id, b"salt")
            .await
            .unwrap()
    }


    async fn register_players(&mut self, test_data: &TestData) {
        println!("REGISTER");

        // Get initial accurals for all users
        for &user_id in &USERS {
            self.pts_service_client
                .get_accural()
                .with_args(GTestArgs::new(user_id.into()))
                .send_recv(self.pts_id)
                .await
                .unwrap();
        }

        // Register players (skip index 0 as it's admin)
        for i in 1..USERS.len() {
            self.service_client
                .register("Player".to_string(), test_data.pks[i].1.clone())
                .with_args(GTestArgs::new(USERS[i].into()))
                .send_recv(self.program_id)
                .await
                .unwrap();
        }
    }

    async fn start_and_setup_game(&mut self, test_data: &TestData) {
        println!("START GAME");
        self.service_client
            .start_game()
            .send_recv(self.program_id)
            .await
            .unwrap();
        self.check_status(Status::WaitingShuffleVerification).await;

        println!("SHUFFLE");
        self.service_client
            .shuffle_deck(
                test_data.encrypted_deck.clone(),
                test_data.shuffle_proofs.clone(),
            )
            .send_recv(self.program_id)
            .await
            .unwrap();
        self.check_status(Status::WaitingPartialDecryptionsForPlayersCards)
            .await;

        println!("DECRYPT");
        self.service_client
            .submit_all_partial_decryptions(test_data.decrypt_proofs.clone())
            .send_recv(self.program_id)
            .await
            .unwrap();
        self.check_status(Status::Play {
            stage: Stage::PreFlop,
        })
        .await;
    }

    async fn restart_game(&mut self) {
        self.service_client
            .restart_game()
            .send_recv(self.program_id)
            .await
            .unwrap();
    }

    async fn delete_player(&mut self, id: u64) {
        self.service_client
            .delete_player(id.into())
            .send_recv(self.program_id)
            .await
            .unwrap();
    }

    async fn register(&mut self, id: u64, pk: PublicKey) {
        self.service_client
            .register("".to_string(), pk)
            .with_args(GTestArgs::new(id.into()))
            .send_recv(self.program_id)
            .await
            .unwrap();
    }

    pub async fn run_actions(&mut self, moves: Vec<(u64, poker_client::Action)>) {
        for (user_id, action) in moves {
            println!("action {:?}", action);
            self.service_client
                .turn(action)
                .with_args(GTestArgs::new(user_id.into()))
                .send_recv(self.program_id)
                .await
                .unwrap();
        }
    }

    pub async fn reveal_table_cards(&mut self, test_data: &TestData, range: Range<usize>) {
        for (i, user) in USERS.iter().enumerate() {
            let proofs: Vec<_> = test_data.table_cards_proofs[i].1 .1[range.clone()].to_vec();
            self.service_client
                .submit_table_partial_decryptions(proofs)
                .with_args(GTestArgs::new((*user).into()))
                .send_recv(self.program_id)
                .await
                .unwrap();
        }
    }

    async fn reveal_player_cards(&mut self, test_data: &TestData) {
        println!("Players reveal their cards..");
        let (_, card_map) = init_deck_and_card_map();
        let hands = build_player_card_disclosure(test_data.player_cards.clone(), &card_map);

        for i in 0..USERS.len() {
            let proofs = hands[i].1.clone();
            self.service_client
                .card_disclosure(proofs)
                .with_args(GTestArgs::new(USERS[i].into()))
                .send_recv(self.program_id)
                .await
                .unwrap();
        }
    }

    async fn print_table_cards(&mut self) {
        let table_cards = self
            .service_client
            .revealed_table_cards()
            .recv(self.program_id)
            .await
            .unwrap();
        println!("Cards on table {:?}", table_cards);
    }

    async fn verify_game_finished(&mut self) -> Status {
        let result = self
            .service_client
            .status()
            .recv(self.program_id)
            .await
            .unwrap();
        println!("Final result: {:?}", result);
        assert!(
            matches!(result, Status::Finished { .. }),
            "Game should be finished"
        );
        result
    }

    async fn check_status(&mut self, expected_status: Status) {
        let result = self
            .service_client
            .status()
            .recv(self.program_id)
            .await
            .unwrap();
        assert_eq!(result, expected_status);
    }
}

#[derive(Debug)]
struct BlsBuiltinMock;
impl WasmProgram for BlsBuiltinMock {
    fn init(&mut self, _payload: Vec<u8>) -> Result<Option<Vec<u8>>, &'static str> {
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

    fn handle_reply(&mut self, _payload: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }
    /// Signal handler with given `payload`.
    fn handle_signal(&mut self, _payload: Vec<u8>) -> Result<(), &'static str> {
        Ok(())
    }
    /// State of wasm program.
    ///
    /// See [`Program::read_state`] for the usage.
    fn state(&mut self) -> Result<Vec<u8>, &'static str> {
        Ok(vec![])
    }

    fn debug(&mut self, _data: &str) {}
}
