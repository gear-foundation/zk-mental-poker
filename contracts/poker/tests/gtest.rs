use sails_rs::{calls::*, gtest::{calls::*, System}};
use sails_rs::ActorId;
use poker_client::{traits::*, Config, Status, Card, Suit};

const ADMIN_ID: u64 = 42;
const USER_1: u64 = 43;
const USER_2: u64 = 44;

#[tokio::test]
async fn do_something_works() {
    let system = System::new();
    // system.init_logger_with_default_filter("gwasm=debug,gtest=info,sails_rs=debug");
    system.init_logger();
    system.mint_to(ADMIN_ID, 100_000_000_000_000);
    system.mint_to(USER_1, 100_000_000_000_000);
    system.mint_to(USER_2, 100_000_000_000_000);
    let remoting = GTestRemoting::new(system, ADMIN_ID.into());

    // Submit program code into the system
    let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);

    let program_factory = poker_client::PokerFactory::new(remoting.clone());

    let program_id = program_factory
        .new(Config {
            admin_id: ADMIN_ID.into(),
            admin_name: "Player_1".to_string(),
            lobby_name: "Lobby name".to_string(),
            small_blind: 5,
            big_blind: 10,
            number_of_participants: 3,
        })
        .send_recv(program_code_id, b"salt")
        .await
        .unwrap();

    let mut service_client = poker_client::Poker::new(remoting.clone());

    check_status(&mut service_client, program_id, Status::Registration).await;

    service_client
        .register("Player_2".to_string())
        .with_args(GTestArgs::new(USER_1.into()))
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .register("Player_3".to_string())
        .with_args(GTestArgs::new(USER_2.into()))
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::WaitingStart).await;

    service_client
        .start_game()
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::WaitingSetSmallBlind(ADMIN_ID.into())).await;

    service_client
        .set_small_blind()
        .with_value(5)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::WaitingSetBigBlind(USER_1.into())).await;

    service_client
        .set_big_blind()
        .with_args(GTestArgs::new(USER_1.into()))
        .with_value(10)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::Play { stage: poker_client::Stage::PreFlop }).await;

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USER_2.into()))
        .with_value(10)
        .send_recv(program_id)
        .await
        .unwrap();

    let result = service_client
        .bank()
        .recv(program_id)
        .await
        .unwrap();

    println!("bank {:?}", result);
    service_client
        .turn(poker_client::Action::Call)
        .with_value(5)
        .send_recv(program_id)
        .await
        .unwrap();
    check_status(&mut service_client, program_id, Status::Play { stage: poker_client::Stage::Flop }).await;

    service_client
        .turn(poker_client::Action::Check)
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Raise)
        .with_args(GTestArgs::new(USER_1.into()))
        .with_value(10)
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Raise)
        .with_args(GTestArgs::new(USER_2.into()))
        .with_value(15)
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Call)
        .with_value(15)
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USER_1.into()))
        .with_value(5)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::Play { stage: poker_client::Stage::Turn }).await;

    service_client
        .turn(poker_client::Action::AllIn)
        .with_value(50)
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Fold)
        .with_args(GTestArgs::new(USER_1.into()))
        .send_recv(program_id)
        .await
        .unwrap();

    service_client
        .turn(poker_client::Action::Call)
        .with_args(GTestArgs::new(USER_2.into()))
        .with_value(50)
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::WaitingForCardsToBeDisclosed).await;

    let result = service_client
        .all_in_players()
        .recv(program_id)
        .await
        .unwrap();
    assert_eq!(result, vec![ADMIN_ID.into()]);
    let result = service_client
        .bank()
        .recv(program_id)
        .await
        .unwrap();
    println!("bank {:?}", result);

    service_client
        .card_disclosure(vec![
            (ADMIN_ID.into(), (Card {value: 14, suit: Suit::Hearts}, Card {value: 14, suit: Suit::Spades})),
            (USER_2.into(), (Card {value: 13, suit: Suit::Hearts}, Card {value: 13, suit: Suit::Spades})),
            ],
            vec![
                Card {value: 3, suit: Suit::Hearts},
                Card {value: 7, suit: Suit::Diamonds},
                Card {value: 11, suit: Suit::Clubs},
                Card {value: 13, suit: Suit::Diamonds},
                Card {value: 4, suit: Suit::Clubs},
            ])
        .send_recv(program_id)
        .await
        .unwrap();

    check_status(&mut service_client, program_id, Status::Finished{winners: vec![USER_2.into()], cash_prize: vec![175]}).await;

}

async fn check_status(service_client: &mut poker_client::Poker<GTestRemoting>, program_id: ActorId, expected_status: Status) {
    let result = service_client
        .status()
        .recv(program_id)
        .await
        .unwrap();
    assert_eq!(result, expected_status);
}

// fn check_result(result: Result<(), Error>, error: &[u8]) {
//     assert!(matches!(
//         result,
//         Err(sails_rs::errors::Error::Rtl(RtlError::ReplyHasError(
//             ErrorReplyReason::Execution(SimpleExecutionError::UserspacePanic),
//             message
//         ))) if message == *error
//     ));
// }
// #[tokio::test]
// async fn get_something_works() {
//     let system = System::new();
//     system.init_logger_with_default_filter("gwasm=debug,gtest=info,sails_rs=debug");
//     system.mint_to(ADMIN_ID, 100_000_000_000_000);
//     let remoting = GTestRemoting::new(system, ADMIN_ID.into());

//     // Submit program code into the system
//     let program_code_id = remoting.system().submit_code(poker::WASM_BINARY);

//     let program_factory = poker_client::PokerFactory::new(remoting.clone());

//     let program_id = program_factory
//         .new() // Call program's constructor (see app/src/lib.rs:29)
//         .send_recv(program_code_id, b"salt")
//         .await
//         .unwrap();

//     let service_client = poker_client::Poker::new(remoting.clone());

//     let result = service_client
//         .get_something() // Call service's query (see app/src/lib.rs:19)
//         .recv(program_id)
//         .await
//         .unwrap();

//     assert_eq!(result, "Hello from Poker!".to_string());
// }
