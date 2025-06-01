#![allow(static_mut_refs)]
use sails_rs::collections::{HashMap, HashSet};
use sails_rs::gstd::{exec, msg};
use sails_rs::prelude::*;
use utils::*;
mod curve;
mod utils;
mod verify;
use crate::services::curve::{
    calculate_agg_pub_key, check_decrypted_points, decrypt_point, init_deck_and_card_map,
    verify_cards,
};
use ark_ed_on_bls12_381_bandersnatch::EdwardsProjective;
use pts_client::pts::io as pts_io;
pub use verify::{
    BatchVerificationContext, ShuffleChainValidator, VerificationVariables, VerifyingKeyBytes,
};

#[derive(Debug, Encode, Decode, TypeInfo, Clone, PartialEq, Eq, Hash)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct EncryptedCard {
    pub c0: [Vec<u8>; 3], // (x, y, z)
    pub c1: [Vec<u8>; 3], // (x, y, z)
}
const ACTOR_ID: [u8; 32] =
    hex_literal::hex!("6b6e292c382945e80bf51af2ba7fe9f458dcff81ae6075c46f9095e1bbecdc37");
#[derive(Debug)]
struct Storage {
    // for zk
    shuffle_verification_context: BatchVerificationContext,
    decrypt_verificaiton_context: BatchVerificationContext,
    encrypted_deck: Option<Vec<EncryptedCard>>,
    encrypted_cards: HashMap<ActorId, [EncryptedCard; 2]>,
    partially_decrypted_cards: HashMap<ActorId, [EncryptedCard; 2]>,
    partial_table_card_decryptions: HashMap<EncryptedCard, PartialDecryptionsByCard>,
    revealed_table_cards: Vec<Card>,
    original_card_map: HashMap<EdwardsProjective, Card>,
    original_deck: Vec<EdwardsProjective>,
    table_cards: Vec<EncryptedCard>,
    deck_position: usize,
    participants: HashMap<ActorId, Participant>,
    agg_pub_key: PublicKey,
    // active_participants - players who can place bets
    // not to be confused with those who are in the game, as there are also all in players.
    active_participants: TurnManager<ActorId>,
    revealed_players: HashMap<ActorId, (Card, Card)>,
    status: Status,
    config: Config,
    round: u32,
    betting: Option<BettingStage>,
    betting_bank: HashMap<ActorId, u128>,
    all_in_players: Vec<ActorId>,
    already_invested_in_the_circle: HashMap<ActorId, u128>, // The mapa is needed to keep track of how much a person has put on the table,
    // which can change after each player's turn
    pts_actor_id: ActorId,
    factory_actor_id: ActorId,
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Status {
    Registration,
    WaitingShuffleVerification,
    WaitingStart,
    WaitingPartialDecryptionsForPlayersCards,
    Play {
        stage: Stage,
    },
    WaitingForCardsToBeDisclosed,
    Finished {
        winners: Vec<ActorId>,
        cash_prize: Vec<u128>,
    },
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Action {
    Fold,
    Call,
    Raise { bet: u128 },
    Check,
    AllIn,
}

#[derive(Debug, Decode, Encode, TypeInfo, Clone)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct Config {
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
pub struct Participant {
    name: String,
    balance: u128,
    card_1: Option<u32>,
    card_2: Option<u32>,
    pk: PublicKey,
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq, Hash)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct PublicKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub z: [u8; 32],
}

static mut STORAGE: Option<Storage> = None;

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Event {
    Registered {
        participant_id: ActorId,
        pk: PublicKey,
        all_registered: bool,
    },
    PlayerDeleted {
        player_id: ActorId,
    },
    RegistrationCanceled {
        player_id: ActorId,
    },
    GameStarted,
    CardsDealtToPlayers(Vec<(ActorId, [EncryptedCard; 2])>),
    CardsDealtToTable(Vec<EncryptedCard>),
    GameRestarted {
        status: Status,
    },
    SmallBlindIsSet,
    BigBlindIsSet,
    TurnIsMade {
        action: Action,
    },
    NextStage(Stage),
    Finished {
        winners: Vec<ActorId>,
        cash_prize: Vec<u128>,
    },
    Killed {
        inheritor: ActorId,
    },
}

pub struct PokerService(());

impl PokerService {
    pub fn init(
        config: Config,
        pts_actor_id: ActorId,
        pk: PublicKey,
        vk_shuffle_bytes: VerifyingKeyBytes,
        vk_decrypt_bytes: VerifyingKeyBytes,
    ) -> Self {
        let mut participants = HashMap::new();
        participants.insert(
            config.admin_id,
            Participant {
                name: config.admin_name.clone(),
                balance: config.starting_bank,
                card_1: None,
                card_2: None,
                pk: pk.clone(),
            },
        );
        let mut active_participants = TurnManager::new();
        active_participants.add(config.admin_id);

        let (original_deck, original_card_map) = init_deck_and_card_map();
        unsafe {
            STORAGE = Some(Storage {
                config,
                status: Status::Registration,
                participants,
                active_participants,
                round: 0,
                betting: None,
                betting_bank: HashMap::new(),
                all_in_players: Vec::new(),
                already_invested_in_the_circle: HashMap::new(),
                decrypt_verificaiton_context: BatchVerificationContext::new(
                    &vk_decrypt_bytes,
                    ActorId::from(ACTOR_ID),
                ),
                shuffle_verification_context: BatchVerificationContext::new(
                    &vk_shuffle_bytes,
                    ActorId::from(ACTOR_ID),
                ),
                encrypted_deck: None,
                deck_position: 0,
                encrypted_cards: HashMap::new(),
                table_cards: Vec::new(),
                partially_decrypted_cards: HashMap::new(),
                revealed_table_cards: Vec::new(),
                original_card_map,
                original_deck,
                partial_table_card_decryptions: HashMap::new(),
                pts_actor_id,
                factory_actor_id: msg::source(),
                agg_pub_key: pk,
                revealed_players: HashMap::new(),
            });
        }
        Self(())
    }
    fn get_mut(&mut self) -> &'static mut Storage {
        unsafe { STORAGE.as_mut().expect("Storage is not initialized") }
    }
    fn get(&self) -> &'static Storage {
        unsafe { STORAGE.as_ref().expect("Storage is not initialized") }
    }
}

#[sails_rs::service(events = Event)]
impl PokerService {
    pub fn new() -> Self {
        Self(())
    }

    /// Registers a player by sending a transfer request to the PTS contract (starting_bank points).
    ///
    /// Panics if:
    /// - status is not `Registration`;
    /// - player is already registered.
    ///
    /// Sends a message to the PTS contract (pts_actor_id) to transfer points to this contract.
    /// On success, updates participant data and emits a `Registered` event.
    pub async fn register(&mut self, player_name: String, pk: PublicKey) {
        let storage = self.get_mut();
        if storage.status != Status::Registration {
            panic("Wrong status");
        }
        let msg_src = msg::source();
        if storage.participants.contains_key(&msg_src) {
            panic("Already registered");
        }
        let request = pts_io::Transfer::encode_call(
            msg_src,
            exec::program_id(),
            storage.config.starting_bank,
        );

        msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
            .expect("Error in async message to PTS contract")
            .await
            .expect("PTS: Error transfer points to contract");

        storage.participants.insert(
            msg_src,
            Participant {
                name: player_name,
                balance: storage.config.starting_bank,
                card_1: None,
                card_2: None,
                pk: pk.clone(),
            },
        );
        storage.active_participants.add(msg_src);

        let mut all_registered = false;
        if storage.participants.len() == storage.config.number_of_participants as usize {
            storage.status = Status::WaitingShuffleVerification;
            all_registered = true;
        }
        storage.agg_pub_key = calculate_agg_pub_key(storage.agg_pub_key.clone(), pk.clone());
        self.emit_event(Event::Registered {
            participant_id: msg_src,
            pk,
            all_registered,
        })
        .expect("Event Invocation Error");
    }

    /// Cancels player registration and refunds their balance via PTS contract.
    ///
    /// Panics if:
    /// - current status is invalid for cancellation;
    /// - caller is not a registered player.
    ///
    /// Sends a transfer request to PTS contract to return points to the player.
    /// Removes player data and emits `RegistrationCanceled` event on success.
    pub async fn cancel_registration(&mut self) {
        let storage = self.get_mut();
        let msg_src = msg::source();

        match storage.status {
            Status::Registration | Status::WaitingShuffleVerification | Status::Finished { .. } => {
            }
            _ => {
                panic("Wrong status");
            }
        }

        if let Some(participant) = storage.participants.get(&msg_src) {
            let request =
                pts_io::Transfer::encode_call(exec::program_id(), msg_src, participant.balance);

            msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
                .expect("Error in async message to PTS contract")
                .await
                .expect("PTS: Error transfer points to player");

            storage.participants.remove(&msg_src);
            storage.active_participants.remove(&msg_src);
        } else {
            panic("You are not player");
        }

        self.emit_event(Event::RegistrationCanceled { player_id: msg_src })
            .expect("Event Error");
    }

    /// Restarts the game, resetting status and refunding bets (if not Finished).
    /// Panics if caller is not admin.
    /// Resets game to WaitingShuffleVerification (if full) or Registration status.
    /// Emits GameRestarted event with new status.
    pub fn restart_game(&mut self) {
        let storage = self.get_mut();
        if msg::source() != storage.config.admin_id {
            panic("Access denied");
        }
        if !matches!(storage.status, Status::Finished { .. }) {
            for (id, bet) in storage.betting_bank.iter() {
                if *bet != 0 {
                    let participant = storage.participants.get_mut(id).unwrap();
                    participant.balance += *bet;
                }
            }
        }

        if storage.participants.len() == storage.config.number_of_participants as usize {
            storage.status = Status::WaitingShuffleVerification;
        } else {
            storage.status = Status::Registration;
        }

        self.emit_event(Event::GameRestarted {
            status: storage.status.clone(),
        })
        .expect("Event Invocation Error");
    }

    /// Admin-only function to terminate the lobby and refund all players.
    ///
    /// Panics if:
    /// - caller is not admin
    /// - wrong game status (not Registration/WaitingShuffleVerification/Finished)
    ///
    /// Performs:
    /// 1. Batch transfer of all player balances via PTS contract
    /// 2. Sends DeleteLobby request to PokerFactory
    /// 3. Emits Killed event and transfers remaining funds to inheritor
    ///
    /// WARNING: Irreversible operation
    pub async fn kill(&mut self, inheritor: ActorId) {
        let storage = self.get();
        let msg_src = msg::source();
        if msg_src != storage.config.admin_id {
            panic("Access denied");
        }
        match storage.status {
            Status::Registration | Status::WaitingShuffleVerification | Status::Finished { .. } => {
            }
            _ => {
                panic("Wrong status");
            }
        }
        let mut ids = Vec::new();
        let mut points = Vec::new();

        for (id, participant) in storage.participants.iter() {
            ids.push(*id);
            points.push(participant.balance);
        }
        let request = pts_io::BatchTransfer::encode_call(exec::program_id(), ids, points);

        msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
            .expect("Error in async message to PTS contract")
            .await
            .expect("PTS: Error batch transfer points to players");

        let request = [
            "PokerFactory".encode(),
            "DeleteLobby".to_string().encode(),
            (msg::source()).encode(),
        ]
        .concat();

        msg::send_bytes_for_reply(storage.factory_actor_id, request, 0, 0)
            .expect("Error in sending message to PokerFactory")
            .await
            .expect("PokerFactory: Error DeleteLobby");

        self.emit_event(Event::Killed { inheritor })
            .expect("Notification Error");
        exec::exit(inheritor);
    }

    /// Admin-only function to forcibly remove a player and refund their balance.
    ///
    /// Panics if:
    /// - caller is not admin or tries to delete themselves
    /// - wrong game status (not Registration/WaitingShuffleVerification)
    /// - player doesn't exist
    ///
    /// Performs:
    /// 1. Transfers player's balance back to user via PTS contract
    /// 2. Removes player from all participant lists
    /// 3. Resets status to Registration
    /// 4. Emits PlayerDeleted event
    pub async fn delete_player(&mut self, player_id: ActorId) {
        let storage = self.get_mut();
        let msg_src = msg::source();
        if msg_src != storage.config.admin_id || player_id == storage.config.admin_id {
            panic("Access denied");
        }

        if storage.status != Status::Registration
            && storage.status != Status::WaitingShuffleVerification
        {
            panic("Wrong status");
        }

        if let Some(participant) = storage.participants.get(&player_id) {
            let request =
                pts_io::Transfer::encode_call(exec::program_id(), player_id, participant.balance);

            msg::send_bytes_for_reply(storage.pts_actor_id, request, 0, 0)
                .expect("Error in async message to PTS contract")
                .await
                .expect("PTS: Error transfer points to player");

            storage.participants.remove(&player_id);
            storage.active_participants.remove(&player_id);
            storage.status = Status::Registration;
        } else {
            panic("There is no such player");
        }

        self.emit_event(Event::PlayerDeleted { player_id })
            .expect("Event Invocation Error");
    }

    pub async fn shuffle_deck(
        &mut self,
        encrypted_deck: Vec<EncryptedCard>,
        instances: Vec<VerificationVariables>,
    ) {
        let storage = self.get_mut();
        if storage.status != Status::WaitingShuffleVerification {
            panic("Wrong status");
        }

        ShuffleChainValidator::validate_shuffle_chain(
            &instances,
            &storage.original_deck,
            &storage.agg_pub_key,
            &encrypted_deck,
        );

        storage
            .shuffle_verification_context
            .verify_batch(instances)
            .await;

        storage.status = Status::WaitingStart;
        storage.encrypted_deck = Some(encrypted_deck);
    }

    /// Admin-only function to start the poker game after setup.
    ///
    /// Panics if:
    /// - caller is not admin
    /// - wrong status (not WaitingStart)
    ///
    /// Performs:
    /// 1. Deals cards to players and table
    /// 2. Processes small/big blinds (handles all-in cases)
    /// 3. Initializes betting stage
    /// 4. Updates game status and emits GameStarted event
    ///
    /// Note: Handles edge cases where players can't cover blinds
    pub async fn start_game(&mut self) {
        let storage = self.get_mut();
        let msg_src = msg::source();
        if msg_src != storage.config.admin_id {
            panic("Access denied");
        }
        if storage.status != Status::WaitingStart {
            panic("Wrong status");
        }

        self.deal_player_cards();
        self.deal_table_cards(5);

        let sb_player = storage
            .active_participants
            .next()
            .expect("The player must exist");

        let participant = storage.participants.get_mut(&sb_player).unwrap();
        if participant.balance <= storage.config.small_blind {
            storage.active_participants.remove(&sb_player);
            storage.all_in_players.push(sb_player);
            storage
                .already_invested_in_the_circle
                .insert(sb_player, participant.balance);
            storage.betting_bank.insert(sb_player, participant.balance);
            participant.balance = 0;
        } else {
            storage
                .already_invested_in_the_circle
                .insert(sb_player, storage.config.small_blind);
            storage
                .betting_bank
                .insert(sb_player, storage.config.small_blind);
            participant.balance -= storage.config.small_blind;
        }

        let bb_player = storage
            .active_participants
            .next()
            .expect("The player must exist");

        let participant = storage.participants.get_mut(&bb_player).unwrap();

        if participant.balance <= storage.config.big_blind {
            storage.active_participants.remove(&bb_player);
            storage.all_in_players.push(bb_player);
            storage
                .already_invested_in_the_circle
                .insert(bb_player, participant.balance);
            storage.betting_bank.insert(bb_player, participant.balance);
            participant.balance = 0;
        } else {
            storage
                .already_invested_in_the_circle
                .insert(bb_player, storage.config.big_blind);
            storage
                .betting_bank
                .insert(bb_player, storage.config.big_blind);
            participant.balance -= storage.config.big_blind;
        }

        storage.betting = Some(BettingStage {
            turn: storage
                .active_participants
                .next()
                .expect("The player must exist"),
            last_active_time: None,
            current_bet: storage.config.big_blind,
            acted_players: vec![],
        });

        storage.status = Status::WaitingPartialDecryptionsForPlayersCards;
        storage.round += 1;
        self.emit_event(Event::GameStarted)
            .expect("Event Invocation Error");
    }

    fn deal_player_cards(&mut self) {
        let storage = self.get_mut();
        let deck = storage.encrypted_deck.as_ref().expect("No encrypted deck");
        let mut pos = storage.deck_position;

        let mut dealt = Vec::new();
        sails_rs::gstd::debug!("DEAL ENCRYPTED DECK LEN {:?}", deck.len());
        for id in storage.participants.keys() {
            if pos + 2 > deck.len() {
                panic("Not enough cards");
            }

            let card1 = deck[pos].clone();
            let card2 = deck[pos + 1].clone();
            storage
                .encrypted_cards
                .insert(*id, [card1.clone(), card2.clone()]);

            dealt.push((*id, [card1, card2]));

            pos += 2;
        }

        storage.deck_position = pos;
        self.emit_event(Event::CardsDealtToPlayers(dealt))
            .expect("Event Invocation Error");
    }

    pub async fn submit_all_partial_decryptions(
        &mut self,
        cards_by_player: Vec<(ActorId, [EncryptedCard; 2])>,
        instances: Vec<VerificationVariables>,
    ) {
        let storage = self.get_mut();

        if !check_decrypted_points(
            &instances,
            &storage.encrypted_cards,
            cards_by_player.clone(),
        ) {
            panic!("Error in dec points");
        }

        storage
            .decrypt_verificaiton_context
            .verify_batch(instances)
            .await;

        for (player, cards) in cards_by_player {
            storage.partially_decrypted_cards.insert(player, cards);
        }

        storage.status = Status::Play {
            stage: Stage::PreFlop,
        };
        if let Some(betting) = &mut storage.betting {
            betting.last_active_time = Some(exec::block_timestamp());
        }
    }

    pub async fn submit_table_partial_decryptions(
        &mut self,
        decryptions: Vec<(EncryptedCard, [Vec<u8>; 3])>,
        instances: Vec<VerificationVariables>,
    ) {
        let storage = self.get_mut();
        let sender = msg::source();

        let (base_index, expected_count, next_stage) = match &storage.status {
            Status::Play { stage } => match stage {
                Stage::WaitingTableCardsAfterPreFlop => (0, 3, Stage::Flop),
                Stage::WaitingTableCardsAfterFlop => (3, 1, Stage::Turn),
                Stage::WaitingTableCardsAfterTurn => (4, 1, Stage::River),
                _ => panic("Wrong stage"),
            },
            _ => panic("Wrong status"),
        };

        storage
            .decrypt_verificaiton_context
            .verify_batch(instances)
            .await;

        if !storage.participants.contains_key(&sender) {
            panic!("Not participant");
        }

        if decryptions.len() != expected_count {
            panic!("Wrong count");
        }

        for (card, decryption) in decryptions {
            assert!(storage.table_cards.contains(&card), "Wrong card");
            storage
                .partial_table_card_decryptions
                .entry(card)
                .or_default()
                .add(sender, decryption);
        }

        let first_card = &storage.table_cards[base_index];

        let all_submitted = storage
            .partial_table_card_decryptions
            .get(first_card)
            .map(|by_card| by_card.participants.len() == storage.participants.len())
            .unwrap_or(false);
        if all_submitted {
            let mut revealed_cards = Vec::with_capacity(expected_count);
            for i in base_index..base_index + expected_count {
                let encrypted_card = &storage.table_cards[i];

                let by_card = storage
                    .partial_table_card_decryptions
                    .get(encrypted_card)
                    .expect("Decryptions must exist for this card");

                let partials = by_card
                    .partials
                    .iter()
                    .map(|pd| pd.clone())
                    .collect::<Vec<_>>();

                if let Some(card) =
                    decrypt_point(&storage.original_card_map, encrypted_card, partials)
                {
                    revealed_cards.push(card);
                } else {
                    panic!("Failed to decrypt card");
                }
            }

            storage.revealed_table_cards.extend(revealed_cards);

            storage.status = Status::Play { stage: next_stage };

            if let Some(betting) = &mut storage.betting {
                betting.last_active_time = Some(exec::block_timestamp());
            }
        }
    }

    /// Processes player actions during betting rounds.
    ///
    /// Panics if:
    /// - Wrong game status
    /// - Not player's turn
    /// - Invalid action (e.g. check when bet exists)
    ///
    /// Handles:
    /// - Fold/Call/Check/Raise/AllIn actions
    /// - Turn timers and skips
    /// - Game end conditions (single player left)
    /// - Stage transitions
    ///
    /// Emits TurnIsMade and NextStage events
    pub fn turn(&mut self, action: Action) {
        let player = msg::source();
        let storage = self.get_mut();

        let Status::Play { stage } = &mut storage.status else {
            panic("Wrong status");
        };

        if *stage == Stage::WaitingTableCardsAfterPreFlop
            || *stage == Stage::WaitingTableCardsAfterFlop
            || *stage == Stage::WaitingTableCardsAfterTurn
        {
            panic("Wrong stage");
        }

        let betting = storage.betting.as_mut().expect("No betting");

        let last_active_time = betting.last_active_time.expect("No last active time");
        let current_time = exec::block_timestamp();
        let number_of_passes = (current_time - last_active_time) / storage.config.time_per_move_ms;

        if number_of_passes != 0 {
            let current_turn_player_id = storage
                .active_participants
                .skip_and_remove(number_of_passes);

            if let Some(current_turn_player_id) = current_turn_player_id {
                if current_turn_player_id != player {
                    panic!("Not your turn!");
                }
            } else {
                storage.status = Status::Finished {
                    winners: vec![],
                    cash_prize: vec![],
                };
                storage.betting = None;
                return;
            }
        } else {
            if betting.turn != player {
                panic!("Not your turn!");
            }
        }

        let participant = storage.participants.get_mut(&player).unwrap();
        // Process the player's action
        match action {
            Action::Fold => {
                storage.active_participants.remove(&player);
            }
            Action::Call => {
                let already_invested = *storage
                    .already_invested_in_the_circle
                    .get(&player)
                    .unwrap_or(&0);
                let call_value = betting.current_bet - already_invested;
                if call_value == 0 || participant.balance <= call_value {
                    panic("Wrong action");
                }
                participant.balance -= call_value;
                betting.acted_players.push(player);
                storage
                    .already_invested_in_the_circle
                    .entry(player)
                    .and_modify(|v| *v += call_value)
                    .or_insert(call_value);
                storage
                    .betting_bank
                    .entry(player)
                    .and_modify(|v| *v += call_value)
                    .or_insert(call_value);
            }
            Action::Check => {
                let already_invested = *storage
                    .already_invested_in_the_circle
                    .get(&player)
                    .unwrap_or(&0);
                if betting.current_bet != already_invested {
                    panic("cannot check");
                }
                betting.acted_players.push(player);
            }
            Action::Raise { bet } => {
                let already_invested = *storage
                    .already_invested_in_the_circle
                    .get(&player)
                    .unwrap_or(&0);

                if participant.balance <= bet {
                    panic("Wrong action");
                }
                if already_invested + bet <= betting.current_bet {
                    panic("Raise must be higher");
                }
                betting.current_bet = already_invested + bet;
                participant.balance -= bet;
                // if someone raises the bet, the betting round starts all over again
                // so it is necessary to clear the acted_players
                betting.acted_players.clear();
                betting.acted_players.push(player);
                storage
                    .already_invested_in_the_circle
                    .entry(player)
                    .and_modify(|v| *v += bet)
                    .or_insert(bet);
                storage
                    .betting_bank
                    .entry(player)
                    .and_modify(|v| *v += bet)
                    .or_insert(bet);
            }
            Action::AllIn => {
                let already_invested = *storage
                    .already_invested_in_the_circle
                    .get(&player)
                    .unwrap_or(&0);
                let bet = already_invested + participant.balance;
                if bet > betting.current_bet {
                    betting.current_bet = bet;
                    betting.acted_players.clear();
                }

                storage.all_in_players.push(player);
                // if a player has made a all in, we remove him from the active_participants, so that he no longer participates in bets
                storage.active_participants.remove(&player);
                storage
                    .already_invested_in_the_circle
                    .entry(player)
                    .and_modify(|v| *v += participant.balance)
                    .or_insert(participant.balance);
                storage
                    .betting_bank
                    .entry(player)
                    .and_modify(|v| *v += participant.balance)
                    .or_insert(participant.balance);
                participant.balance = 0;
            }
        }

        // Check if the game should end immediately (only one player left)
        if storage.active_participants.len() + storage.all_in_players.len() == 1 {
            let winner = if storage.active_participants.is_empty() {
                storage
                    .all_in_players
                    .get(0)
                    .expect("The player must exist")
            } else {
                storage
                    .active_participants
                    .get(0)
                    .expect("The player must exist")
            };
            let prize = storage.betting_bank.values().sum();
            let participant = storage.participants.get_mut(winner).unwrap();
            participant.balance += prize;
            storage.status = Status::Finished {
                winners: vec![*winner],
                cash_prize: vec![prize],
            };
            //self.emit_event(Event::Finished { winners: vec![*winner], cash_prize: vec![*betting_bank] }).expect("Event Invocation Error");
        }
        // Check if the round is complete at the River stage
        else if betting.acted_players.len() == storage.active_participants.len()
            && *stage == Stage::River
        {
            storage.status = Status::WaitingForCardsToBeDisclosed;
        }
        // Check if the round is complete before River stage
        else if betting.acted_players.len() == storage.active_participants.len() {
            // if there's only one active player left, there's no point in betting any more
            if storage.active_participants.len() == 1 {
                storage.status = Status::WaitingForCardsToBeDisclosed;
            } else {
                storage.active_participants.reset_turn_index();
                storage.already_invested_in_the_circle = HashMap::new();
                betting.turn = storage.active_participants.next().unwrap();
                betting.last_active_time = None;
                betting.acted_players.clear();
                betting.current_bet = 0;

                *stage = stage.clone().next().unwrap();
                self.emit_event(Event::NextStage(stage.clone()))
                    .expect("Event Error");
            }
        } else {
            betting.turn = storage
                .active_participants
                .next()
                .expect("The player must exist");
            betting.last_active_time = Some(current_time);
        }
        self.emit_event(Event::TurnIsMade { action })
            .expect("Event Error");
    }

    fn deal_table_cards(&mut self, count: usize) {
        let storage = self.get_mut();
        let deck = storage.encrypted_deck.as_ref().expect("No shuffled deck");

        if storage.deck_position + count > deck.len() {
            panic("Not enough cards");
        }

        let mut new_cards = Vec::new();
        for _ in 0..count {
            let card = deck[storage.deck_position].clone();
            storage.table_cards.push(card.clone());
            new_cards.push(card);
            storage.deck_position += 1;
        }

        self.emit_event(Event::CardsDealtToTable(new_cards))
            .expect("Event Error");
    }

    pub async fn card_disclosure(&mut self, instances: Vec<(Card, VerificationVariables)>) {
        let storage = self.get_mut();
        let player = msg::source();
        let partially_decrypted_cards = storage
            .partially_decrypted_cards
            .get(&player)
            .expect("Not in game");

        verify_cards(
            &partially_decrypted_cards,
            instances.clone(),
            &storage.original_card_map,
        );

        let only_proofs = vec![instances[0].1.clone(), instances[1].1.clone()];

        storage
            .decrypt_verificaiton_context
            .verify_batch(only_proofs)
            .await;
        let cards = (instances[0].0.clone(), instances[1].0.clone());
        storage.revealed_players.insert(player, cards);

        let expected_players: HashSet<ActorId> = storage
            .active_participants
            .all()
            .iter()
            .chain(storage.all_in_players.iter())
            .cloned()
            .collect();
        let players: HashSet<ActorId> = storage.revealed_players.keys().cloned().collect();

        if players.is_superset(&expected_players) {
            let table_cards: [Card; 5] = match storage.revealed_table_cards.clone().try_into() {
                Ok(array) => array,
                Err(_) => unreachable!(),
            };

            let (winners, cash_prize) = evaluate_round(
                storage.revealed_players.clone(),
                table_cards,
                &storage.betting_bank,
            );

            for (winner, prize) in winners.iter().zip(cash_prize.clone()) {
                let participant = storage.participants.get_mut(winner).unwrap();
                participant.balance = prize;
            }

            storage.status = Status::Finished {
                winners: winners.clone(),
                cash_prize: cash_prize.clone(),
            };
            self.emit_event(Event::Finished {
                winners,
                cash_prize,
            })
            .expect("Event Error");
        }
    }

    // Query
    pub fn player_cards(&self, player_id: ActorId) -> Option<[EncryptedCard; 2]> {
        self.get()
            .partially_decrypted_cards
            .get(&player_id)
            .cloned()
    }

    pub fn encrypted_table_cards(&self) -> Vec<EncryptedCard> {
        self.get().table_cards.clone()
    }

    pub fn revealed_table_cards(&self) -> Vec<Card> {
        self.get().revealed_table_cards.clone()
    }

    pub fn participants(&self) -> Vec<(ActorId, Participant)> {
        self.get().participants.clone().into_iter().collect()
    }
    pub fn active_participants(&self) -> &'static TurnManager<ActorId> {
        &self.get().active_participants
    }
    pub fn status(&self) -> &'static Status {
        &self.get().status
    }
    pub fn config(&self) -> &'static Config {
        &self.get().config
    }
    pub fn round(&self) -> u32 {
        self.get().round
    }
    pub fn betting(&self) -> &'static Option<BettingStage> {
        &self.get().betting
    }
    pub fn betting_bank(&self) -> Vec<(ActorId, u128)> {
        self.get().betting_bank.clone().into_iter().collect()
    }
    pub fn all_in_players(&self) -> &'static Vec<ActorId> {
        &self.get().all_in_players
    }
    pub fn already_invested_in_the_circle(&self) -> Vec<(ActorId, u128)> {
        self.get()
            .already_invested_in_the_circle
            .clone()
            .into_iter()
            .collect()
    }
    pub fn factory_actor_id(&self) -> ActorId {
        self.get().factory_actor_id
    }
    pub fn pts_actor_id(&self) -> ActorId {
        self.get().pts_actor_id
    }
}
