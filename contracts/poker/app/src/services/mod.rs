#![allow(static_mut_refs)]
use sails_rs::prelude::*;
use sails_rs::collections::HashMap;
use sails_rs::gstd::msg;
use sails_rs::gstd::debug;
use utils::*;
mod utils;

#[derive(Debug)]
struct Storage {
    participants: HashMap<ActorId, Participant>,
    // active_participants - players who can place bets
    // not to be confused with those who are in the game, as there are also all in players.
    active_participants: TurnManager<ActorId>,
    status: Status,
    config: Config,
    round: u128,
    betting: Option<BettingStage>,
    bank: HashMap<ActorId, u128>,
    all_in_players: Vec<ActorId>,
    already_invested_in_the_circle: HashMap<ActorId, u128>, // The mapa is needed to keep track of how much a person has put on the table,
                                                            // which can change after each player's turn
}


#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Status {
    Registration,
    WaitingStart,
    WaitingSetSmallBlind(ActorId),
    WaitingSetBigBlind(ActorId),
    Play {
        stage: Stage,
    },
    WaitingForCardsToBeDisclosed,
    Finished {
        winners: Vec<ActorId>,
        cash_prize: Vec<u128>,
    }
}



#[derive(Debug, Decode, Encode, TypeInfo, Clone, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Action {
    Fold,
    Call,
    Raise,
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
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct Participant {
    name: String,
    card_1: Option<u32>,
    card_2: Option<u32>,

}
static mut STORAGE: Option<Storage> = None;

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Event {
    Registered {
        participant_id: ActorId,
    },
    GameStarted,
    GameCanceled {
        status: Status,
    },
    SmallBlindIsSet,
    BigBlindIsSet,
    TurnIsMade {
        action: Action,
        value: u128,
    },
    NextStage(Stage),
    Finished {
        winners: Vec<ActorId>,
        cash_prize: Vec<u128>,
    }
}


pub struct PokerService(());

impl PokerService {
    pub fn init(config: Config) -> Self {
        let mut participants = HashMap::new();
        participants.insert(config.admin_id, Participant {name: config.admin_name.clone(), card_1: None, card_2: None});
        let mut active_participants = TurnManager::new();
        active_participants.add(config.admin_id);
        unsafe {
            STORAGE = Some(Storage {
                config,
                status: Status::Registration,
                participants,
                active_participants,
                round: 0,
                betting: None,
                bank: HashMap::new(),
                all_in_players: Vec::new(),
                already_invested_in_the_circle: HashMap::new(),
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

    pub fn register(&mut self, player_name: String) {
        let storage = self.get_mut();
        if storage.status != Status::Registration {
            panic("Wrong status");
        }
        let msg_src = msg::source();
        if storage.participants.contains_key(&msg_src) {
            panic("Already registered");
        }

        storage.participants.insert(msg_src, Participant { name: player_name, card_1: None, card_2: None});
        storage.active_participants.add(msg_src);
        if storage.participants.len() == storage.config.number_of_participants as usize {
            storage.status = Status::WaitingStart;
        }
        self.emit_event(Event::Registered{participant_id: msg_src}).expect("Event Invocation Error");
    }
    pub fn start_game(&mut self) {
        // TODO: add necessary logic
        let storage = self.get_mut();
        if msg::source() != storage.config.admin_id {
            panic("Access denied");
        }
        if storage.status != Status::WaitingStart {
            panic("Wrong status");
        }
        storage.status = Status::WaitingSetSmallBlind(storage.active_participants.next().expect("The player must exist"));
        storage.round +=1;
        self.emit_event(Event::GameStarted).expect("Event Invocation Error");
    }
    pub fn cancel_game(&mut self) {
        // TODO: add logic to return value player 
        let storage = self.get_mut();
        if msg::source() != storage.config.admin_id {
            panic("Access denied");
        }
        if storage.participants.len() == storage.config.number_of_participants as usize {
            storage.status = Status::WaitingStart;
        } else {
            storage.status = Status::Registration;
        }

        self.emit_event(Event::GameCanceled{status: storage.status.clone()}).expect("Event Invocation Error");
    }
    
    pub fn set_small_blind(&mut self) {
        let storage = self.get_mut();
        let player = msg::source();
        let value = msg::value();

        if let Status::WaitingSetSmallBlind(id) = storage.status {
            if player != id {
                panic("Access denied");
            }
            if value != storage.config.small_blind {
                panic("Wrong value");
            }
        } else {
            panic("Wrong status");
        }
        storage.already_invested_in_the_circle.insert(player, value);
        storage.bank.insert(player, value);
        storage.status = Status::WaitingSetBigBlind(storage.active_participants.next().expect("The player must exist"));
        self.emit_event(Event::SmallBlindIsSet).expect("Event Invocation Error");
    }

    pub fn set_big_blind(&mut self) {
        let storage = self.get_mut();
        let player = msg::source();
        let value = msg::value();

        let big_blind_id = if let Status::WaitingSetBigBlind(id) = storage.status {
            if player != id {
                panic("Access denied");
            }
            if value != storage.config.big_blind {
                panic("Wrong value");
            }
            id
        } else {
            panic("Wrong status");
        };

        storage.already_invested_in_the_circle.insert(player, value);
        storage.bank.insert(player, value);

        storage.status = Status::Play {stage: Stage::PreFlop};
        storage.betting = Some(BettingStage {
            turn: storage.active_participants.next().expect("The player must exist"),
            current_bet: storage.config.big_blind,
            acted_players: vec![big_blind_id],
        });
        self.emit_event(Event::BigBlindIsSet).expect("Event Invocation Error");
    }

    pub fn turn(&mut self, action: Action) {
        let player = msg::source();
        let value = msg::value();
        let storage = self.get_mut();
    
        let Status::Play {stage} = &mut storage.status else {
            debug!("Wrong status");
            panic("Wrong status");
        };

        let betting = storage.betting.as_mut().expect("Betting must exist");

        if betting.turn != player {
            debug!("Not your turn: betting.turn {:?} player {:?}", betting.turn, player);
            panic("Not your turn");
        }

        // Process the player's action
        match action {
            Action::Fold => {
                storage.active_participants.remove(&player);
            }
            Action::Call => {
                let already_invested = *storage.already_invested_in_the_circle.get(&player).unwrap_or(&0);
                debug!("CALL {:?}", already_invested);
                if already_invested + value != betting.current_bet {
                    panic("Wrong call value");
                }
                betting.acted_players.push(player);
                storage.already_invested_in_the_circle.entry(player).and_modify(|v| *v += value).or_insert(value);
                storage.bank.entry(player).and_modify(|v| *v += value).or_insert(value);
            }
            Action::Check => {
                debug!("HERE {:?}", betting.current_bet);
                let already_invested = *storage.already_invested_in_the_circle.get(&player).unwrap_or(&0);
                if betting.current_bet != already_invested {
                    panic("cannot check");
                }
                betting.acted_players.push(player);
            }
            Action::Raise => {
                let already_invested = *storage.already_invested_in_the_circle.get(&player).unwrap_or(&0);
                if already_invested + value <= betting.current_bet {
                    panic("Raise must be higher");
                }
                betting.current_bet = value;
                // if someone raises the bet, the betting round starts all over again
                // so it is necessary to clear the acted_players
                betting.acted_players.clear();
                betting.acted_players.push(player);
                storage.already_invested_in_the_circle.entry(player).and_modify(|v| *v += value).or_insert(value);
                storage.bank.entry(player).and_modify(|v| *v += value).or_insert(value);
            }
            Action::AllIn => {
                let already_invested = *storage.already_invested_in_the_circle.get(&player).unwrap_or(&0);
                if already_invested + value > betting.current_bet {
                    betting.current_bet = value;
                    betting.acted_players.clear();
                }
                storage.all_in_players.push(player);
                // if a player has made a all in, we remove him from the active_participants, so that he no longer participates in bets
                storage.active_participants.remove(&player);
                storage.already_invested_in_the_circle.entry(player).and_modify(|v| *v += value).or_insert(value);
                storage.bank.entry(player).and_modify(|v| *v += value).or_insert(value);
            }
        }
        debug!("BEFORE TURN {:?}", betting.turn);
        betting.turn = storage.active_participants.next().expect("The player must exist");
        debug!("AFTER TURN {:?}", betting.turn);

        // Check if the game should end immediately (only one player left)
        if storage.active_participants.len() + storage.all_in_players.len() == 1 {
            let winner = if storage.active_participants.is_empty() {
                storage.all_in_players.get(0).expect("The player must exist")
            } else {
                storage.active_participants.get(0).expect("The player must exist")
            };
            storage.status = Status::Finished { winners: vec![*winner], cash_prize: vec![storage.bank.values().sum()] };
            //self.emit_event(Event::Finished { winners: vec![*winner], cash_prize: vec![*bank] }).expect("Event Invocation Error");
        } 
        // Check if the round is complete at the River stage
        else if betting.acted_players.len() == storage.active_participants.len() && *stage == Stage::River {
            // переводим в статус ожидания карт игроков и стола
            storage.status = Status::WaitingForCardsToBeDisclosed;
        }
        // Check if the round is complete before River stage
        else if betting.acted_players.len() == storage.active_participants.len() {
            debug!("NEW CIRCLE");
            // if there's only one active player left, there's no point in betting any more 
            if storage.active_participants.len() == 1 {
                storage.status = Status::WaitingForCardsToBeDisclosed;
            } else {
                storage.active_participants.reset_turn_index();
                storage.already_invested_in_the_circle = HashMap::new();
                betting.turn = storage.active_participants.next().unwrap();
                debug!("TURN {:?}", betting.turn);
                betting.current_bet = 0;
                *stage = stage.clone().next().unwrap();
                self.emit_event(Event::NextStage(stage.clone())).expect("Event Invocation Error");
            }

        }
        self.emit_event(Event::TurnIsMade {action, value}).expect("Event Invocation Error");
    }

    pub fn card_disclosure(&mut self, id_to_cards: Vec<(ActorId, (Card, Card))>, table_cards: Vec<Card>) {
        // TODO: add necessary logic (check difference cards, check msg source)
        let storage = self.get_mut();
        let mut expected_players: Vec<ActorId> = storage.active_participants.all()
            .iter()
            .chain(storage.all_in_players.iter())
            .cloned()
            .collect();

        let mut revealed_players: Vec<ActorId> = id_to_cards
            .iter()
            .map(|(id, _)| *id)
            .collect();

        expected_players.sort();
        revealed_players.sort();

        if expected_players != revealed_players {
            panic("Wrong players");
        }

        if table_cards.len() != 5 {
            panic("Wrong length of table cards");
        }
  
        let table_cards: [Card; 5] = match table_cards.try_into() {
            Ok(array) => array,
            Err(_) => unreachable!("Checked length above, should not fail"),
        };

        let hands = id_to_cards.into_iter().collect();
        let (winners, cash_prize) = evaluate_round(hands, table_cards, &storage.bank);
        storage.status = Status::Finished { winners: winners.clone(), cash_prize: cash_prize.clone() };
        self.emit_event(Event::Finished { winners, cash_prize}).expect("Event Invocation Error");
    }

    // Query
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
    pub fn round(&self) -> u128 {
        self.get().round
    }
    pub fn betting(&self) -> &'static Option<BettingStage> {
        &self.get().betting
    }
    pub fn bank(&self) -> Vec<(ActorId, u128)> {
        self.get().bank.clone().into_iter().collect()
    }
    pub fn all_in_players(&self) -> &'static Vec<ActorId> {
        &self.get().all_in_players
    }
    pub fn already_invested_in_the_circle(&self) -> Vec<(ActorId, u128)> {
        self.get().already_invested_in_the_circle.clone().into_iter().collect()
    }
    

}


