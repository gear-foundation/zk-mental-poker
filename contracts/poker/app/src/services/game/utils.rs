use core::fmt::Debug;
use sails_rs::collections::HashMap;
use sails_rs::prelude::*;
use sails_rs::{ActorId, Vec};

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct TurnManager<Id> {
    active_ids: Vec<Id>,
    turn_index: u64,
    first_index: u16,
}

#[allow(clippy::new_without_default)]
impl<Id: Eq + Clone + Debug> TurnManager<Id> {
    pub fn new() -> Self {
        Self {
            active_ids: Vec::new(),
            turn_index: 0,
            first_index: 0,
        }
    }

    pub fn new_round(&mut self) {
        self.first_index = (self.first_index + 1) % self.active_ids.len() as u16;
    }

    pub fn add(&mut self, id: Id) {
        self.active_ids.push(id.clone());
    }

    pub fn remove(&mut self, id: &Id) {
        if let Some(pos) = self.active_ids.iter().position(|x| x == id) {
            self.active_ids.remove(pos);

            if self.turn_index as usize > pos {
                self.turn_index -= 1;
            } else if self.turn_index as usize >= self.active_ids.len() {
                self.turn_index = 0;
            }
        }
    }

    pub fn next(&mut self) -> Option<Id> {
        if self.active_ids.is_empty() {
            return None;
        }
        let id = self.active_ids[self.turn_index as usize].clone();
        self.turn_index = (self.turn_index + 1) % self.active_ids.len() as u64;
        Some(id)
    }

    pub fn skip_and_remove(&mut self, n: u64) -> Option<Id> {
        if self.active_ids.is_empty() || n == 0 {
            return None;
        }

        let mut last_removed = None;

        let mut idx = if self.turn_index == 0 {
            self.active_ids.len() - 1
        } else {
            (self.turn_index - 1) as usize
        };

        for _ in 0..n {
            if self.active_ids.is_empty() {
                break;
            }

            if idx >= self.active_ids.len() {
                idx = 0;
            }

            let removed = self.active_ids.remove(idx);
            last_removed = Some(removed.clone());

            if (self.turn_index as usize > idx)
                || (self.turn_index as usize == idx && self.turn_index > 0)
            {
                self.turn_index -= 1;
            }
        }

        let result_id = if self.active_ids.is_empty() {
            last_removed.expect("At least one player should have been removed")
        } else {
            let id = self.active_ids[self.turn_index as usize].clone();
            self.turn_index = (self.turn_index + 1) % self.active_ids.len() as u64;
            id
        };

        Some(result_id)
    }

    pub fn reset_turn_index(&mut self) {
        self.turn_index = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.active_ids.is_empty()
    }

    pub fn len(&self) -> usize {
        self.active_ids.len()
    }

    pub fn current(&self) -> Option<&Id> {
        self.active_ids.get(self.turn_index as usize)
    }

    pub fn all(&self) -> &Vec<Id> {
        &self.active_ids
    }

    pub fn get(&self, index: usize) -> Option<&Id> {
        self.active_ids.get(index)
    }

    pub fn peek_next(&self) -> Option<&Id> {
        if self.active_ids.is_empty() {
            return None;
        }
        let next_index = (self.turn_index + 1) % self.active_ids.len() as u64;
        self.active_ids.get(next_index as usize)
    }
    pub fn peek_prev(&self) -> Option<&Id> {
        if self.active_ids.is_empty() {
            return None;
        }

        let prev_index = if self.turn_index == 0 {
            self.active_ids.len() - 1
        } else {
            self.turn_index as usize - 1
        };

        self.active_ids.get(prev_index)
    }

    pub fn set_first_index(&mut self) {
        self.turn_index = self.first_index as u64;
    }

    pub fn remove_and_update_first_index(&mut self, id: &Id) {
        if let Some(pos) = self.active_ids.iter().position(|x| x == id) {
            self.active_ids.remove(pos);

            if self.first_index as usize > pos {
                self.first_index -= 1;
            } else if self.first_index as usize >= self.active_ids.len() {
                self.first_index = 0;
            }
        }
    }

    pub fn clear_all(&mut self) {
        self.active_ids.clear();
        self.turn_index = 0;
    }
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct BettingStage {
    pub turn: ActorId,
    pub last_active_time: Option<u64>,
    pub current_bet: u128,
    pub acted_players: Vec<ActorId>, // players who have placed a bet (Check or Call)
                                     // it's to keep track of when the lap ends
}

#[derive(Debug, Clone, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Stage {
    PreFlop,
    WaitingTableCardsAfterPreFlop,
    Flop,
    WaitingTableCardsAfterFlop,
    Turn,
    WaitingTableCardsAfterTurn,
    River,
}

impl Stage {
    pub fn next(self) -> Option<Stage> {
        match self {
            Stage::PreFlop => Some(Stage::WaitingTableCardsAfterPreFlop),
            Stage::WaitingTableCardsAfterPreFlop => Some(Stage::Flop),
            Stage::Flop => Some(Stage::WaitingTableCardsAfterFlop),
            Stage::WaitingTableCardsAfterFlop => Some(Stage::Turn),
            Stage::Turn => Some(Stage::WaitingTableCardsAfterTurn),
            Stage::WaitingTableCardsAfterTurn => Some(Stage::River),
            Stage::River => None,
        }
    }
}

#[derive(Debug, Clone, Hash, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub enum Suit {
    Spades,   // ♠
    Hearts,   // ♥
    Diamonds, // ♦
    Clubs,    // ♣
}

#[derive(Debug, Clone, Hash, Encode, Decode, TypeInfo, PartialEq, Eq)]
#[codec(crate = sails_rs::scale_codec)]
#[scale_info(crate = sails_rs::scale_info)]
pub struct Card {
    pub value: u8, // 2–14 (where 11-J, 12-Q, 13-K, 14-A)
    pub suit: Suit,
}

impl Card {
    pub fn new(suit: Suit, value: u8) -> Self {
        Card { suit, value }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HandRank {
    HighCard(Vec<u8>),
    Pair(u8, Vec<u8>),
    TwoPair(u8, u8, u8),
    ThreeOfAKind(u8, Vec<u8>),
    Straight(u8),
    Flush(Vec<u8>),
    FullHouse(u8, u8),
    FourOfAKind(u8, u8),
    StraightFlush(u8),
}

fn highest_straight_high(values: &[u8]) -> Option<u8> {
    // Finds the BEST (according to the senior card) straight in the set of values (ace = 14)
    let mut u = values.to_vec();
    u.sort();
    u.dedup();

    // standard streets — search from the end (highest)
    for w in u.windows(5).rev() {
        if w[0] + 1 == w[1] && w[1] + 1 == w[2] && w[2] + 1 == w[3] && w[3] + 1 == w[4] {
            return Some(w[4]);
        }
    }

    // wheel A-2-3-4-5
    if u.contains(&14) && u.contains(&2) && u.contains(&3) && u.contains(&4) && u.contains(&5) {
        return Some(5);
    }

    None
}

fn rank_hand(cards: Vec<Card>) -> HandRank {
    let mut values: Vec<u8> = Vec::new();
    let mut suits: HashMap<Suit, Vec<u8>> = HashMap::new();

    for card in &cards {
        values.push(card.value);
        suits.entry(card.suit.clone()).or_default().push(card.value);
    }

    // ----- Straight Flush (looking for a COMPLETE set of master cards) -----
    let mut best_sf: Option<u8> = None;
    for vs in suits.values() {
        if vs.len() >= 5 {
            if let Some(h) = highest_straight_high(vs) {
                best_sf = Some(best_sf.map_or(h, |cur| cur.max(h)));
            }
        }
    }
    if let Some(h) = best_sf {
        return HandRank::StraightFlush(h);
    }

    // Preparing counters by values
    values.sort_by(|a, b| b.cmp(a));
    // For High Card and Flush, we only use the top 5 where necessary.
    let mut counts: HashMap<u8, u8> = HashMap::with_capacity(7);
    for &v in &values {
        *counts.entry(v).or_insert(0) += 1;
    }

    let mut count_vec: Vec<_> = counts.iter().collect();
    // sorting: by multiplicity, then by value
    count_vec.sort_by(|a, b| b.1.cmp(a.1).then(b.0.cmp(a.0)));
    match count_vec[..] {
        [(&a, &4), (&b, _), ..] => return HandRank::FourOfAKind(a, b),
        [(&a, &3), (&b, &3), ..] => return HandRank::FullHouse(a.max(b), a.min(b)),
        [(&a, &3), (&b, &2), ..] => return HandRank::FullHouse(a, b),
        [(&a, &3), ..] => {
            let kickers: Vec<u8> = values.iter().copied().filter(|&v| v != a).take(2).collect();
            return HandRank::ThreeOfAKind(a, kickers);
        }
        [(&a, &2), (&b, &2), ..] if a != b => {
            let kicker = count_vec
                .iter()
                .filter_map(|&(&val, &cnt)| {
                    if val != a && val != b && cnt >= 1 {
                        Some(val)
                    } else {
                        None
                    }
                })
                .max()
                .unwrap_or(0);
            return HandRank::TwoPair(a.max(b), a.min(b), kicker);
        }
        [(&a, &2), ..] => {
            let kickers: Vec<u8> = values.iter().copied().filter(|&v| v != a).take(3).collect();
            return HandRank::Pair(a, kickers);
        }

        _ => {}
    }

    // ----- Flush (take the TOP 5 in the lexicographical sense) -----
    let mut best_flush: Option<Vec<u8>> = None;
    for vs in suits.values() {
        if vs.len() >= 5 {
            let mut t = vs.clone();
            t.sort_by(|a, b| b.cmp(a));
            t.truncate(5);
            if best_flush.as_ref().map_or(true, |b| &t > b) {
                best_flush = Some(t);
            }
        }
    }
    if let Some(s) = best_flush {
        return HandRank::Flush(s);
    }

    // ----- Straight (highest) -----
    if let Some(h) = highest_straight_high(&values) {
        return HandRank::Straight(h);
    }

    // ----- High card: only the top 5 -----
    let mut top5 = values.clone();
    top5.truncate(5);
    HandRank::HighCard(top5)
}

pub fn evaluate_round(
    hands: HashMap<ActorId, (Card, Card)>,
    table_cards: [Card; 5],
    bank: &HashMap<ActorId, u128>,
) -> Vec<(u128, Vec<ActorId>)> {
    let mut pots: Vec<(Vec<ActorId>, u128)> = Vec::new();
    let mut stakes: Vec<(ActorId, u128)> = bank
        .iter()
        .filter_map(|(id, &amt)| (amt > 0).then_some((*id, amt)))
        .collect();

    stakes.sort_unstable_by_key(|&(_, amt)| amt);

    while !stakes.is_empty() {
        let min_amt = stakes[0].1;
        if min_amt == 0 {
            stakes.retain(|&(_, amt)| amt > 0);
            continue;
        }
        let mut pot = 0;
        let mut eligible = Vec::new();

        for (id, amount) in &mut stakes {
            let take = min_amt.min(*amount);
            pot += take;
            *amount -= take;
            eligible.push(*id);
        }

        if pot > 0 {
            pots.push((eligible.clone(), pot));
        }

        stakes.retain(|&(_, amt)| amt > 0);
    }

    let mut rankings: HashMap<ActorId, HandRank> = HashMap::new();
    for (id, (c1, c2)) in &hands {
        let mut cards = vec![c1.clone(), c2.clone()];
        cards.extend_from_slice(&table_cards);
        rankings.insert(*id, rank_hand(cards));
    }

    let mut results: Vec<(u128, Vec<ActorId>)> = Vec::new();
    for (eligible, pot_amount) in pots {
        let mut ranked: Vec<_> = eligible
            .iter()
            .filter_map(|id| rankings.get(id).map(|r| (id, r)))
            .collect();

        ranked.sort_by(|a, b| b.1.cmp(a.1)); // strongest hand first

        if let Some(best_rank) = ranked.clone().first().map(|(_, rank)| rank) {
            let winners: Vec<ActorId> = ranked
                .into_iter()
                .filter(|(_, rank)| rank == best_rank)
                .map(|(id, _)| *id)
                .collect();

            results.push((pot_amount, winners));
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pots_eq(actual: Vec<(u128, Vec<ActorId>)>, expected: Vec<(u128, Vec<ActorId>)>) {
        assert_eq!(actual.len(), expected.len(), "Number of pots differ");
        for (a, e) in actual.iter().zip(expected.iter()) {
            assert_eq!(a.0, e.0, "Pot amounts differ");
            let mut actual_winners = a.1.clone();
            let mut expected_winners = e.1.clone();
            actual_winners.sort();
            expected_winners.sort();
            assert_eq!(actual_winners, expected_winners, "Pot winners differ");
        }
    }

    #[test]
    fn test_high_card() {
        // player 2 should win whole pot
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 6), Card::new(Suit::Spades, 12)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 9), Card::new(Suit::Hearts, 14)),
        );
        hands.insert(
            3.into(),
            (Card::new(Suit::Diamonds, 11), Card::new(Suit::Spades, 13)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 5),
            Card::new(Suit::Hearts, 10),
            Card::new(Suit::Clubs, 7),
            Card::new(Suit::Diamonds, 4),
            Card::new(Suit::Diamonds, 2),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);
        bank.insert(3.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(300, vec![2.into()])]);
    }

    #[test]
    fn test_straight_flush() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 6), Card::new(Suit::Hearts, 8)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 9), Card::new(Suit::Spades, 4)),
        );
        hands.insert(
            3.into(),
            (Card::new(Suit::Spades, 7), Card::new(Suit::Spades, 3)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 5),
            Card::new(Suit::Hearts, 9),
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Diamonds, 4),
            Card::new(Suit::Diamonds, 10),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);
        bank.insert(3.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(300, vec![1.into()])]);
    }

    #[test]
    fn test_straight_and_flush() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 6), Card::new(Suit::Hearts, 11)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 9), Card::new(Suit::Spades, 11)),
        );
        hands.insert(
            3.into(),
            (Card::new(Suit::Spades, 7), Card::new(Suit::Spades, 3)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 5),
            Card::new(Suit::Hearts, 8),
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Diamonds, 4),
            Card::new(Suit::Diamonds, 10),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);
        bank.insert(3.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(300, vec![1.into()])]);
    }

    #[test]
    fn test_pair_kicker() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 10), Card::new(Suit::Clubs, 14)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 10), Card::new(Suit::Diamonds, 3)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 4),
            Card::new(Suit::Spades, 10),
            Card::new(Suit::Hearts, 13),
            Card::new(Suit::Diamonds, 13),
            Card::new(Suit::Clubs, 2),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![1.into()])]);
    }

    #[test]
    fn test_wheel_straight_vs_high_straight() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 2), Card::new(Suit::Clubs, 3)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 8), Card::new(Suit::Diamonds, 9)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 4),
            Card::new(Suit::Spades, 5),
            Card::new(Suit::Hearts, 14),
            Card::new(Suit::Diamonds, 6),
            Card::new(Suit::Clubs, 7),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![2.into()])]);
    }

    #[test]
    fn test_three_of_a_kind_vs_two_pair() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 7), Card::new(Suit::Clubs, 7)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 10), Card::new(Suit::Diamonds, 10)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Spades, 6),
            Card::new(Suit::Hearts, 6),
            Card::new(Suit::Diamonds, 2),
            Card::new(Suit::Clubs, 3),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![1.into()])]);
    }

    #[test]
    fn test_full_house_beats_flush() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 5), Card::new(Suit::Hearts, 2)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 6), Card::new(Suit::Diamonds, 6)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 6),
            Card::new(Suit::Clubs, 7),
            Card::new(Suit::Hearts, 8),
            Card::new(Suit::Hearts, 9),
            Card::new(Suit::Clubs, 9),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![2.into()])]);
    }

    #[test]
    fn test_side_pot_split() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 14), Card::new(Suit::Diamonds, 14)),
        ); // AA
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 13), Card::new(Suit::Clubs, 13)),
        ); // KK
        hands.insert(
            3.into(),
            (Card::new(Suit::Spades, 2), Card::new(Suit::Clubs, 3)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 10),
            Card::new(Suit::Diamonds, 9),
            Card::new(Suit::Clubs, 4),
            Card::new(Suit::Spades, 7),
            Card::new(Suit::Diamonds, 6),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 200);
        bank.insert(3.into(), 200);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(
            pots,
            vec![
                (300, vec![1.into()]), // main pot
                (200, vec![2.into()]), // side pot
            ],
        );
    }

    #[test]
    fn test_split_pot_same_hand() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 10), Card::new(Suit::Clubs, 9)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 10), Card::new(Suit::Diamonds, 9)),
        );
        hands.insert(
            3.into(),
            (Card::new(Suit::Spades, 2), Card::new(Suit::Hearts, 3)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 8),
            Card::new(Suit::Diamonds, 7),
            Card::new(Suit::Clubs, 6),
            Card::new(Suit::Spades, 4),
            Card::new(Suit::Hearts, 2),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 150);
        bank.insert(2.into(), 150);
        bank.insert(3.into(), 150);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(450, vec![1.into(), 2.into()])]);
    }

    #[test]
    fn test_pots_1() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Diamonds, 6), Card::new(Suit::Hearts, 8)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Diamonds, 13), Card::new(Suit::Hearts, 3)),
        );
        hands.insert(
            3.into(),
            (Card::new(Suit::Hearts, 13), Card::new(Suit::Diamonds, 8)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Clubs, 5),
            Card::new(Suit::Diamonds, 14),
            Card::new(Suit::Spades, 13),
            Card::new(Suit::Spades, 9),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 500);
        bank.insert(3.into(), 500);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(300, vec![1.into()]), (800, vec![3.into()])]);
    }

    #[test]
    fn test_pots_2() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Diamonds, 6), Card::new(Suit::Hearts, 8)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Diamonds, 13), Card::new(Suit::Hearts, 3)),
        );
        hands.insert(
            3.into(),
            (Card::new(Suit::Hearts, 13), Card::new(Suit::Diamonds, 3)),
        );

        let table_cards = [
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Clubs, 5),
            Card::new(Suit::Diamonds, 14),
            Card::new(Suit::Spades, 13),
            Card::new(Suit::Spades, 9),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 500);
        bank.insert(3.into(), 500);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(
            pots,
            vec![(300, vec![1.into()]), (800, vec![2.into(), 3.into()])],
        );
    }

    #[test]
    fn test_split_same_board_straight() {
        let table_cards = [
            Card::new(Suit::Hearts, 5),
            Card::new(Suit::Clubs, 6),
            Card::new(Suit::Diamonds, 7),
            Card::new(Suit::Spades, 8),
            Card::new(Suit::Hearts, 9),
        ];

        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Clubs, 13), Card::new(Suit::Spades, 14)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Diamonds, 4), Card::new(Suit::Clubs, 2)),
        );

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![1.into(), 2.into()])]);
    }

    #[test]
    fn test_straight_flush_not_only_from_top5_suited() {
        // A♥ 9♥ 5♥ 4♥
        let table_cards = [
            Card::new(Suit::Hearts, 14),
            Card::new(Suit::Hearts, 9),
            Card::new(Suit::Hearts, 5),
            Card::new(Suit::Hearts, 4),
            Card::new(Suit::Clubs, 7),
        ];

        let mut hands = HashMap::new();
        // player 1 get 3♥ 2♥ => A♥,5♥,4♥,3♥,2♥
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 3), Card::new(Suit::Hearts, 2)),
        );
        // player 2 without ♥
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 14), Card::new(Suit::Diamonds, 12)),
        );

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![1.into()])]);
    }

    #[test]
    fn test_high_card_uses_only_top5() {
        let table_cards = [
            Card::new(Suit::Spades, 13),   // K
            Card::new(Suit::Diamonds, 12), // Q
            Card::new(Suit::Clubs, 9),
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Clubs, 4),
        ];

        let mut hands = HashMap::new();
        // Both get A-high
        hands.insert(
            1.into(),
            (Card::new(Suit::Clubs, 14), Card::new(Suit::Diamonds, 2)),
        ); // A,2
        hands.insert(
            2.into(),
            (Card::new(Suit::Hearts, 14), Card::new(Suit::Spades, 3)),
        ); // A,3

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![1.into(), 2.into()])]);
    }

    #[test]
    fn test_wheel_does_not_override_higher_straight() {
        let table_cards = [
            Card::new(Suit::Hearts, 14), // A
            Card::new(Suit::Diamonds, 2),
            Card::new(Suit::Clubs, 3),
            Card::new(Suit::Spades, 4),
            Card::new(Suit::Clubs, 13), // K
        ];

        let mut hands = HashMap::new();
        // Player 1: 5 и 6 => Straight 2-6
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 5), Card::new(Suit::Diamonds, 6)),
        );
        // Player 2: only 5 => wheel (5-high)
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 5), Card::new(Suit::Clubs, 9)),
        );

        let mut bank = HashMap::new();
        bank.insert(1.into(), 100);
        bank.insert(2.into(), 100);

        let pots = evaluate_round(hands, table_cards, &bank);
        assert_pots_eq(pots, vec![(200, vec![1.into()])]);
    }

    #[test]
    fn test_full_house_from_double_trips() {
        // 7 7 7 9 9
        let table = [
            Card::new(Suit::Hearts, 7),
            Card::new(Suit::Clubs, 7),
            Card::new(Suit::Diamonds, 7),
            Card::new(Suit::Spades, 9),
            Card::new(Suit::Hearts, 9),
        ];

        // Player 1: 9 => 9-9-9 и 7-7-7 => FullHouse(9,7)
        // Player 2: A A => FullHouse(7,14))
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Clubs, 9), Card::new(Suit::Spades, 2)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Clubs, 14), Card::new(Suit::Diamonds, 14)),
        );

        let mut bank = HashMap::new();
        bank.insert(1.into(), 200);
        bank.insert(2.into(), 200);

        let pots = evaluate_round(hands, table, &bank);
        // (FullHouse(9,7) > FullHouse(7,14))
        assert_pots_eq(pots, vec![(400, vec![1.into()])]);
    }

    #[test]
    fn test_zero_bank_entries_are_ignored() {
        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 14), Card::new(Suit::Clubs, 2)),
        );
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 13), Card::new(Suit::Diamonds, 3)),
        );

        let table = [
            Card::new(Suit::Clubs, 10),
            Card::new(Suit::Clubs, 9),
            Card::new(Suit::Hearts, 8),
            Card::new(Suit::Spades, 7),
            Card::new(Suit::Diamonds, 6),
        ];

        let mut bank = HashMap::new();
        bank.insert(1.into(), 0); // zero contribution to waste
        bank.insert(2.into(), 200); // real contribution

        let pots = evaluate_round(hands, table, &bank);
        assert_pots_eq(pots, vec![(200, vec![2.into()])]);
    }

    #[test]
    fn test_board_quads_kicker_matters() {
        // 9 9 9 9 2
        let table = [
            Card::new(Suit::Hearts, 9),
            Card::new(Suit::Clubs, 9),
            Card::new(Suit::Diamonds, 9),
            Card::new(Suit::Spades, 9),
            Card::new(Suit::Hearts, 2),
        ];

        let mut hands = HashMap::new();
        hands.insert(
            1.into(),
            (Card::new(Suit::Clubs, 14), Card::new(Suit::Spades, 3)),
        ); // A-kicker
        hands.insert(
            2.into(),
            (Card::new(Suit::Diamonds, 13), Card::new(Suit::Clubs, 3)),
        ); // K-kicker

        let mut bank = HashMap::new();
        bank.insert(1.into(), 150);
        bank.insert(2.into(), 150);

        let pots = evaluate_round(hands, table, &bank);
        assert_pots_eq(pots, vec![(300, vec![1.into()])]);
    }

    #[test]
    fn test_main_and_two_side_pots_with_ties() {
        // A=100, B=200, C=350
        let mut bank = HashMap::new();
        bank.insert(1.into(), 100); // A
        bank.insert(2.into(), 200); // B
        bank.insert(3.into(), 350); // C

        // Let's select so that:
        // - In the main pot, A and B split, C loses
        // - In the first side pot (B vs C), C wins
        // - In the second side pot (only C) — obviously C
        let mut hands = HashMap::new();
        // A: Straight 10-A
        hands.insert(
            1.into(),
            (Card::new(Suit::Hearts, 14), Card::new(Suit::Clubs, 10)),
        );
        // B: also a straight 10-A
        hands.insert(
            2.into(),
            (Card::new(Suit::Spades, 14), Card::new(Suit::Diamonds, 10)),
        );
        // C: only a pair (loses to the main pot), but a strong hand for the side pot
        hands.insert(
            3.into(),
            (Card::new(Suit::Hearts, 13), Card::new(Suit::Spades, 13)),
        );

        let table = [
            Card::new(Suit::Clubs, 11),
            Card::new(Suit::Diamonds, 12),
            Card::new(Suit::Spades, 13),
            Card::new(Suit::Hearts, 9),
            Card::new(Suit::Clubs, 8),
        ];

        let pots = evaluate_round(hands, table, &bank);

        // We expect:
        // main: 100*3 = 300 → divide A and B
        // side1: (200-100)*2 = 200 → B vs C, C wins
        // side2: (350-200) = 150 → only C
        assert_pots_eq(
            pots,
            vec![
                (300, vec![1.into(), 2.into()]),
                (200, vec![2.into()]),
                (150, vec![3.into()]),
            ],
        );
    }
}
