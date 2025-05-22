use crate::services::{Card, EncryptedCard, Suit};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381_bandersnatch::{EdwardsAffine, EdwardsProjective, Fq, Fr};
use ark_ff::{BigInt, PrimeField};
use sails_rs::{collections::HashMap, prelude::*};

pub fn deserialize_bandersnatch_coords(coords: &[Vec<u8>; 3]) -> EdwardsProjective {
    let x = Fq::from_le_bytes_mod_order(&coords[0]);
    let y = Fq::from_le_bytes_mod_order(&coords[1]);
    let z = Fq::from_le_bytes_mod_order(&coords[2]);
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
            card_map.insert(point, Card::new(suit.clone(), value));

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

pub fn decrypt_point(
    card_map: &HashMap<EdwardsProjective, Card>,
    encrypted_point: &EncryptedCard,
    partial_decryptions: Vec<[Vec<u8>; 3]>,
) -> Option<Card> {
    let mut sum = deserialize_bandersnatch_coords(&partial_decryptions[0]);
    for i in 1..partial_decryptions.len() {
        sum = sum + deserialize_bandersnatch_coords(&partial_decryptions[i]);
    }
    let c1_point = deserialize_bandersnatch_coords(&encrypted_point.c1);
    let decrypted_point = c1_point + sum;
    find_card_by_point(card_map, &decrypted_point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ed_on_bls12_381_bandersnatch::{EdwardsProjective, Fq};
    use ark_ff::UniformRand;
    use ark_std::Zero;
    use num_bigint::BigUint;
    use rand::rngs::OsRng;
    use serde::Deserialize;

    const CARD_MAP_JSON: &str = include_str!("../../test_data/card_map.json");

    #[cfg(test)]
    extern crate std;
    #[cfg(test)]
    use std::println;

    #[derive(Debug, Deserialize)]
    struct JsonCard {
        suit: String,
        rank: String,
        point: JsonPoint,
    }

    #[derive(Debug, Deserialize)]
    struct JsonPoint {
        X: String,
        Y: String,
        Z: String,
    }

    fn decimal_str_to_bytes_32_be(s: &str) -> [u8; 32] {
        let n = BigUint::parse_bytes(s.as_bytes(), 10).expect("Invalid decimal string");
        let mut b = n.to_bytes_be();
        if b.len() > 32 {
            panic!("Value too large for 32 bytes");
        }
        let mut buf = [0u8; 32];
        buf[32 - b.len()..].copy_from_slice(&b);
        buf
    }

    fn key_gen() -> (Fr, EdwardsProjective) {
        let mut rng = ark_std::test_rng();
        let sk = Fr::rand(&mut rng);

        let base_affine = EdwardsAffine::generator();
        let base_point: EdwardsProjective = base_affine.into();

        let pk = base_point * sk;

        (sk, pk)
    }

    fn elgamal_encrypt(
        pk: EdwardsProjective,
        i_c0: EdwardsProjective,
        i_c1: EdwardsProjective,
    ) -> (EdwardsProjective, EdwardsProjective) {
        let mut rng = ark_std::test_rng();
        let r = Fr::rand(&mut rng);
        let base_affine = EdwardsAffine::generator();
        let base_point: EdwardsProjective = base_affine.into();

        let r_g = base_point * r;
        let r_pk = pk * r;

        let c0 = r_g + i_c0;
        let c1 = r_pk + i_c1;

        (c0, c1)
    }

    #[test]
    fn test_decrypt() {
        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();

        for _ in 0..3 {
            let (sk, pk) = key_gen();
            secret_keys.push(sk);
            public_keys.push(pk);
        }
        let agg_pk = public_keys.iter().copied().reduce(|a, b| a + b).unwrap();
        let card_map = init_deck_and_card_map();

        let (point, card) = card_map.iter().next().unwrap();

        let mut c0 = EdwardsProjective::zero();
        let mut c1 = *point;

        for _ in 0..3 {
            let (i_c0, i_c1) = elgamal_encrypt(agg_pk, c0, c1);
            c0 = i_c0;
            c1 = i_c1;
        }

        let mut partial_decryptions = Vec::new();
        for i in 0..3 {
            let sk_c0 = -(c0 * secret_keys[i]);
            let x = sk_c0.x.into_bigint().to_bytes_le();
            let y = sk_c0.y.into_bigint().to_bytes_le();
            let z = sk_c0.z.into_bigint().to_bytes_le();
            partial_decryptions.push([x, y, z]);
        }

        let c0x = c0.x.into_bigint().to_bytes_le();
        let c0y = c0.y.into_bigint().to_bytes_le();
        let c0z = c0.z.into_bigint().to_bytes_le();
        let c1x = c1.x.into_bigint().to_bytes_le();
        let c1y = c1.y.into_bigint().to_bytes_le();
        let c1z = c1.z.into_bigint().to_bytes_le();

        let encrypted_card = EncryptedCard {
            c0: [c0x, c0y, c0z],
            c1: [c1x, c1y, c1z],
        };
        let decrypted_point = decrypt_point(&card_map, &encrypted_card, partial_decryptions)
            .expect("Point is not found");
        assert_eq!(decrypted_point, *card);
        println!("decrypted_point {:?}", decrypted_point);
    }

    #[test]
    fn test_init_deck_and_card_map() {
        let card_map = init_deck_and_card_map();
        let json_cards: Vec<JsonCard> =
            serde_json::from_str(CARD_MAP_JSON).expect("Failed to parse CARD_MAP_JSON");

        assert_eq!(card_map.len(), 52, "Card map must contain 52 cards");
        let mut json_map = HashMap::new();

        for jc in json_cards {
            let x_bytes = decimal_str_to_bytes_32_be(&jc.point.X);
            let y_bytes = decimal_str_to_bytes_32_be(&jc.point.Y);
            let z_bytes = decimal_str_to_bytes_32_be(&jc.point.Z);

            let x = Fq::from_be_bytes_mod_order(&x_bytes);
            let y = Fq::from_be_bytes_mod_order(&y_bytes);
            let z = Fq::from_be_bytes_mod_order(&z_bytes);
            let t = x * y;

            let point = EdwardsProjective::new(x, y, t, z);

            let rank = match jc.rank.as_str() {
                "2" => 2,
                "3" => 3,
                "4" => 4,
                "5" => 5,
                "6" => 6,
                "7" => 7,
                "8" => 8,
                "9" => 9,
                "10" => 10,
                "J" => 11,
                "Q" => 12,
                "K" => 13,
                "A" => 14,
                other => panic!("Unknown rank"),
            };
            let suit = match jc.suit.as_str() {
                "hearts" => Suit::Hearts,
                "diamonds" => Suit::Diamonds,
                "clubs" => Suit::Clubs,
                "spades" => Suit::Spades,
                other => panic!("Unknown suit: {}", other),
            };

            json_map.insert(point, Card::new(suit, rank));
        }
        assert_eq!(card_map, json_map, "Rust-generated map must match JSON");
    }
}
