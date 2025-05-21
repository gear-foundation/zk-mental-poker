use ark_bls12_381::Bls12_381;
use ark_bls12_381::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use num_bigint::BigUint;
use num_traits::Num;
use poker_client::{
    EncryptedCard, ProofBytes, PublicKey, VerificationVariables, VerifyingKeyBytes,
};
use serde::Deserialize;
use std::fs;
use std::ops::Neg;
use std::str::FromStr;

#[derive(Debug, Deserialize)]
struct PartialDecryptionCard {
    c0: ECPointJson,
    c1_partial: ECPointJson,
}

#[derive(Debug, Deserialize)]
struct PartialDecryptionEntry {
    publicKey: ECPointJson,
    cards: Vec<PartialDecryptionCard>,
}

#[derive(Debug, Deserialize)]
struct PublicKeyJson {
    index: usize,
    pk: ECPointJson,
}

#[derive(Debug, Deserialize)]
struct ECPointJson {
    #[serde(rename = "X")]
    x: String,
    #[serde(rename = "Y")]
    y: String,
    #[serde(rename = "Z")]
    z: String,
}

#[derive(Deserialize)]
struct ProofJson {
    pi_a: Vec<String>,
    pi_b: Vec<Vec<String>>,
    pi_c: Vec<String>,
}

#[derive(Deserialize)]
struct BatchProofEntry {
    proof: ProofJson,
    publicSignals: Vec<String>,
}

pub fn load_player_public_keys(path: &str) -> Vec<(usize, PublicKey)> {
    let raw = fs::read_to_string(path).expect("failed to read player_pks.json");
    let json: Vec<PublicKeyJson> = serde_json::from_str(&raw).expect("invalid JSON");

    json.into_iter()
        .map(|pk| {
            (
                pk.index,
                PublicKey {
                    x: decimal_str_to_bytes_32(&pk.pk.x),
                    y: decimal_str_to_bytes_32(&pk.pk.y),
                    z: decimal_str_to_bytes_32(&pk.pk.z),
                },
            )
        })
        .collect()
}

fn decimal_str_to_bytes_32(s: &str) -> [u8; 32] {
    let n = BigUint::from_str_radix(s, 10).expect("invalid decimal");
    let b = n.to_bytes_be();
    if b.len() > 32 {
        panic!("too large for 32 bytes");
    }
    let mut buf = [0u8; 32];
    buf[32 - b.len()..].copy_from_slice(&b);
    buf
}

pub fn load_partial_decrypt_proofs(path: &str) -> Vec<VerificationVariables> {
    let content = std::fs::read_to_string(path).expect("Cannot read partial_decrypt_proofs.json");
    let parsed: Vec<BatchProofEntry> = serde_json::from_str(&content).expect("invalid JSON");

    parsed
        .into_iter()
        .map(|entry| {
            let proof = Proof {
                a: deserialize_g1(&entry.proof.pi_a),
                b: deserialize_g2(&entry.proof.pi_b).unwrap(),
                c: deserialize_g1(&entry.proof.pi_c),
            };

            let public_inputs = parse_public_signals(&entry.publicSignals);

            VerificationVariables {
                proof_bytes: encode_proof(&proof),
                public_input: encode_inputs(&public_inputs),
            }
        })
        .collect()
}

pub fn get_vkey(path: &str) -> VerifyingKeyBytes {
    let json = fs::read_to_string(path).unwrap();
    let vkey: VKey = serde_json::from_str(&json).unwrap();
    let alpha = deserialize_g1(&vkey.vk_alpha_1);
    let mut buf = Vec::new();
    alpha.serialize_compressed(&mut buf).unwrap();

    let beta = deserialize_g2(&(vkey.vk_beta_2.to_vec())).unwrap();
    let gamma = deserialize_g2(&vkey.vk_gamma_2).unwrap();
    let delta = deserialize_g2(&vkey.vk_delta_2).unwrap();

    // IC: Vec<G1Affine> from [String; 3]
    let ic_points: Vec<G1Affine> = vkey.IC.iter().map(|p| deserialize_g1(p)).collect();

    // pairing(alpha, beta)
    let alpha_g1_beta_g2 = Bls12_381::pairing(alpha, beta).0;

    let mut alpha_beta_bytes = Vec::new();
    alpha_g1_beta_g2
        .serialize_uncompressed(&mut alpha_beta_bytes)
        .unwrap();

    let gamma_g2_neg_pc = gamma.into_group().neg().into_affine();
    let delta_g2_neg_pc = delta.into_group().neg().into_affine();

    let mut gamma_neg_bytes = Vec::new();
    gamma_g2_neg_pc
        .serialize_uncompressed(&mut gamma_neg_bytes)
        .unwrap();

    let mut delta_neg_bytes = Vec::new();
    delta_g2_neg_pc
        .serialize_uncompressed(&mut delta_neg_bytes)
        .unwrap();

    let mut ic_uncompressed: Vec<Vec<u8>> = vec![];

    for ic in ic_points.clone() {
        let mut buf = Vec::new();
        ic.serialize_uncompressed(&mut buf).unwrap();
        assert_eq!(buf.len(), 96);
        ic_uncompressed.push(buf);
    }
    VerifyingKeyBytes {
        alpha_g1_beta_g2: alpha_beta_bytes,
        gamma_g2_neg_pc: gamma_neg_bytes,
        delta_g2_neg_pc: delta_neg_bytes,
        ic: ic_uncompressed,
    }
}
pub fn load_partial_decryptions(path: &str) -> Vec<(PublicKey, [EncryptedCard; 2])> {
    let raw = fs::read_to_string(path).expect("failed to read partial_decryptions.json");
    let json: Vec<PartialDecryptionEntry> = serde_json::from_str(&raw).expect("invalid JSON");

    json.into_iter()
        .map(|entry| {
            let pk = PublicKey {
                x: decimal_str_to_bytes_32(&entry.publicKey.x),
                y: decimal_str_to_bytes_32(&entry.publicKey.y),
                z: decimal_str_to_bytes_32(&entry.publicKey.z),
            };

            if entry.cards.len() != 2 {
                panic!("Expected exactly 2 cards per player");
            }

            let encrypted_cards = [
                EncryptedCard {
                    c0: [
                        from_decimal_string(&entry.cards[0].c0.x),
                        from_decimal_string(&entry.cards[0].c0.y),
                        from_decimal_string(&entry.cards[0].c0.z),
                    ],
                    c1: [
                        from_decimal_string(&entry.cards[0].c1_partial.x),
                        from_decimal_string(&entry.cards[0].c1_partial.y),
                        from_decimal_string(&entry.cards[0].c1_partial.z),
                    ],
                },
                EncryptedCard {
                    c0: [
                        from_decimal_string(&entry.cards[1].c0.x),
                        from_decimal_string(&entry.cards[1].c0.y),
                        from_decimal_string(&entry.cards[1].c0.z),
                    ],
                    c1: [
                        from_decimal_string(&entry.cards[1].c1_partial.x),
                        from_decimal_string(&entry.cards[1].c1_partial.y),
                        from_decimal_string(&entry.cards[1].c1_partial.z),
                    ],
                },
            ];

            (pk, encrypted_cards)
        })
        .collect()
}

pub fn load_shuffle_proofs(path: &str) -> Vec<VerificationVariables> {
    let content = fs::read_to_string(path).expect("cannot read shuffle_proofs.json");
    let parsed: Vec<BatchProofEntry> = serde_json::from_str(&content).expect("invalid JSON");

    parsed
        .into_iter()
        .map(|entry| {
            let proof = Proof {
                a: deserialize_g1(&entry.proof.pi_a),
                b: deserialize_g2(&entry.proof.pi_b).unwrap(),
                c: deserialize_g1(&entry.proof.pi_c),
            };

            let public_inputs = parse_public_signals(&entry.publicSignals);

            VerificationVariables {
                proof_bytes: encode_proof(&proof),
                public_input: encode_inputs(&public_inputs),
            }
        })
        .collect()
}

pub fn load_encrypted_table_cards(path: &str) -> Vec<EncryptedCard> {
    let raw = fs::read_to_string(path).expect("failed to read encrypted_deck.json");
    let json: Vec<Vec<String>> = serde_json::from_str(&raw).expect("invalid JSON");

    if json.len() != 6 {
        panic!("Expected 6 rows for encrypted deck");
    }

    // Предполагаем, что первые 5 карт в деке — это карты на стол
    let num_table_cards = 52;
    let mut table_cards = Vec::with_capacity(num_table_cards);

    for i in 0..num_table_cards {
        let c0 = [
            from_decimal_string(&json[0][i]), // X
            from_decimal_string(&json[1][i]), // Y
            from_decimal_string(&json[2][i]), // Z
        ];
        let c1 = [
            from_decimal_string(&json[3][i]), // X
            from_decimal_string(&json[4][i]), // Y
            from_decimal_string(&json[5][i]), // Z
        ];

        table_cards.push(EncryptedCard { c0, c1 });
    }

    table_cards
}

fn from_decimal_string(s: &str) -> Vec<u8> {
    let n = BigUint::from_str_radix(s, 10).expect("invalid number");
    let mut b = n.to_bytes_be();
    while b.len() < 32 {
        b.insert(0, 0);
    }
    b
}

#[derive(serde::Deserialize)]
pub struct VKey {
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    pub IC: Vec<Vec<String>>,
}

pub fn deserialize_g1(point: &Vec<String>) -> G1Affine {
    let x_biguint = BigUint::from_str_radix(&point[0], 10).unwrap();
    let y_biguint = BigUint::from_str_radix(&point[1], 10).unwrap();

    let mut x_bytes = [0u8; 48];
    let mut y_bytes = [0u8; 48];

    let x_b = x_biguint.to_bytes_be();
    let y_b = y_biguint.to_bytes_be();

    x_bytes[48 - x_b.len()..].copy_from_slice(&x_b);
    y_bytes[48 - y_b.len()..].copy_from_slice(&y_b);

    let x = Fq::from_be_bytes_mod_order(&x_bytes);
    let y = Fq::from_be_bytes_mod_order(&y_bytes);

    G1Affine::new(x, y)
}

pub fn deserialize_g2(coords: &[Vec<String>]) -> Result<G2Affine, String> {
    if coords.len() != 3 {
        return Err("G2Affine coordinates must have exactly 3 pairs".to_string());
    }

    if coords[2][0] != "1" || coords[2][1] != "0" {
        return Err("Expected third coordinate to be [1, 0] for affine representation".to_string());
    }

    let x_c0 = Fq::from_str(&coords[0][0]).map_err(|_| "Invalid x_c1 coordinate".to_string())?;
    let x_c1 = Fq::from_str(&coords[0][1]).map_err(|_| "Invalid x_c0 coordinate".to_string())?;

    let y_c0 = Fq::from_str(&coords[1][0]).map_err(|_| "Invalid y_c1 coordinate".to_string())?;
    let y_c1 = Fq::from_str(&coords[1][1]).map_err(|_| "Invalid y_c0 coordinate".to_string())?;

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    Ok(G2Affine::new(x, y))
}

fn parse_public_signals(signals: &[String]) -> Vec<Fr> {
    signals
        .iter()
        .map(|s| {
            let n = BigUint::from_str_radix(s, 10).unwrap();
            let bytes = n.to_bytes_le();
            let mut buf = [0u8; 32];
            buf[..bytes.len()].copy_from_slice(&bytes);
            Fr::from_le_bytes_mod_order(&buf)
        })
        .collect()
}

#[derive(Debug)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

fn encode_proof(proof: &Proof) -> ProofBytes {
    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();
    let mut c_bytes = Vec::new();

    proof.a.serialize_uncompressed(&mut a_bytes).unwrap();
    proof.b.serialize_uncompressed(&mut b_bytes).unwrap();
    proof.c.serialize_uncompressed(&mut c_bytes).unwrap();

    ProofBytes {
        a: a_bytes,
        b: b_bytes,
        c: c_bytes,
    }
}

fn encode_inputs(inputs: &[Fr]) -> Vec<Vec<u8>> {
    inputs
        .iter()
        .map(|fr| {
            let mut buf = Vec::new();
            fr.serialize_uncompressed(&mut buf).unwrap();
            buf
        })
        .collect()
}
