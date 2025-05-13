use gclient::{EventProcessor, GearApi, Result};
use sails_rs::{ActorId, Decode, Encode, U256};
mod utils_gclient;
use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ec::CurveGroup;
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_ff::{BigInteger256, PrimeField};
use ark_scale::ArkScale;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use core::ops::AddAssign;
use num_bigint::BigUint;
use num_traits::Num;
use poker_client::{ProofBytes, VerificationVariables, traits::*};
use serde::Deserialize;
use std::fs;
use std::ops::Neg;
use std::str::FromStr;
use utils_gclient::*;

fn parse_field_element(s: &str) -> BigInteger256 {
    BigInteger256::from_str(s).expect("Failed to parse field element")
}

// Convert pi_a from string array to G1Affine
fn parse_g1_affine(coords: &[String]) -> G1Affine {
    if coords.len() != 3 {
        panic!("G1Affine coordinates must have exactly 3 elements");
    }

    // let x = parse_field_element(&coords[0]);
    // let y = parse_field_element(&coords[1]);

    // Verify that the third coordinate is "1" (affine representation)
    if coords[2] != "1" {
        panic!("Expected third coordinate to be '1' for affine representation");
    }

    // Convert to field elements
    let x_field = Fq::from_str(&coords[0]).unwrap();
    let y_field = Fq::from_str(&coords[1]).unwrap();

    // Create the G1Affine point
    G1Affine::new_unchecked(x_field, y_field)
}

#[derive(serde::Deserialize)]
struct VKey {
    vk_alpha_1: [String; 3],
    vk_beta_2: Vec<Vec<String>>,  // 3 projective coords
    vk_gamma_2: Vec<Vec<String>>, // 3 projective coords
    vk_delta_2: Vec<Vec<String>>, // 3 projective coords
    IC: Vec<[String; 3]>,
}

fn decimal_str_to_bytes_48(s: &str) -> [u8; 48] {
    let num = BigUint::from_str_radix(s, 10).expect("invalid decimal");
    let mut bytes = num.to_bytes_be();
    if bytes.len() > 48 {
        panic!("value too large for 48 bytes");
    }

    let mut buf = [0u8; 48];
    buf[48 - bytes.len()..].copy_from_slice(&bytes);
    buf
}
fn deserialize_g1(point: &[String; 3]) -> G1Affine {
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

fn parse_fq2_from_json(coords: &[Vec<String>]) -> Result<Fq2, String> {
    if coords.len() < 2 || coords[0].len() < 2 || coords[1].len() < 2 {
        return Err("Invalid Fq2 format in JSON".to_string());
    }

    // В JSON формате порядок c1, c0 (обратный от математической записи c0 + c1*u)
    let c1 = Fq::from_str(&coords[0][0]).map_err(|_| "Invalid c1 coordinate".to_string())?;
    let c0 = Fq::from_str(&coords[0][1]).map_err(|_| "Invalid c0 coordinate".to_string())?;

    // Создаем элемент Fq2
    Ok(Fq2::new(c0, c1))
}

fn parse_g2_affine_from_json(coords: &[Vec<String>]) -> Result<G2Affine, String> {
    if coords.len() != 3 {
        return Err("G2Affine coordinates must have exactly 3 pairs".to_string());
    }

    // Проверка, что третья координата [1, 0] (аффинное представление)
    if coords[2][0] != "1" || coords[2][1] != "0" {
        return Err("Expected third coordinate to be [1, 0] for affine representation".to_string());
    }

    // Парсинг x координаты в формате [c0, c1]
    let x_c0 = Fq::from_str(&coords[0][0]).map_err(|_| "Invalid x_c1 coordinate".to_string())?;
    let x_c1 = Fq::from_str(&coords[0][1]).map_err(|_| "Invalid x_c0 coordinate".to_string())?;

    // Парсинг y координаты в формате [c0, c1]
    let y_c0 = Fq::from_str(&coords[1][0]).map_err(|_| "Invalid y_c1 coordinate".to_string())?;
    let y_c1 = Fq::from_str(&coords[1][1]).map_err(|_| "Invalid y_c0 coordinate".to_string())?;

    // Создаем Fq2 элементы для x и y координат
    let x = Fq2::new(x_c0, x_c1); // Обратите внимание на порядок: c0 + c1*u
    let y = Fq2::new(y_c0, y_c1); // Обратите внимание на порядок: c0 + c1*u

    // Создаем точку G2Affine
    Ok(G2Affine::new(x, y))
}
fn deserialize_g2(point: &[[String; 2]]) -> G2Affine {
    if point.len() != 3 {
        panic!("Expected 3 coordinates for projective G2 point (x, y, z)");
    }

    let mut uncompressed = Vec::with_capacity(192);
    for coord in point.iter().take(2) {
        // take only x and y
        for half in coord {
            let b = decimal_str_to_bytes_48(half);
            uncompressed.extend_from_slice(&b);
        }
    }

    G2Affine::deserialize_uncompressed_unchecked(&*uncompressed).expect("invalid G2Affine point")
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

#[derive(Deserialize)]
struct JsProof {
    proof: ProofJson,
    publicSignals: Vec<String>,
}

#[derive(Deserialize)]
struct ProofJson {
    pi_a: [String; 3],
    pi_b: Vec<Vec<String>>,
    pi_c: [String; 3],
}

#[derive(Debug)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

fn load_proof_and_inputs(path: &str) -> (Proof, Vec<Fr>) {
    let data = fs::read_to_string(path).expect("failed to read proof.json");
    let js: JsProof = serde_json::from_str(&data).expect("invalid JSON");

    let proof = Proof {
        a: deserialize_g1(&js.proof.pi_a),
        b: parse_g2_affine_from_json(&js.proof.pi_b).unwrap(),
        c: deserialize_g1(&js.proof.pi_c),
    };

    let inputs = parse_public_signals(&js.publicSignals);

    (proof, inputs)
}

fn prepare_inputs(gamma_abc_g1: &[G1Affine], public_inputs: &[Fr]) -> Vec<u8> {
    if public_inputs.len() + 1 != gamma_abc_g1.len() {
        panic!(
            "Invalid number of public inputs: got {}, expected {}",
            public_inputs.len(),
            gamma_abc_g1.len() - 1
        );
    }

    let mut g_ic = gamma_abc_g1[0].into_group();

    for (input, base_point) in public_inputs.iter().zip(gamma_abc_g1.iter().skip(1)) {
        let mul = base_point.mul_bigint(input.into_bigint());
        g_ic.add_assign(&mul);
    }

    let mut prepared_bytes = Vec::new();
    g_ic.serialize_uncompressed(&mut prepared_bytes)
        .expect("Failed to serialize prepared input");

    prepared_bytes
}

fn format_bytes_array_const(name: &str, bytes: &[u8]) -> String {
    let mut out = format!("pub const {}: [u8; {}] = [\n    ", name, bytes.len());
    for (i, b) in bytes.iter().enumerate() {
        out.push_str(&format!("{}, ", b));
        if (i + 1) % 16 == 0 {
            out.push_str("\n    ");
        }
    }
    out.push_str("\n];\n\n");
    out
}

fn format_ic_array_const(name: &str, bytes_vec: &[Vec<u8>]) -> String {
    let mut out = format!("pub const {}: [[u8; 96]; {}] = [\n", name, bytes_vec.len());
    for bytes in bytes_vec {
        out.push_str("    [\n        ");
        for (i, b) in bytes.iter().enumerate() {
            out.push_str(&format!("{}, ", b));
            if (i + 1) % 16 == 0 {
                out.push_str("\n        ");
            }
        }
        out.push_str("],\n");
    }
    out.push_str("];\n\n");
    out
}

#[tokio::test]
async fn test_basic_function() -> Result<()> {
    let json = fs::read_to_string("/Users/luisa/zk-shuffle-runner/verification_key.json").unwrap();
    let vkey: VKey = serde_json::from_str(&json).unwrap();

    let alpha = deserialize_g1(&vkey.vk_alpha_1);
    let mut buf = Vec::new();
    alpha.serialize_compressed(&mut buf).unwrap();

    println!("{:?}", buf);

    let beta = parse_g2_affine_from_json(&(vkey.vk_beta_2.to_vec())).unwrap();
    let gamma = parse_g2_affine_from_json(&vkey.vk_gamma_2).unwrap();
    let delta = parse_g2_affine_from_json(&vkey.vk_delta_2).unwrap();

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

    let mut ic_compressed: Vec<Vec<u8>> = vec![];

    for ic in ic_points.clone() {
        let mut buf = Vec::new();
        ic.serialize_uncompressed(&mut buf).unwrap();
        assert_eq!(buf.len(), 96);
        ic_compressed.push(buf);
    }
    let (proof, public_inputs) = load_proof_and_inputs("/Users/luisa/zk-shuffle-runner/proof.json");

    let prepared_inputs_bytes = prepare_inputs(&ic_points, &public_inputs);
    let prepared_inputs = G1Affine::deserialize_uncompressed_unchecked(&*prepared_inputs_bytes)
        .expect("Deserialize error");

    let a_prep = <ark_ec::bls12::G1Prepared<ark_bls12_381::Config>>::from(proof.a);
    let b_prep = <ark_ec::bls12::G2Prepared<ark_bls12_381::Config>>::from(proof.b);
    let c_prep = <ark_ec::bls12::G1Prepared<ark_bls12_381::Config>>::from(proof.c);
    let prepared_inputs_prep =
        <ark_ec::bls12::G1Prepared<ark_bls12_381::Config>>::from(prepared_inputs);
    let gamma_neg_prep = <ark_ec::bls12::G2Prepared<ark_bls12_381::Config>>::from(gamma_g2_neg_pc);
    let delta_neg_prep = <ark_ec::bls12::G2Prepared<ark_bls12_381::Config>>::from(delta_g2_neg_pc);

    let mut output = String::new();
    output.push_str(&format_bytes_array_const(
        "VK_ALPHA_G1_BETA_G2",
        &alpha_beta_bytes,
    ));
    output.push_str(&format_bytes_array_const(
        "VK_GAMMA_G2_NEG_PC",
        &gamma_neg_bytes,
    ));
    output.push_str(&format_bytes_array_const(
        "VK_DELTA_G2_NEG_PC",
        &delta_neg_bytes,
    ));
    output.push_str(&format_ic_array_const("VK_IC", &ic_compressed));

    fs::write("verifier_constants.rs", output).unwrap();

    let qap = <Bls12_381 as Pairing>::multi_miller_loop(
        [a_prep, prepared_inputs_prep, c_prep],
        [b_prep, gamma_neg_prep, delta_neg_prep],
    );
    let test = <Bls12_381 as Pairing>::final_exponentiation(qap).unwrap();
    println!(
        "test.0 == pvk.alpha_g1_beta_g2 {:?}",
        test.0 == alpha_g1_beta_g2
    );

    let proof_bytes = encode_proof(&proof);
    let public_input = encode_inputs(&public_inputs);
    let verification = VerificationVariables {
        proof_bytes,
        public_input,
    };
    let api = GearApi::dev().await?;
    let john_api = get_new_client(&api, USERS_STR[0]).await;

    let mut listener = api.subscribe().await?;
    assert!(listener.blocks_running().await?);

    // Init
    let (message_id, program_id) = init(&api).await;
    assert!(listener.message_processed(message_id).await?.succeed());

    let message_id = send_request!(api: &api, program_id: program_id, service_name: "Poker", action: "VerifyShuffle", payload: (verification));
    assert!(listener.message_processed(message_id).await?.succeed());

    Ok(())
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
