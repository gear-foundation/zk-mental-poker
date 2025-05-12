import {  initDeck, generateRandomScalar, keyGen, scalarMul, projectiveAdd, elgamalEncryptDeck, generatePermutation, permuteMatrix} from 'zk-shuffle-proof';

import { resolve } from 'path';
import { readFileSync, writeFileSync } from 'fs';
// @ts-ignore
import { F1Field } from "ffjavascript";
// @ts-ignore
import { groth16 } from "snarkjs";

const snarkjs = require('snarkjs');

const q = BigInt("52435875175126190479447740508185965837690552500527637822603658699938581184513"); // BLS12-381 scalar field
const F = new F1Field(q);
const neutral = { X: 0n, Y: 1n, Z: 1n };
const a = BigInt(-5);
const d = 45022363124591815672509500913686876175488063829319466900776701791074614335719n;
const base = {
    X: BigInt("0x29c132cc2c0b34c5743711777bbe42f32b79c022ad998465e1e71866a252ae18"),
    Y: BigInt("0x2a6c669eda123e0f157d8b50badcd586358cad81eee464605e3167b6cc974166"),
    Z: 1n,
  };


type CipherCard = {
  c0: ECPoint;
  c1: ECPoint;
};
interface ECPoint {
  X: bigint;
  Y: bigint;
  Z: bigint;
}

interface Card {
  suit: string;
  rank: string;
  point: ECPoint;
}

const SUITS = ['hearts', 'diamonds', 'clubs', 'spades'];
const RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];


function buildCardMap(deck: bigint[][]): Card[] {
  const numCards = SUITS.length * RANKS.length;
  if (deck[0].length !== numCards) {
    throw new Error(`Deck size mismatch: expected ${numCards}, got ${deck[0].length}`);
  }

  const cards: Card[] = [];

  for (let s = 0; s < SUITS.length; s++) {
    for (let r = 0; r < RANKS.length; r++) {
      const i = s * RANKS.length + r;
      cards.push({
        suit: SUITS[s],
        rank: RANKS[r],
        point: {
          X: deck[3][i],
          Y: deck[4][i],
          Z: deck[5][i],
        },
      });
    }
  }

  return cards;
}

function toAffine(F: any, P: ECPoint) {
  const x = F.div(P.X, P.Z);
  const y = F.div(P.Y, P.Z);
  return { x, y };
}

function findCardByPoint(F: any, cards: Card[], target: ECPoint): Card | undefined {
  const targetAffine = toAffine(F, target);

  return cards.find(card => {
    const cardAffine = toAffine(F, card.point);
    return F.eq(cardAffine.x, targetAffine.x) && F.eq(cardAffine.y, targetAffine.y);
  });
}

async function generateDecryptProof(
  c0: ECPoint,
  sk: bigint,
  decryptWasmFile: string,
  decryptZkeyFile: string,
  decryptVkey: string
): Promise<{
  dec: ECPoint;
  proof: any;
  publicSignals: any;
  isValid: boolean;
}> {
  const skC0 = scalarMul(F, a, d, c0, sk);
  const dec: ECPoint = {
    X: F.neg(skC0.X),
    Y: skC0.Y,
    Z: skC0.Z
  };

  const input = {
    c0: [c0.X.toString(), c0.Y.toString(), c0.Z.toString()],
    sk: sk.toString()
  };

  console.time("fullProve");
  const { proof, publicSignals } = await groth16.fullProve(
    input,
    decryptWasmFile,
    decryptZkeyFile
  );
  console.timeEnd("fullProve");

  const isValid = await snarkjs.groth16.verify(decryptVkey, publicSignals, proof);
  return { dec, proof, publicSignals, isValid };
}

// function save_test_data(players: any[], proofs: any[], publicSignals: any[]) {
//   const testOutput = players.map((player, i) => ({
//     pk: [player.pk[0].toString(), player.pk[1].toString()],
//     proof: proofs[i],
//     publicSignals: publicSignals[i],
//   }));

//   writeFileSync('test_outputs.json', JSON.stringify(testOutput, null, 2));
// }


async function main() {
  const encryptWasmFile = resolve(__dirname, '../circuits/build/shuffle_encrypt/shuffle_encrypt_js/shuffle_encrypt.wasm');
  const encryptZkeyFile = resolve(__dirname, '../circuits/build/shuffle_encrypt/shuffle_encrypt.zkey');
  const encryptVkey = await snarkjs.zKey.exportVerificationKey(new Uint8Array(Buffer.from(readFileSync(encryptZkeyFile))));

  const decryptWasmFile = resolve(__dirname, '../circuits/build/decrypt/decrypt_js/decrypt.wasm');
  const decryptZkeyFile = resolve(__dirname, '../circuits/build/decrypt/decrypt.zkey');
  const decryptVkey = await snarkjs.zKey.exportVerificationKey(new Uint8Array(Buffer.from(readFileSync(decryptZkeyFile))));

  // CLIENT-SERVER INTERACTION FLOW FOR ZK SHUFFLE PROTOCOL
  const numCards = 52;

  const numPlayers = 3;
  const numBits = 128;
  const players = Array.from({ length: numPlayers }, () => keyGen(numBits));

  // Mapping cards to elliptic curve points (used for later matching)
  const initialPoints: [bigint, bigint][] = [];
  let deck: bigint[][] = initDeck(numCards);

  const cardMap = buildCardMap(deck);

  // STEP 1: BACKEND SIDE
  // After registration — backend already has public keys of players collected from contract events
  // Calculates aggregate public key = pk1 + pk2 + pk3
  const aggKey = players.reduce(
    (acc, player) => projectiveAdd(F, a, d, acc, player.pk),
    { X: 0n, Y: 1n, Z: 1n }
  );

  const allProofs: any[] = [];
  const allPublicSignals: any[] = [];

  // STEP 2: BACKEND SIDE — generate initial  deck 
  // Backend sends compressedDeck and aggKey to the first player
  
  // STEP 3: CLIENT SIDE — each player shuffles & encrypts the deck
  // Shuffle phase: each player encrypts and permutes the deck
  for (let i = 0; i < numPlayers; i++) {
    console.log(`\nPlayer ${i + 1} shuffling...`);

    // Client generates shuffle permutation and randomness
    const permutation = generatePermutation(numCards);

    const { encrypted, rScalars } = elgamalEncryptDeck(F, a, d, base, aggKey, deck);
    const R = rScalars.map(r => r.toString());

    const shuffled = permuteMatrix(encrypted, permutation);
    
    const input = {
      pk: [aggKey.X.toString(), aggKey.Y.toString(), aggKey.Z.toString()],
      R,
      permutation,
      original: deck.map((row) => row.map((v) => v.toString())),
      permuted: shuffled.map((row) => row.map((v) => v.toString())),
    };
    console.time("fullProve");
    // Client generates SNARK proof of correct shuffle
    const { proof, publicSignals } = await groth16.fullProve(
      input,
      encryptWasmFile,
      encryptZkeyFile
    );
    console.timeEnd("fullProve");

    // Client sends result to backend (deck + proof)
    // Payload example:
    // {
    //   gameId: string,
    //   playerPk: [string, string],
    //   proof: {
    //     pi_a: string[],
    //     pi_b: string[][],
    //     pi_c: string[]
    //   },
    //   publicSignals: string[],
    //   encryptedDeck: bigint[][]
    // }
    // This payload is used by the backend to:
    // - verify SNARK proof
    // - update game state with newly encrypted deck
    // - broadcast deck to next player
   
    // Backend verifies the proof
    const isValid = await snarkjs.groth16.verify(encryptVkey, publicSignals,proof);

    if (!isValid) {
      throw new Error(`Invalid shuffle proof from Player ${i + 1}`);
    }
    allProofs.push(proof);
    allPublicSignals.push(publicSignals);

    // Backend updates deck to latest encrypted state
    deck = shuffled;
   }

  // save_test_data(players, allProofs, allPublicSignals);
  // STEP 4: CONTRACT SIDE — decompress deck and distribute cards

  // Distribute 2 cards to each player
  const playerHands: CipherCard[][] = [];
  
  for (let i = 0; i < numPlayers; i++) {
    const hand: CipherCard[] = [];
  
    for (let j = 0; j < 2; j++) { // 2 карты на игрока
      const cardIndex = i * 2 + j;
  
      const c0: ECPoint = {
      X: deck[0][cardIndex],
      Y: deck[1][cardIndex],
      Z: deck[2][cardIndex],
    };

    const c1: ECPoint = {
      X: deck[3][cardIndex],
      Y: deck[4][cardIndex],
      Z: deck[5][cardIndex],
    };
  
      hand.push({ c0, c1 });
    }
  
    playerHands.push(hand);
  }
  

  // Contract emits event with assigned encrypted cards to players

  // STEP 5: BACKEND SIDE — prepare decryption assignments

  // - Player 1 decrypts cards of Player 2 and Player 3
  // - Player 2 decrypts cards of Player 1 and Player 3
  // - Player 3 decrypts cards of Player 1 and Player 2

  // --- DECRYPTION ASSIGNMENTS ---
  // Player 1 receives cards [0, 1] — and must decrypt cards [2,3] and [4,5] (Player 2 and Player 3)
  // Player 2 receives cards [2, 3] — and must decrypt cards [0,1] and [4,5] (Player 1 and Player 3)
  // Player 3 receives cards [4, 5] — and must decrypt cards [0,1] and [2,3] (Player 1 and Player 2)
  // Each player submits partial decryptions of cards they do not own
  // Backend aggregates all partial decryptions before final reveal

  let cards1player = playerHands[0];
  let cards2player = playerHands[1];
  let cards3player = playerHands[2];

  // partial decks
  let partialSumDecs1 = [neutral, neutral]
  let partialSumDecs2 = [neutral, neutral]
  let partialSumDecs3 = [neutral, neutral]

  // player 1 decrypts for second player and third players
  for (let i = 0; i < 2; i ++) {
    // CLIENT SIDE
    // second player
    // client generate proof and sends proof, public signal to backend
    let c0 = cards2player[i].c0;

    let {
      dec,
      proof,
      publicSignals,
      isValid
    } = await generateDecryptProof(
      c0,
      players[0].sk,
      decryptWasmFile,
      decryptZkeyFile,
      decryptVkey
    );
    
    if (!isValid) {
      throw new Error("Invalid decryption proof");
    }

    // BACKEND SIDE
    partialSumDecs2[i] = projectiveAdd(F, a, d, partialSumDecs2[i], dec);

    // CLIENT SIDE
    // third player
    c0 = cards3player[i].c0;

    ({
      dec,
      proof,
      publicSignals,
      isValid
    } = await generateDecryptProof(
      c0,
      players[0].sk,
      decryptWasmFile,
      decryptZkeyFile,
      decryptVkey
    ));
    
    if (!isValid) {
      throw new Error("Invalid decryption proof");
    }
  
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs3[i] =  projectiveAdd(F, a, d, partialSumDecs3[i], dec);
  }

  // // player 2 decrypts for first player and third players
  for (let i = 0; i < 2; i ++) {
    // CLIENT SIDE
    // first player
    let c0 = cards1player[i].c0;

    let skC0 = scalarMul(F, a, d, c0, players[1].sk);
    let dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
 
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs1[i] = projectiveAdd(F, a, d, partialSumDecs1[i], dec);

    // CLIENT SIDE
    // third player
    c0 = cards3player[i].c0;
    skC0 = scalarMul(F, a, d, c0, players[1].sk);
    dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs3[i] =  projectiveAdd(F, a, d, partialSumDecs3[i], dec);
  }

  // player 3 decrypts for first player and second players
  for (let i = 0; i < 2; i ++) {
    // CLIENT SIDE
    // first player
    let c0 = cards1player[i].c0;

    let skC0 = scalarMul(F, a, d, c0, players[2].sk);
    let dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
 
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs1[i] = projectiveAdd(F, a, d, partialSumDecs1[i], dec);

    // CLIENT SIDE
    // second player
    c0 = cards2player[i].c0;
    skC0 = scalarMul(F, a, d, c0, players[2].sk);
    dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs2[i] =  projectiveAdd(F, a, d, partialSumDecs2[i], dec);
  }

  // BACKEND SIDE
  // for all players backend received all partial decs
  // backend calculates
  const partiallyDecCards1 = cards1player.map((card, i) => {
    return projectiveAdd(F, a, d, card.c1, partialSumDecs1[i]);
  });

  const partiallyDecCards2 = cards2player.map((card, i) => {
    return projectiveAdd(F, a, d, card.c1, partialSumDecs2[i]);
  });

  const partiallyDecCards3 = cards3player.map((card, i) => {
    return projectiveAdd(F, a, d, card.c1, partialSumDecs3[i]);
  });

  // CLIENT SIDE
  // player1 decrypts his cards
  const decCards1 = cards1player.map((card, i) => {
    let {c0, c1} = card;

    let skC0 = scalarMul(F, a, d, c0, players[0].sk);
    let dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
    const c1Partial = partiallyDecCards1[i];
    return projectiveAdd(F, a, d, c1Partial, dec);
  });

  decCards1.forEach((pt, i) => {
    const match = findCardByPoint(F, cardMap, pt);
  
    if (match) {
      console.log(`Player 1 card ${i + 1}: 🃏 ${match.rank} of ${match.suit}`);
    } else {
      console.log(`Player 1 card ${i + 1}: ❓ Unknown card`);
    }
  });

  // player2 decrypts his cards
  const decCards2 = cards2player.map((card, i) => {
    let {c0, c1} = card;
    let skC0 = scalarMul(F, a, d, c0, players[1].sk);
    let dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
    const c1Partial = partiallyDecCards2[i];
    return projectiveAdd(F, a, d, c1Partial, dec);
  });

  decCards1.forEach((pt, i) => {
    const match = findCardByPoint(F, cardMap, pt);
  
    if (match) {
      console.log(`Player 2 card ${i + 1}: 🃏 ${match.rank} of ${match.suit}`);
    } else {
      console.log(`Player 2 card ${i + 1}: ❓ Unknown card`);
    }
  });

    // player2 decrypts his cards
    const decCards3 = cards3player.map((card, i) => {
      let {c0, c1} = card;
      let skC0 = scalarMul(F, a, d, c0, players[2].sk);
      let dec = { X: F.neg(skC0.X), Y: skC0.Y, Z: skC0.Z };
      const c1Partial = partiallyDecCards3[i];
      return projectiveAdd(F, a, d, c1Partial, dec);
    });

    decCards3.forEach((pt, i) => {
      const match = findCardByPoint(F, cardMap, pt);
      if (match) {
        console.log(`Player 3 card ${i + 1}: 🃏 ${match.rank} of ${match.suit}`);
      } else {
        console.log(`Player 3 card ${i + 1}: ❓ Unknown card`);
      }
    });

  }


    main()
    .then(() => {
      console.log('Finished successfully.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('Error:', err);
      process.exit(1);
    });