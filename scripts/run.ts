import {  initDeck, keyGen, scalarMul, projectiveAdd, elgamalEncryptDeck, generatePermutation, permuteMatrix} from 'zk-shuffle-proof';

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
    sk: sk.toString(), 
    expected: [dec.X.toString(), dec.Y.toString(), dec.Z.toString()]
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

function bigintToBytes48(x: string): Uint8Array {
  const hex = BigInt(x).toString(16).padStart(96, "0"); 
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function serializeG1Uncompressed([x, y, _z]: string[]): Uint8Array {
  const xBytes = bigintToBytes48(x);
  const yBytes = bigintToBytes48(y);
  return new Uint8Array([...xBytes, ...yBytes]);
}

function serializeG2Uncompressed([[x0, x1], [y0, y1], _z]: string[][]): Uint8Array {
  const x1Bytes = bigintToBytes48(x1);
  const x0Bytes = bigintToBytes48(x0);
  const y1Bytes = bigintToBytes48(y1);
  const y0Bytes = bigintToBytes48(y0);
  return new Uint8Array([...x1Bytes, ...x0Bytes, ...y1Bytes, ...y0Bytes]);
}

function encodeProof(proof: {
  pi_a: string[],
  pi_b: string[][],
  pi_c: string[],
}): {
  a: Uint8Array;
  b: Uint8Array;
  c: Uint8Array;
} {
  return {
    a: serializeG1Uncompressed(proof.pi_a),
    b: serializeG2Uncompressed(proof.pi_b),
    c: serializeG1Uncompressed(proof.pi_c),
  };
}
async function main() {
  const encryptWasmFile = resolve(__dirname, '../circuits/build/shuffle_encrypt/shuffle_encrypt_js/shuffle_encrypt.wasm');
  const encryptZkeyFile = resolve(__dirname, '../circuits/build/shuffle_encrypt/shuffle_encrypt.zkey');
  const encryptVkey = await snarkjs.zKey.exportVerificationKey(new Uint8Array(Buffer.from(readFileSync(encryptZkeyFile))));

  const decryptWasmFile = resolve(__dirname, '../circuits/build/decrypt/decrypt_js/decrypt.wasm');
  const decryptZkeyFile = resolve(__dirname, '../circuits/build/decrypt/decrypt.zkey');
  const decryptVkey = await snarkjs.zKey.exportVerificationKey(new Uint8Array(Buffer.from(readFileSync(decryptZkeyFile))));

  writeFileSync(
    'output/decrypt_vkey.json',
    JSON.stringify(decryptVkey, null, 2)
  );

  writeFileSync(
    'output/shuffle_vkey.json',
    JSON.stringify(encryptVkey, null, 2)
  );


  // CLIENT-SERVER INTERACTION FLOW FOR ZK SHUFFLE PROTOCOL
  const numCards = 52;

  const numPlayers = 3;
  const numBits = 64;
  const players = Array.from({ length: numPlayers }, () => keyGen(numBits));

  const playerPks = players.map((player, i) => ({
    index: i,
    pk: {
      X: player.pk.X.toString(),
      Y: player.pk.Y.toString(),
      Z: player.pk.Z.toString(),
    },
  }));
  
  writeFileSync('output/player_pks.json', JSON.stringify(playerPks, null, 2));
  
  const playerSks = players.map((player, i) => ({
    index: i,
    sk: player.sk.toString() 
  }));
  writeFileSync('output/player_sks.json', JSON.stringify(playerSks, null, 2));

  // Mapping cards to elliptic curve points (used for later matching)
  let deck: bigint[][] = initDeck(numCards);

  const cardMap = buildCardMap(deck);

  writeFileSync(
    'output/card_map.json',
    JSON.stringify(cardMap, (_, value) =>
      typeof value === 'bigint' ? value.toString() : value,
      2
    )
  );

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

   const shuffleProofsData = allProofs.map((proof, i) => ({
    proof,
    publicSignals: allPublicSignals[i],
  }));
  
  writeFileSync('output/shuffle_proofs.json', JSON.stringify(shuffleProofsData, null, 2));
  const encryptedDeck = deck.map(row => row.map(v => v.toString()));

writeFileSync('output/encrypted_deck.json', JSON.stringify(encryptedDeck, null, 2));
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

  const partialDecryptProofs = [];


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

    partialDecryptProofs.push({
      proof,
      publicSignals
    });
    
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
    partialDecryptProofs.push({
      proof,
      publicSignals
    });
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

    let {
      dec,
      proof,
      publicSignals,
      isValid
    } = await generateDecryptProof(
      c0,
      players[1].sk,
      decryptWasmFile,
      decryptZkeyFile,
      decryptVkey
    );

    partialDecryptProofs.push({
      proof,
      publicSignals
    });

    if (!isValid) {
      throw new Error("Invalid decryption proof");
    }

    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs1[i] = projectiveAdd(F, a, d, partialSumDecs1[i], dec);

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
      players[1].sk,
      decryptWasmFile,
      decryptZkeyFile,
      decryptVkey
    ));
    partialDecryptProofs.push({
      proof,
      publicSignals
    });
    if (!isValid) {
      throw new Error("Invalid decryption proof");
    }
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

    let {
      dec,
      proof,
      publicSignals,
      isValid
    } = await generateDecryptProof(
      c0,
      players[2].sk,
      decryptWasmFile,
      decryptZkeyFile,
      decryptVkey
    );

    partialDecryptProofs.push({
      proof,
      publicSignals
    });
    
    if (!isValid) {
      throw new Error("Invalid decryption proof");
    }
 
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs1[i] = projectiveAdd(F, a, d, partialSumDecs1[i], dec);

    // CLIENT SIDE
    // second player
    c0 = cards2player[i].c0;
    ({
      dec,
      proof,
      publicSignals,
      isValid
    } = await generateDecryptProof(
      c0,
      players[2].sk,
      decryptWasmFile,
      decryptZkeyFile,
      decryptVkey
    ));
    partialDecryptProofs.push({
      proof,
      publicSignals
    });
    if (!isValid) {
      throw new Error("Invalid decryption proof");
    }
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

  const partialDecryptions = [];

  partialDecryptions.push({
    publicKey: {
      X: players[0].pk.X.toString(),
      Y: players[0].pk.Y.toString(),
      Z: players[0].pk.Z.toString(),
    },
    cards: cards1player.map((card, i) => ({
      c0: {
        X: card.c0.X.toString(),
        Y: card.c0.Y.toString(),
        Z: card.c0.Z.toString(),
      },
      c1_partial: {
        X: partiallyDecCards1[i].X.toString(),
        Y: partiallyDecCards1[i].Y.toString(),
        Z: partiallyDecCards1[i].Z.toString(),
      }
    }))
  });
  
  partialDecryptions.push({
    publicKey: {
      X: players[1].pk.X.toString(),
      Y: players[1].pk.Y.toString(),
      Z: players[1].pk.Z.toString(),
    },
    cards: cards2player.map((card, i) => ({
      c0: {
        X: card.c0.X.toString(),
        Y: card.c0.Y.toString(),
        Z: card.c0.Z.toString(),
      },
      c1_partial: {
        X: partiallyDecCards2[i].X.toString(),
        Y: partiallyDecCards2[i].Y.toString(),
        Z: partiallyDecCards2[i].Z.toString(),
      }
    }))
  });
  
  partialDecryptions.push({
    publicKey: {
      X: players[2].pk.X.toString(),
      Y: players[2].pk.Y.toString(),
      Z: players[2].pk.Z.toString(),
    },
    cards: cards3player.map((card, i) => ({
      c0: {
        X: card.c0.X.toString(),
        Y: card.c0.Y.toString(),
        Z: card.c0.Z.toString(),
      },
      c1_partial: {
        X: partiallyDecCards3[i].X.toString(),
        Y: partiallyDecCards3[i].Y.toString(),
        Z: partiallyDecCards3[i].Z.toString(),
      }
    }))
  });
  
  writeFileSync(
    'output/partial_decryptions.json',
    JSON.stringify(partialDecryptions, null, 2)
  );

  writeFileSync(
    'output/partial_decrypt_proofs.json',
    JSON.stringify(partialDecryptProofs, null, 2)
  );
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

  decCards2.forEach((pt, i) => {
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

    const usedCards = numPlayers * 2;

    const tableCards: CipherCard[] = [];

    for (let i = 0; i < 3; i++) {
      const cardIndex = usedCards + i;

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

      tableCards.push({ c0, c1 });
    }

    // Players decrypt 3 cards
    const playerDecryptionsData = [];

    const partialSumDecsTable: ECPoint[] = [];
    for (let i = 0; i < 3; i++) {
      partialSumDecsTable.push(neutral);
    }
    for (let playerIndex = 0; playerIndex < numPlayers; playerIndex++) {
      const sk = players[playerIndex].sk;
      const pk = players[playerIndex].pk;

      const decryptions = [];

      for (let cardIndex = 0; cardIndex < 3; cardIndex++) {
        const card = tableCards[cardIndex];
        const c0 = card.c0;
    
        const {
          dec,
          proof,
          publicSignals,
          isValid
        } = await generateDecryptProof(
          c0,
          sk,
          decryptWasmFile,
          decryptZkeyFile,
          decryptVkey
        );
    
        if (!isValid) {
          throw new Error(`Invalid decryption proof for card ${cardIndex} by player ${playerIndex}`);
        }
    
        partialSumDecsTable[cardIndex] = projectiveAdd(
          F, a, d,
          partialSumDecsTable[cardIndex],
          dec
        );
    
        decryptions.push({
          encryptedCard: {
            c0: {
              X: card.c0.X.toString(),
              Y: card.c0.Y.toString(),
              Z: card.c0.Z.toString()
            },
            c1: {
              X: card.c1.X.toString(),
              Y: card.c1.Y.toString(),
              Z: card.c1.Z.toString()
            }
          },
          proof,
          publicSignals
        });
      }
      playerDecryptionsData.push({
        playerPubKey: {
          X: pk.X.toString(),
          Y: pk.Y.toString(),
          Z: pk.Z.toString()
        },
        decryptions
      });
    }
    writeFileSync("table_decryptions_ater_preflop.json", JSON.stringify(playerDecryptionsData, null, 2));


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