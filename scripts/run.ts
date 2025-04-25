import { shuffleEncryptV2Plaintext, generateShuffleEncryptV2Proof, initDeck, compressDeck, samplePermutation, sampleFieldElements, recoverDeck, keyGen, decompressDeck, elgamalEncrypt, elgamalDecrypt, generateDecryptProof } from 'zk-shuffle-proof';
import { resolve } from 'path';
import { readFileSync } from 'fs';
// @ts-ignore
import * as ff from "ffjavascript";
type EC = [ff.FElement, ff.FElement];
const buildBabyjub = require('circomlibjs').buildBabyjub;
const snarkjs = require('snarkjs');

type CipherCard = { c0: [bigint, bigint], c1: [bigint, bigint] };

type CompressedDeck = {
  X0: bigint[];
  X1: bigint[];
  selector: bigint[];
  delta0: bigint[];
  delta1: bigint[];
};

// generate initial cards
function generatePlainDeck(babyjub: any): CompressedDeck {
  const numCards = BigInt(52);
  const initializedDeck: bigint[] = initDeck(babyjub, Number(numCards));
  let compressedDeck = compressDeck(initializedDeck);
  return compressedDeck;
}

async function main() {
  const encryptWasmFile = resolve(__dirname, '../circuits/build/shuffle_encrypt/shuffle_encrypt_js/shuffle_encrypt.wasm');
  const encryptZkeyFile = resolve(__dirname, '../circuits/build/shuffle_encrypt/shuffle_encrypt.zkey');
  const encryptVkey = await snarkjs.zKey.exportVerificationKey(new Uint8Array(Buffer.from(readFileSync(encryptZkeyFile))));

  const decryptWasmFile = resolve(__dirname, '../circuits/build/decrypt_js/decrypt.wasm');
  const decryptZkeyFile = resolve(__dirname, '../circuits/build/decrypt/decrypt.zkey');
  const decryptVkey = await snarkjs.zKey.exportVerificationKey(new Uint8Array(Buffer.from(readFileSync(decryptZkeyFile))));

  // CLIENT-SERVER INTERACTION FLOW FOR ZK SHUFFLE PROTOCOL
  const numCards = BigInt(52);
  const r = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
  const babyjub = await buildBabyjub();
  const zeroPoint = [babyjub.F.e(0), babyjub.F.e(1)];
  const numPlayers = 3;
  const numBits = BigInt(251);
  const players = Array.from({ length: numPlayers }, () => keyGen(babyjub, numBits));

  // Mapping cards to elliptic curve points (used for later matching)
  const initialPoints: [bigint, bigint][] = [];
  const initializedDeck: bigint[] = initDeck(babyjub, Number(numCards));
  for (let i = 0; i < Number(numCards); i++) {
    const x1 = babyjub.F.e(initializedDeck[i + 2 * Number(numCards)]);
    const y1 = babyjub.F.e(initializedDeck[i + 3 * Number(numCards)]);
    initialPoints.push([x1, y1]);
  }

  const SUITS = ['hearts', 'diamonds', 'clubs', 'spades'];
  const RANKS = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K', 'A'];
  const CARD_MAP = SUITS.flatMap((suit, s) =>
      RANKS.map((rank, r) => {
        const i = s * RANKS.length + r;
        return { suit, rank, point: initialPoints[i] };
      })
    );

  console.log("CARD_MAP", CARD_MAP)
  // STEP 1: BACKEND SIDE
  // After registration — backend already has public keys of players collected from contract events
  // Calculates aggregate public key = pk1 + pk2 + pk3
  const aggKey = players.reduce(
    (acc, player) => babyjub.addPoint(acc, player.pk),
    zeroPoint
  );

  // STEP 2: BACKEND SIDE — generate initial unencrypted deck
  // Backend sends compressedDeck and aggKey to the first player
  let compressedDeck = generatePlainDeck(babyjub);
  
  // STEP 3: CLIENT SIDE — each player shuffles & encrypts the deck
  // Shuffle phase: each player encrypts and permutes the deck
  for (let i = 0; i < numPlayers; i++) {
    console.log(`\nPlayer ${i + 1} shuffling...`);

    // Client generates shuffle permutation and randomness
    const A = samplePermutation(Number(numCards));
    const R = sampleFieldElements(babyjub, numCards);
    const pkString = [babyjub.F.toString(aggKey[0]), babyjub.F.toString(aggKey[1])];
    
    // Client performs plaintext shuffle & encryption
    const plaintext_output = shuffleEncryptV2Plaintext(
      babyjub, Number(numCards), A, R, aggKey,
      compressedDeck.X0, compressedDeck.X1,
      compressedDeck.delta0, compressedDeck.delta1,
      compressedDeck.selector,
    );
      
    console.time("fullProve");
    // Client generates SNARK proof of correct shuffle
    let shuffleEncryptOutput = await generateShuffleEncryptV2Proof(
      pkString, A, R,
      compressedDeck.X0, compressedDeck.X1,
      compressedDeck.delta0, compressedDeck.delta1,
      compressedDeck.selector,
      plaintext_output.X0, plaintext_output.X1,
      plaintext_output.delta0, plaintext_output.delta1,
      plaintext_output.selector,
      encryptWasmFile, encryptZkeyFile,
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
    //   encryptedDeck: {
    //     X0: string[],
    //     X1: string[],
    //     selector: string[],
    //     delta0: string[],
    //     delta1: string[]
    //   }
    // }
    // This payload is used by the backend to:
    // - verify SNARK proof
    // - update game state with newly encrypted deck
    // - broadcast deck to next player
   
    // Backend verifies the proof
    const isValid = await snarkjs.groth16.verify(encryptVkey, shuffleEncryptOutput.publicSignals, shuffleEncryptOutput.proof);

    if (!isValid) {
      throw new Error(`Invalid shuffle proof from Player ${i + 1}`);
    }

    // Backend updates deck to latest encrypted state
    // and sends to the next player
    compressedDeck = {
      X0: plaintext_output.X0,
      X1: plaintext_output.X1,
      delta0: plaintext_output.delta0,
      delta1: plaintext_output.delta1,
      selector: plaintext_output.selector,
    };
  }

  // STEP 4: CONTRACT SIDE — decompress deck and distribute cards
  const decompressedDeck = decompressDeck(compressedDeck.X0, compressedDeck.X1, compressedDeck.delta0, compressedDeck.delta1, compressedDeck.selector);
  const fullDeck = []
  for (let i = 0; i < Number(numCards); i++) {
    const x0 = decompressedDeck[i];
    const y0 = decompressedDeck[i + Number(numCards)];
    const x1 = decompressedDeck[i + 2 * Number(numCards)];
    const y1 = decompressedDeck[i + 3 * Number(numCards)];
    fullDeck.push([x0, y0, x1, y1]);
  }

  // Distribute 2 cards to each player
  const playerHands: CipherCard[][] = [];
  for (let i = 0; i < numPlayers; i++) {
    const [[c0x0, c0y0, c1x0, c1y0], [c0x1, c0y1, c1x1, c1y1]] = [
      fullDeck[i * 2],
      fullDeck[i * 2 + 1]
    ];
    
    playerHands.push([
      { c0: [c0x0, c0y0], c1: [c1x0, c1y0] },
      { c0: [c0x1, c0y1], c1: [c1x1, c1y1] }
    ]);
    console.log(`Player ${i + 1} receives cards [${i * 2}, ${i * 2 + 1}]`);   
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
  let partialSumDecs1 = [zeroPoint, zeroPoint]
  let partialSumDecs2 = [zeroPoint, zeroPoint]
  let partialSumDecs3 = [zeroPoint, zeroPoint]

  // player 1 decrypts for second player and third players
  for (let i = 0; i < 2; i ++) {
    // CLIENT SIDE
    // second player
    let c0 = cards2player[i].c0;
    let c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])]
    // calculates partial dec
    let dec = babyjub.mulPointEscalar(c0Point, r - players[0].sk)
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs2[i] = babyjub.addPoint(partialSumDecs2[i], dec);

    // CLIENT SIDE
    // third player
    c0 = cards3player[i].c0;
    c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])]
    // calculates partial dec
    dec = babyjub.mulPointEscalar(c0Point, r - players[0].sk)
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs3[i] = babyjub.addPoint(partialSumDecs3[i], dec);
  }

  // player 2 decrypts for first player and third players
  for (let i = 0; i < 2; i ++) {
    // CLIENT SIDE
    // first player
    let c0 = cards1player[i].c0;
    let c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])]
    // calculates partial dec
    let dec = babyjub.mulPointEscalar(c0Point, r - players[1].sk)
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs1[i] = babyjub.addPoint(partialSumDecs1[i], dec);

    // CLIENT SIDE
    // third player
    c0 = cards3player[i].c0;
    c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])]
    // calculates partial dec
    dec = babyjub.mulPointEscalar(c0Point, r - players[1].sk)
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs3[i] = babyjub.addPoint(partialSumDecs3[i], dec);
  }

  // player 3 decrypts for first player and second players
  for (let i = 0; i < 2; i ++) {
    // CLIENT SIDE
    // first player
    let c0 = cards1player[i].c0;
    let c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])]
    // calculates partial dec
    let dec = babyjub.mulPointEscalar(c0Point, r - players[2].sk)
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs1[i] = babyjub.addPoint(partialSumDecs1[i], dec);

    // CLIENT SIDE
    // third player
    c0 = cards2player[i].c0;
    c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])]
    // calculates partial dec
    dec = babyjub.mulPointEscalar(c0Point, r - players[2].sk)
    // TODO: make decrypt circom
    // client generate proof and sends proof, public signal to backend
    // BACKEND SIDE
    partialSumDecs2[i] = babyjub.addPoint(partialSumDecs2[i], dec);
  }

  // BACKEND SIDE
  // for all players backend received all partial decs
  // backend calculates
  const partiallyDecCards1 = cards1player.map((card, i) => {
    const c1Point = [babyjub.F.e(card.c1[0]), babyjub.F.e(card.c1[1])];
    return babyjub.addPoint(c1Point, partialSumDecs1[i]);
  });

  const partiallyDecCards2 = cards2player.map((card, i) => {
    const c1Point = [babyjub.F.e(card.c1[0]), babyjub.F.e(card.c1[1])];
    return babyjub.addPoint(c1Point, partialSumDecs2[i]);
  });

  const partiallyDecCards3 = cards3player.map((card, i) => {
    const c1Point = [babyjub.F.e(card.c1[0]), babyjub.F.e(card.c1[1])];
    return babyjub.addPoint(c1Point, partialSumDecs3[i]);
  });

  // CLIENT SIDE
  // player1 decrypts his cards
  const decCards1 = cards1player.map((card, i) => {
    let {c0, c1} = card;
    const c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])];
    const c1Partial = partiallyDecCards1[i];
    const dec = babyjub.mulPointEscalar(c0Point, r - players[0].sk);
    return babyjub.addPoint(c1Partial, dec);
  });

  decCards1.forEach((pt, i) => {
    const match = CARD_MAP.find(entry =>
      babyjub.F.toString(entry.point[0]) === babyjub.F.toString(pt[0]) &&
      babyjub.F.toString(entry.point[1]) === babyjub.F.toString(pt[1])
    );
    if (match) {
      console.log(`Player 1 card ${i + 1}: 🃏 ${match.rank} of ${match.suit}`);
    } else {
      console.log(`Player 1 card ${i + 1}: ❓ Unknown card`);
    }
  });

  // player2 decrypts his cards
  const decCards2 = cards2player.map((card, i) => {
    let {c0, c1} = card;
    const c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])];
    const c1Partial = partiallyDecCards2[i];
    const dec = babyjub.mulPointEscalar(c0Point, r - players[1].sk);
    return babyjub.addPoint(c1Partial, dec);
  });

  decCards2.forEach((pt, i) => {
    const match = CARD_MAP.find(entry =>
      babyjub.F.toString(entry.point[0]) === babyjub.F.toString(pt[0]) &&
      babyjub.F.toString(entry.point[1]) === babyjub.F.toString(pt[1])
    );
    if (match) {
      console.log(`Player 2 card ${i + 1}: 🃏 ${match.rank} of ${match.suit}`);
    } else {
      console.log(`Player 2 card ${i + 1}: ❓ Unknown card`);
    }
  });

  // player2 decrypts his cards
  const decCards3 = cards3player.map((card, i) => {
    let {c0, c1} = card;
    const c0Point = [babyjub.F.e(c0[0]), babyjub.F.e(c0[1])];
    const c1Partial = partiallyDecCards3[i];
    const dec = babyjub.mulPointEscalar(c0Point, r - players[2].sk);
    return babyjub.addPoint(c1Partial, dec);
  });

  decCards3.forEach((pt, i) => {
    const match = CARD_MAP.find(entry =>
      babyjub.F.toString(entry.point[0]) === babyjub.F.toString(pt[0]) &&
      babyjub.F.toString(entry.point[1]) === babyjub.F.toString(pt[1])
    );
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