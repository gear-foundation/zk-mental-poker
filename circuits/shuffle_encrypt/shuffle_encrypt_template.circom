pragma circom 2.1.6;

include "../common/elgamal.circom";
include "../common/matrix.circom";
include "../common/permutation.circom";
include "../common/babyjubjub.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/// X layout:
/// [ic_{0,0}.x, ic_{1,0}.x, ..., ic_{n-1,0}.x,
///  ic_{0,0}.y, ic_{1,0}.y, ..., ic_{n-1,0}.y,
///  ic_{0,0}.z, ic_{1,0}.z, ..., ic_{n-1,0}.z,
///  ic_{0,1}.x, ic_{1,1}.x, ..., ic_{n-1,1}.x,
///  ic_{0,1}.y, ic_{1,1}.y, ..., ic_{n-1,1}.y,
///  ic_{0,1}.z, ic_{1,1}.z, ..., ic_{n-1,1}.z,
/// ]
// Main encryption circuit over Bandersnatch
// Inputs: 52 cards, each card is (ic0 + ic1) = 2 points = 6 scalars
template ShuffleEncryptTemplate(baseX, baseY, numCards, numBits) {
    signal input original[6][numCards]; // original matrix: [c0.X, c0.Y, c0.Z, c1.X, c1.Y, c1.Z]
    signal input permuted[6][numCards]; // shuffled+encrypted matrix
    signal input R[numCards];           // random scalars r_i
    signal input pk[3];                 // aggregate public key
    signal input permutation[numCards];
    signal output isValid;              // 1 if valid

    signal output debugEncrypted[6][numCards];
    signal encrypted[6][numCards];

    component encrypt[numCards];
    
    for (var i = 0; i < numCards; i++) {
        encrypt[i] = ElGamalEncrypt(numBits, baseX, baseY);

        encrypt[i].ic0[0] <== original[0][i];
        encrypt[i].ic0[1] <== original[1][i];
        encrypt[i].ic0[2] <== original[2][i];

        encrypt[i].ic1[0] <== original[3][i];
        encrypt[i].ic1[1] <== original[4][i];
        encrypt[i].ic1[2] <== original[5][i];

        encrypt[i].pk[0] <== pk[0];
        encrypt[i].pk[1] <== pk[1];
        encrypt[i].pk[2] <== pk[2];

        encrypt[i].r <== R[i];

        encrypted[0][i] <== encrypt[i].c0[0];
        encrypted[1][i] <== encrypt[i].c0[1];
        encrypted[2][i] <== encrypt[i].c0[2];

        encrypted[3][i] <== encrypt[i].c1[0];
        encrypted[4][i] <== encrypt[i].c1[1];
        encrypted[5][i] <== encrypt[i].c1[2];

        debugEncrypted[0][i] <== encrypted[0][i];
        debugEncrypted[1][i] <== encrypted[1][i];
        debugEncrypted[2][i] <== encrypted[2][i];
        debugEncrypted[3][i] <== encrypted[3][i];
        debugEncrypted[4][i] <== encrypted[4][i];
        debugEncrypted[5][i] <== encrypted[5][i];
    }

    component perm = ApplyPermutation(6, numCards);
    for (var j = 0; j < numCards; j++) {
        perm.permutation[j] <== permutation[j];
    }
    for (var i = 0; i < 6; i++) {
        for (var j = 0; j < numCards; j++) {
            perm.original[i][j] <== encrypted[i][j];
        }
    }

    component pointChecks[numCards][2]; // 2 точки: c0 и c1
    signal pointValid[numCards];

    for (var i = 0; i < numCards; i++) {
        // Проверка c0 (X, Y, Z): [0..2]
        pointChecks[i][0] = IsEqualProjective();
        pointChecks[i][0].X1 <== perm.permuted[0][i];
        pointChecks[i][0].Y1 <== perm.permuted[1][i];
        pointChecks[i][0].Z1 <== perm.permuted[2][i];
        pointChecks[i][0].X2 <== permuted[0][i];
        pointChecks[i][0].Y2 <== permuted[1][i];
        pointChecks[i][0].Z2 <== permuted[2][i];

        // Проверка c1 (X, Y, Z): [3..5]
        pointChecks[i][1] = IsEqualProjective();
        pointChecks[i][1].X1 <== perm.permuted[3][i];
        pointChecks[i][1].Y1 <== perm.permuted[4][i];
        pointChecks[i][1].Z1 <== perm.permuted[5][i];
        pointChecks[i][1].X2 <== permuted[3][i];
        pointChecks[i][1].Y2 <== permuted[4][i];
        pointChecks[i][1].Z2 <== permuted[5][i];

        pointValid[i] <== pointChecks[i][0].isEqual * pointChecks[i][1].isEqual;
    }

    signal allValid[numCards + 1];

    allValid[0] <== 1;

    for (var i = 0; i < numCards; i++) {
        allValid[i + 1] <== allValid[i] * pointValid[i];
    }

    isValid <== allValid[numCards];
    isValid === 1;
}


template IsEqualProjective() {
    signal input X1;
    signal input Y1;
    signal input Z1;
    signal input X2;
    signal input Y2;
    signal input Z2;

    signal output isEqual;

    // Compute cross-multiplications
    signal X1Z2;
    signal X2Z1;
    signal Y1Z2;
    signal Y2Z1;

    X1Z2 <== X1 * Z2;
    X2Z1 <== X2 * Z1;
    Y1Z2 <== Y1 * Z2;
    Y2Z1 <== Y2 * Z1;

    // Compare results
    component xEq = IsEqual();
    xEq.in[0] <== X1Z2;
    xEq.in[1] <== X2Z1;

    component yEq = IsEqual();
    yEq.in[0] <== Y1Z2;
    yEq.in[1] <== Y2Z1;

    isEqual <== xEq.out * yEq.out;
}
