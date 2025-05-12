/*
 * Note:
 * sk = sk_A + sk_B + sk_C
 * pk = sk*g

 * Init:
 * (0, m)
 * Alice Encrypt:
 * (a*g, m + a*pk)
 * Bob Encrypt:
 * ((a+b)*g, m + (a+b)*pk)
 * Charlie Encrypt:
 * ((a+b+c)*g, m + (a+b+c)*pk)
 * Bob Decrypt:
 * m+(a+b+c)*pk - sk_B*(a+b+c)*g
 * ...
*/

pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/escalarmulfix.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";
include "bandersnatch_scalar_mul.circom";
include "bandersnatch_add.circom";

// ElGamalEncrypt:
// c0 = r * g + ic0
// c1 = r * pk + ic1
template ElGamalEncrypt(numBits, baseX, baseY) {
    signal input ic0[3];  // Projective point (X, Y, Z)
    signal input ic1[3];  // Projective point (X, Y, Z)
    signal input r;       // Random scalar
    signal input pk[3];   // Public key (X, Y, Z)
    signal output c0[3];  // Encrypted output 1
    signal output c1[3];  // Encrypted output 2


    // c0 = r * g + ic0
    component bitDecomposition = Num2Bits(numBits);
    bitDecomposition.in <== r;
    component computeC0 = BandersnatchScalarMulProjective(numBits);
    computeC0.X <== baseX;
    computeC0.Y <== baseY;
    computeC0.Z <== 1;
    computeC0.scalar <== r;
   
    component adder0 = BandersnatchAddProjective();
    adder0.X1 <== computeC0.Xout;
    adder0.Y1 <== computeC0.Yout;
    adder0.Z1 <== computeC0.Zout;
    adder0.X2 <== ic0[0];
    adder0.Y2 <== ic0[1];
    adder0.Z2 <== ic0[2];
    c0[0] <== adder0.X3;
    c0[1] <== adder0.Y3;
    c0[2] <== adder0.Z3;

    // c1 = r * pk + ic1
    component computeC1 = BandersnatchScalarMulProjective(numBits);
    computeC1.X <== pk[0];
    computeC1.Y <== pk[1];
    computeC1.Z <== pk[2];
    computeC1.scalar <== r;
    
    component adder1 = BandersnatchAddProjective();
    adder1.X1 <== computeC1.Xout;
    adder1.Y1 <== computeC1.Yout;
    adder1.Z1 <== computeC1.Zout;
    adder1.X2 <== ic1[0];
    adder1.Y2 <== ic1[1];
    adder1.Z2 <== ic1[2];
    c1[0] <== adder1.X3;
    c1[1] <== adder1.Y3;
    c1[2] <== adder1.Z3;
}

// ElGamalDecrypt:
//  - sk * c0

template ElGamalDecrypt(numBits) {
    signal input c0[3];  // c0 of ElGamalEncrypt
    signal input sk;     // secret key, {0, 1}^numBits
    signal output m[3];  // decrypt result

    component scalarMul = BandersnatchScalarMulProjective(numBits);
    scalarMul.X <== c0[0];
    scalarMul.Y <== c0[1];
    scalarMul.Z <== c0[2];
    scalarMul.scalar <== sk;

    m[0] <== 0 - scalarMul.Xout;
    m[1] <== scalarMul.Yout;
    m[2] <== scalarMul.Zout;
}