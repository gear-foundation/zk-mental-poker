pragma circom 2.1.6;

include "../common/elgamal.circom";

template MainTestEncrypt() {
    var numBits = 251;
    var base[2] = [
        5299619240641551281634865583518297030282874472190772894086521144482721001553,
        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];

    signal input ic0[2];
    signal input ic1[2];
    signal input r;
    signal input pk[2];
    signal output c0[2];
    signal output c1[2];

    component encrypt = ElGamalEncrypt(numBits, base);

    encrypt.ic0[0] <== ic0[0];
    encrypt.ic0[1] <== ic0[1];
    encrypt.ic1[0] <== ic1[0];
    encrypt.ic1[1] <== ic1[1];
    encrypt.r <== r;
    encrypt.pk[0] <== pk[0];
    encrypt.pk[1] <== pk[1];

    c0[0] <== encrypt.c0[0];
    c0[1] <== encrypt.c0[1];
    c1[0] <== encrypt.c1[0];
    c1[1] <== encrypt.c1[1];
}

component main = MainTestEncrypt();
