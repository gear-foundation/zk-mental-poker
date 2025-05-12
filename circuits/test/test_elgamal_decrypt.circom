pragma circom 2.1.6;

include "../common/elgamal.circom";

template MainTestDecrypt() {
    var numBits = 128;

    signal input c0[3];
    signal input sk;
    signal output m[3];

    component decrypt = ElGamalDecrypt(numBits);

    decrypt.c0[0] <== c0[0];
    decrypt.c0[1] <== c0[1];
    decrypt.c0[2] <== c0[2];
    decrypt.sk <== sk;
   
    m[0] <== decrypt.m[0];
    m[1] <== decrypt.m[1];
    m[2] <== decrypt.m[2];
}

component main = MainTestDecrypt();
