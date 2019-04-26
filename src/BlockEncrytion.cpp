//
// Created by OneCarrot on 2019-04-26.
//

#include "BlockEncrytion.h"

BlockEncryption::BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string K) {

    currentMod = mod;
    currentAlgorithm = algorithm;

    this->plaintext = plaintext;
    this->K = K;

}

BlockEncryption::BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string K, string IV) {
    currentMod = mod;
    currentAlgorithm = algorithm;

    this->plaintext = plaintext;
    this->K = K;
    this->IV = BigInteger(IV);
}

string BlockEncryption::modeECB() {

    stringstream resultss;

    for(int i = 0; i < plaintext.length(); i += 16) {

        string block = plaintext.substr(i, 16);
        class DES des(K, block);
        des.Encrypt();
        resultss << des.getCipher();

    }

    return resultss.str();

}

string BlockEncryption::modeCBC() {

    stringstream resultss;
    int arrsize = plaintext.length()/16;
    BigInteger blocks[arrsize];

    for(int i = 0; i < arrsize; i++) {
        string block = plaintext.substr(i*16, 16);
        blocks[i] = BigInteger(block);
    }

    blocks[0] = blocks[0].toBinary(0).XOR(IV.toBinary(0)).toHex();

    for(int i = 0; i < arrsize; i++) {

        class DES des(BigInteger(K), blocks[i]);
        des.Encrypt();

        resultss << des.getCipher();

        if (i != arrsize - 1) {
            blocks[i + 1] = blocks[i + 1].toBinary(0).XOR(BigInteger(des.getCipher()).toBinary(0)).toHex();

        }

    }

    return resultss.str();
}