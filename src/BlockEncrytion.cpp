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