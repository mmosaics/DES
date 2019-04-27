//
// Created by OneCarrot on 2019-04-26.
//

#ifndef DES_BLOCKENCRYTION_H
#define DES_BLOCKENCRYTION_H

#include "DES.h"

#define BLANK " "

enum ModeOfOperation{ECB, CBC, CFB, OFB};
enum Algorithm{DES};

class BlockEncryption {

private:

    ModeOfOperation currentMod;
    Algorithm currentAlgorithm;

    string ciphertext;
    string plaintext;
    string K;
    BigInteger IV;

    BigInteger shiftRegOperaForOFB(BigInteger shiftReg, BigInteger target, int operaMode);
    BigInteger shiftRegOperaForCFB(BigInteger shiftReg, BigInteger target, int operaMode);

    //----工作模式----
    string modeECB(Direction direction);
    string modeCBC(Direction direction);
    string modeCFB(Direction direction, int operaMode);
    string modeOFB(Direction direction, int operaMode);


public:

    BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string cipher, string K);
    BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string cipher, string K, string IV);

    //----外部调用----
    string Encrypt();
    string Decrypt();

    //----getter/setter----
    void setPlaintext(string plain);
    void setCipher(string cipher);
    void setMod(ModeOfOperation mod);
    void setAlgorithm(Algorithm algorithm);
    void setKey(string key);
    void setIV(string iv);


};


#endif //DES_BLOCKENCRYTION_H
