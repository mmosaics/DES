//
// Created by OneCarrot on 2019-04-26.
//

#ifndef DES_BLOCKENCRYTION_H
#define DES_BLOCKENCRYTION_H

#include "DES.h"

enum ModeOfOperation{ECB, CBC, CFB, OFB};
enum Algorithm{DES};

class BlockEncryption {

private:

    ModeOfOperation currentMod;
    Algorithm currentAlgorithm;

    string plaintext;
    string K;
    BigInteger IV;

public:

    BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string K);
    BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string K, string IV);

    //----工作模式----
    string modeECB();
    string modeCBC();
    string modeCFB();
    string modeCTR();



};


#endif //DES_BLOCKENCRYTION_H
