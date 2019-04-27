//
// Created by OneCarrot on 2019-04-26.
//

#include "BlockEncrytion.h"

BlockEncryption::BlockEncryption() {}

BlockEncryption::BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string cipher, string K) {

    currentMod = mod;
    currentAlgorithm = algorithm;

    this->plaintext = plaintext;
    this->K = K;
    this->ciphertext = cipher;

}

BlockEncryption::BlockEncryption(ModeOfOperation mod, Algorithm algorithm, string plaintext, string cipher, string K, string IV) {
    currentMod = mod;
    currentAlgorithm = algorithm;

    this->plaintext = plaintext;
    this->K = K;
    this->ciphertext = cipher;
    this->IV = BigInteger(IV);
}

string BlockEncryption::modeECB(Direction direction) {

    stringstream resultss;

    if(direction == ENCRPT) {

        for (int i = 0; i < plaintext.length(); i += 16) {

            string block = plaintext.substr(i, 16);
            class DES des(K, block, ENCRPT);
            des.Encrypt();
            resultss << des.getCipher();

        }
    } else if(direction == DECRPT) {

        for (int i = 0; i < ciphertext.length(); i += 16) {
            string block = ciphertext.substr(i, 16);
            class DES des(K, block, DECRPT);
            des.Decrypt();
            resultss << des.getPlaintext();
        }

    }

    return resultss.str();

}

string BlockEncryption::modeCBC(Direction direction) {

    stringstream resultss;

    if(direction == ENCRPT) {
        int arrsize = plaintext.length() / 16;
        BigInteger blocks[arrsize];

        for (int i = 0; i < arrsize; i++) {
            string block = plaintext.substr(i * 16, 16);
            blocks[i] = BigInteger(block);
        }

        blocks[0] = blocks[0].toBinary(0).XOR(IV.toBinary(0)).toHex();

        for (int i = 0; i < arrsize; i++) {

            class DES des(BigInteger(K), blocks[i], ENCRPT);
            des.Encrypt();

            resultss << des.getCipher();

            if (i != arrsize - 1) {
                blocks[i + 1] = blocks[i + 1].toBinary(0).XOR(BigInteger(des.getCipher()).toBinary(0)).toHex();
            }
        }
    } else if(direction == DECRPT ) {

        int arrsize = ciphertext.length() / 16;
        BigInteger Cblocks[arrsize];

        for(int i = 0; i < arrsize; i++) {
            string block = ciphertext.substr(i*16, 16);
            Cblocks[i] = BigInteger(block);
        }

        class DES des(K, ciphertext, DECRPT);
        des.Decrypt();
        resultss << BigInteger(des.getPlaintext()).toBinary(0).XOR(IV.toBinary(0)).toHex().toString();

        for(int i = 1; i < arrsize; i++) {
            des.setCipher(Cblocks[i]);
            des.Decrypt();
            resultss << BigInteger(des.getPlaintext()).toBinary(0).XOR(Cblocks[i-1].toBinary(0)).toHex().toString();
        }

    }

    return resultss.str();
}

string BlockEncryption::modeCFB(Direction direction, int operaMod) {

    string result;

    if(direction == ENCRPT) {
        result = operateCFB(plaintext, operaMod);
    } else if(direction == DECRPT) {
        result = operateCFB(ciphertext, operaMod);
    }

    return result;
}



string BlockEncryption::modeOFB(Direction direction, int operaMod) {

    string result;

    if(direction == ENCRPT) {
        result = operateOFB(plaintext, operaMod);
    } else if(direction == DECRPT) {
        result = operateOFB(ciphertext, operaMod);
    }

    return result;
}

string BlockEncryption::Encrypt() {
    string result;

    switch(currentMod) {
        case ECB:
            result = modeECB(ENCRPT);
            break;
        case CBC:
            result = modeCBC(ENCRPT);
            break;
        case CFB:
            result = modeCFB(ENCRPT, 8);
            break;
        case OFB:
            result = modeOFB(ENCRPT, 8);
            break;
    }

    return result;

}

string BlockEncryption::Decrypt() {
    string result;

    switch(currentMod) {
        case ECB:
            result = modeECB(DECRPT);
            break;
        case CBC:
            result = modeCBC(DECRPT);
            break;
        case CFB:
            result = modeCFB(DECRPT, 8);
            break;
        case OFB:
            result = modeOFB(DECRPT, 8);
            break;
    }

    return result;
}



//------设置函数-------

void BlockEncryption::setPlaintext(string plain) {
    this->plaintext = plain;
}

void BlockEncryption::setCipher(string cipher) {
    this->ciphertext = cipher;
}

void BlockEncryption::setMod(ModeOfOperation mod) {
    this->currentMod = mod;
}

void BlockEncryption::setAlgorithm(Algorithm algorithm) {
    this->currentAlgorithm = algorithm;
}

void BlockEncryption::setKey(string key) {
    this->K = key;
}

void BlockEncryption::setIV(string iv) {
    this->IV = BigInteger(iv);
}

//-----辅助函数-------

BigInteger BlockEncryption::shiftRegOperaForOFB(BigInteger shiftReg, BigInteger target, int operaMode) {

    BigInteger bShiftReg = shiftReg.toBinary(0);     //移位寄存器二进制形式
    bShiftReg.logicalShift(operaMode, LEFT);         //左移8位
    bShiftReg = target.toBinary(0).subbits(0,operaMode) + bShiftReg;      //把上一个keyStream送入移位寄存器
    shiftReg = bShiftReg.toHex();                   //保存记录

    return shiftReg;
}

BigInteger BlockEncryption::shiftRegOperaForCFB(BigInteger shiftReg, BigInteger target, int operaMode) {

    BigInteger bShiftReg = shiftReg.toBinary(0);  //移位寄存器的二进制形式
    bShiftReg.logicalShift(operaMode, LEFT);      //移位寄存器左移s位
    bShiftReg = target.toBinary(0) + bShiftReg; //把上一个密文分组送入移位寄存器
    shiftReg = bShiftReg.toHex();                   //保存记录

    return shiftReg;
}

string BlockEncryption::operateCFB(string source, int operaMod) {


    stringstream resultss;

    //----对source进行分组-----
    int arrsize = (source.length() * 4) / operaMod;
    BigInteger Sourceblocks[arrsize];

    for (int i = 0; i < arrsize; i++) {
        string block = source.substr(i * (operaMod / 4), (operaMod / 4));
        Sourceblocks[i] = BigInteger(block);
    }
    //---------------------

    //target分组
    BigInteger Targetblocks[arrsize];

    BigInteger shiftReg = IV;   //IV送入移位寄存器
    class DES des(BigInteger(K), shiftReg, ENCRPT);
    des.Encrypt();          //Ek 步骤
    BigInteger sbitsEk = BigInteger(des.getCipher()).toBinary(0).subbits(0, operaMod); //选择s位，此时为二进制
    Targetblocks[0] = Sourceblocks[0].toBinary(0).XOR(sbitsEk).toHex();         //明文M1和s位Ek作异或操作，最后转为16进制存入密文块中
    resultss << Targetblocks[0].toString();

    for (int i = 1; i < arrsize; i++) {

        shiftReg = shiftRegOperaForCFB(shiftReg, Targetblocks[i - 1], operaMod);      //移位寄存器结果

        des.setPlaintext(shiftReg);
        //class DES desTwo(BigInteger(K), shiftReg, ENCRPT);
        des.Encrypt();                                  //Ek 步骤
        sbitsEk = BigInteger(des.getCipher()).toBinary(0).subbits(0, operaMod); //选择s位，此时为二进制
        Targetblocks[i] = Sourceblocks[i].toBinary(0).XOR(sbitsEk).toHex();       //把明文Mi和s位Ek作异或操作，最后转为16进制存入密文块中
        resultss << Targetblocks[i].toString();

    }

    return resultss.str();

}

string BlockEncryption::operateOFB(string source, int operaMod) {

    stringstream resultss;

    int arrsize = (source.length() * 4) / operaMod;
    BigInteger Sourceblocks[arrsize];      //明文分组
    BigInteger Targetblocks[arrsize];       //密文分组
    BigInteger keyStream[arrsize];     //密钥流
    //--------对source进行分组--------
    for (int i = 0; i < arrsize; i++) {
        string block = source.substr(i * (operaMod / 4), (operaMod / 4));
        Sourceblocks[i] = BigInteger(block);
    }
    //----------------------------

    BigInteger shiftReg = BigInteger(IV);
    class DES des(BigInteger(K), shiftReg, ENCRPT);
    des.Encrypt();
    keyStream[0] = BigInteger(des.getCipher());
    for (int i = 0; i < arrsize; i++) {
        if (i != arrsize - 1) {

            shiftReg = shiftRegOperaForOFB(shiftReg, keyStream[i], operaMod); //移位寄存器结果

            des.setPlaintext(shiftReg);
            des.Encrypt();                                  //获取新的keyStream
            keyStream[i + 1] = BigInteger(des.getCipher());       //保存keyStream
        }

        Targetblocks[i] = Sourceblocks[i].toBinary(0).XOR(keyStream[i].toBinary(0).subbits(0, operaMod)).toHex();

        resultss << Targetblocks[i].toString();
    }

    return resultss.str();
}