#include <iostream>
#include <cmath>
#include <ctime>
#include <fstream>
#include "sstream"
#include "typeinfo"
#include "BlockEncrytion.h"

using namespace std;

string getValueByPara(string key, int argc, char * argv[]) {

    for(int i = 0; i < argc; i++) {
        if(key == argv[i])
            return argv[i+1];
    }
    return "";

}

bool hasPara(string key, int argc, char * argv[]) {
    for(int i = 0; i < argc; i++) {
        if(key == argv[i])
            return true;
    }
    return false;
}

int main(int argc, char * argv[]) {


    ifstream plainfile, keyfile, vfile, cipherfiler;

    string plain, cipher, mod, IV, key;

    BlockEncryption blockEncryption(DES);

    if(hasPara("-p", argc, argv)) {
        plainfile.open(getValueByPara("-p", argc, argv));
        plainfile>>plain;
    }
    if(hasPara("-k", argc, argv)) {
        keyfile.open(getValueByPara("-k", argc, argv));
        keyfile>>key;
        blockEncryption.setKey(key);
    }
    if(hasPara("-v", argc, argv)) {
        vfile.open(getValueByPara("-v", argc, argv));
        vfile>>IV;
        blockEncryption.setIV(IV);
    }
    if(hasPara("-c", argc, argv)) {
        cipherfiler.open(getValueByPara("-c", argc, argv));
        cipherfiler>>cipher;
    }

    if(hasPara("-m", argc, argv)) {
        string mod = getValueByPara("-m",argc,argv);
        if(mod == "ecb" || mod == "ECB")
            blockEncryption.setMod(ECB);
        if(mod == "cbc" || mod == "CBC")
            blockEncryption.setMod(CBC);
        if(mod == "cfb" || mod == "CFB")
            blockEncryption.setMod(CFB);
        if(mod == "ofb" || mod == "OFB")
            blockEncryption.setMod(OFB);
    }

    if(hasPara("-e", argc, argv)) {
        blockEncryption.setPlaintext(plain);
        cipher = blockEncryption.Encrypt();
        ofstream cipherOutStream;
        cipherOutStream.open(getValueByPara("-c", argc, argv));
        cipherOutStream<<cipher;
        cout<<"Encrypt success"<<endl<<"The cipher is at \""<<getValueByPara("-c",argc,argv)<<"\""<<endl;
    }

    if(hasPara("-d", argc, argv)) {
        blockEncryption.setCipher(cipher);
        plain = blockEncryption.Decrypt();
        ofstream plainOutStream;
        plainOutStream.open(getValueByPara("-p", argc, argv));
        plainOutStream<<plain;
        cout<<"Decrypt success"<<endl<<"The plain is at \""<<getValueByPara("-p",argc,argv)<<"\""<<endl;
    }

    if(hasPara("-t", argc, argv)) {
        ifstream testdata;
        testdata.open("./DES_test.txt");
        string testplain;
        testdata>>testplain;

        string insideplain = testplain;
        string insidecipher;

        clock_t start,finish;
        double totaltime;

        ModeOfOperation mods[4] = {ECB, CBC, CFB, OFB};
        string modString[4] = {"ECB", "CBC", "CFB", "OFB"};

        //-------对ECB进行测试---------
        for(int i = 0; i < 4; i++) {
            blockEncryption.setMod(mods[i]);
            start = clock();
            for (int j = 0; j < 20; j++) {
                blockEncryption.setPlaintext(insideplain);
                insidecipher = blockEncryption.Encrypt();
                blockEncryption.setCipher(insidecipher);
                insideplain = blockEncryption.Decrypt();
            }
            finish = clock();
            totaltime = (double) (finish - start) / CLOCKS_PER_SEC;
            cout << "\n" << modString[i] << "加密运行时间:  " << totaltime << "s" << endl;
        }
        //-----------------------------


    }


    return 0;
}