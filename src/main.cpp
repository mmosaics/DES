#include <iostream>
#include <cmath>
#include <ctime>
#include <fstream>
#include "sstream"
#include "typeinfo"
#include "DES.h"
#include "BlockEncrytion.h"

using namespace std;



int main(int argc, char * argv[]) {


    string K = "57696C6C69616D53";
    string plain = "4E6574776F726B205365637572697479";
    string plainhalf = "4E6574776F726B20";
    string IV = "5072656E74696365";
    string cipher = " ";


    //BigInteger test("A2");
    //cout<<test.toBinary(0).subbits(0,3).toString()<<endl;


    BlockEncryption blockEncryption(CBC, DES, plain, BLANK, K, IV);

    cout<<"加密测试： " <<endl;
    string ECBcipher = blockEncryption.modeECB(ENCRPT);
    string CBCcipher = blockEncryption.modeCBC(ENCRPT);
    string CFBcipher = blockEncryption.modeCFB(ENCRPT,8);
    string OFBcipher = blockEncryption.modeOFB(ENCRPT,8);

    cout<<ECBcipher<<endl;
    cout<<CBCcipher<<endl;
    cout<<CFBcipher<<endl;
    cout<<OFBcipher<<endl<<endl;

    BlockEncryption blockDecryption(CBC, DES, BLANK, ECBcipher, K, IV);

    cout<<"解密测试： "<< endl;

    string ECBplain = blockDecryption.modeECB(DECRPT);

    blockDecryption.setCipher(CBCcipher);
    string CBCplain = blockDecryption.modeCBC(DECRPT);

    blockDecryption.setCipher(CFBcipher);
    string CFBplain = blockDecryption.modeCFB(DECRPT, 8);

    blockDecryption.setCipher(OFBcipher);
    string OFBplain = blockDecryption.modeOFB(DECRPT, 8);



    cout<<ECBplain<<endl;
    cout<<CBCplain<<endl;
    cout<<CFBplain<<endl;
    cout<<OFBplain<<endl;





    return 0;
}