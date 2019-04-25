//
// Created by OneCarrot on 2019-04-25.
//

#ifndef DES_DES_H
#define DES_DES_H

#define LEFT false
#define RIGHT true

#include "map"
#include "sstream"
#include "BigInteger.h"

using namespace std;

class DES {

private:
    static map<int, int> IP;
    static map<int, int> inverseIP;
    static map<int, int> E;
    static int S[8][4][16];
    static map<int, int> P;
    static map<int, int> PC_1;
    static map<int, int> PC_2;
    static map<int, int> LS;

    BigInteger K;           //密钥K
    BigInteger C;           //存储C
    BigInteger D;           //存储D
    BigInteger plaintext;   //存储明文
    BigInteger cipher;      //存储密文


    //----置换模块----
    BigInteger universalPermutation(BigInteger var, map<int, int> perMap);
    //----分割比特位---
    BigInteger splitBit(BigInteger bits, int size, bool side);



public:

    //----构造函数-----
    explicit DES(string K);
    DES(string K, string plain);

    //----生成子密钥----
    void generateKifirstRound(); //生成C0和D0
    BigInteger generateKi(BigInteger C, BigInteger D, int round);   //根据轮数生成子密钥

    //----初始置换-----
    BigInteger InitialPermutation();                                //对明文分组进行初始变换

    //----E扩展运算----
    BigInteger Expansion(BigInteger R);

    //----S盒运算-----
    BigInteger Substitution(BigInteger var);

    //----P置换------
    BigInteger Permutation(BigInteger var);

    //----F函数------
    BigInteger FeistelFunc(BigInteger K, BigInteger R);

    //----轮函数-----
    BigInteger RoundFunc(BigInteger var, BigInteger Ki, int round);

    //----16轮变换----
    BigInteger Round16(BigInteger var);

    //----位置交换----
    BigInteger ReversePosition(BigInteger var);

    //----初始逆置换---
    BigInteger InitialInversePermutation(BigInteger var);


    //----加密-----
    void Encrypt();


    //----重要私有成员设置----
    void setPlaintext(string plaintext);                            //设置明文
    void getPlaintext();
    string getCipher();



};


#endif //DES_DES_H
