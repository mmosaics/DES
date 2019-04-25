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
    BigInteger C0;          //存储C0
    BigInteger D0;          //存储D0
    BigInteger plaintext;


public:

    //----构造函数-----
    explicit DES(string K);

    //----初始置换-----
    BigInteger initialPermutation();                                //对明文分组进行初始变换

    //----生成子密钥----
    void generateKifirstRound(); //生成C0和D0
    BigInteger generateKi(BigInteger C, BigInteger D, int round);   //根据轮数生成子密钥




    //----重要私有成员设置----
    void setPlaintext(string plaintext);                            //设置明文





};


#endif //DES_DES_H
