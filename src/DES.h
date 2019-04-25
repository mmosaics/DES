//
// Created by OneCarrot on 2019-04-25.
//

#ifndef DES_DES_H
#define DES_DES_H

#include "map"
#include "sstream"
#include "BigInteger.h"

using namespace std;

class DES {

private:
    static map<int, int> IP;
    static map<int, int> inverseIP;
    static map<int, int> E;
    //tatic int S[8][4][16];
    static map<int, int> P;


public:

    BigInteger initialPermutation(BigInteger plaintext);
    static int S[8][4][16];



};


#endif //DES_DES_H
