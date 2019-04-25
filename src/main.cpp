#include <iostream>
#include <cmath>
#include <ctime>
#include <fstream>
#include "sstream"
#include "typeinfo"
#include "DES.h"

using namespace std;



int main(int argc, char * argv[]) {


    string K = "57696C6C69616D53";

    BigInteger k(K);

    //cout<<k.toBinary(0).toString()<<endl;

    DES des(K);
    //des.generateKifirstRound();
    BigInteger C("0000000011111111011111101000");
    BigInteger D("1000000101001101010111100001");
    BigInteger res = des.generateKi(C,D,1);
    cout<<res.toString()<<endl<<res.getSize()<<endl;


    return 0;
}