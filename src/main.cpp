#include <iostream>
#include <cmath>
#include <ctime>
#include <fstream>
#include "sstream"
#include "typeinfo"
#include "DES.h"

using namespace std;



int main(int argc, char * argv[]) {


    BigInteger test1("4E6574776F726B20");
    BigInteger binaryTest;
    binaryTest = test1.toBinary(0);

    cout<<binaryTest.toString()<<endl;
    cout<<binaryTest.toHex().toString()<<endl;

    DES des;
    BigInteger afterInverse = des.initialPermutation(binaryTest);
    cout<<afterInverse.toString()<<endl;


    return 0;
}