#include <iostream>
#include <cmath>
#include <ctime>
#include <fstream>
#include "BigInteger.h"
#include "sstream"
#include "typeinfo"

using namespace std;


int main(int argc, char * argv[]) {


    BigInteger test1("12AB2321312124");
    BigInteger binaryTest;
    binaryTest = test1.toBinary(0);

    cout<<binaryTest.toHex().toString()<<endl;

    /*
    map<string, char> binaryToHex = {
            {"0000",'0'}, {"0001",'1'}, {"0010",'2'}, {"0000",'3'}, {"0000",'4'}, {"0000",'5'}, {"0000",'6'}, {"0000",'7'},
            {"0000",'8'}, {"0000",'9'}, {"0000",'A'}, {"0000",'B'}, {"0000",'C'}, {"0000",'D'}, {"0000",'E'}, {"0000",'F'},
    };

    stringstream ss;
    ss<<'0'<<'0' <<'1'<<'1';
    cout<< typeid(ss.str()).name()<<endl;
    string s = "0011";
    cout<<binaryToHex["0011"];
*/

    return 0;
}