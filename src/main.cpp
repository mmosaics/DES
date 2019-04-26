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
    string plain = "4E6574776F726B20";


    BlockEncryption blockEncryption(ECB, DES, plain, K);
    cout<<blockEncryption.modeECB()<<endl;




    return 0;
}