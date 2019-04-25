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

    DES des(K);
    des.initialCandD();


    return 0;
}