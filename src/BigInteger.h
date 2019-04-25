//
// Created by OneCarrot on 2019-04-14.
//

#include <iostream>
#include <vector>
#include <string>
#include <map>

using namespace std;

class BigInteger {

private:
    vector<char> _data;
    string value;
    string name;




    int compare(const BigInteger &li);  //比较函数，大于返回1，等于0，小于-1
    void trimZero();
    string getString();
    int getValue(char it);
    char getKey(int it);
    void pushZero(int i);

public:
    BigInteger();
    explicit BigInteger(const int val);
    explicit BigInteger(const string &valStr);


    //四则运算符重载
    BigInteger operator+( BigInteger &li);
    BigInteger operator-( BigInteger &li);
    BigInteger operator*( BigInteger &li);
    BigInteger operator/( BigInteger &li);
    BigInteger operator%( BigInteger &li);

    // 比较运算符重载
    bool operator==(const BigInteger &li);
    bool operator!=(const BigInteger &li);
    bool operator<(const BigInteger &li);
    bool operator>(const BigInteger &li);
    bool operator<=(const BigInteger &li);
    bool operator>=(const BigInteger &li);

    // 字符串格式化输出
    std::string toString();

    //指数运算
    BigInteger pow(int n);
    BigInteger pow(BigInteger n);

    //随机数
    static BigInteger generateRangeRand(BigInteger max) ;

    //进制转换
    BigInteger toBinary(int flag);
    BigInteger toHex();

    //工具
    int getFirst();
    string getName();
    void setName(string name);
    char valueOf(int index);
    int getSize();

    //二进制模式操作
    void cyclicShift(int num, bool direction);       //循环移位， num代表位数， direction代表方向 左0右1
    BigInteger XOR(BigInteger b);                    //只实现了位数相同的异或


};


