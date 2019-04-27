cmake_minimum_required(VERSION 3.13)
project(DES)

set(CMAKE_CXX_STANDARD 14)

add_executable(DES src/main.cpp src/BigInteger.h src/BigInteger.cpp src/BigInteger.cpp src/BigInteger.h src/DES.cpp src/DES.h src/BlockEncrytion.cpp src/BlockEncrytion.h)