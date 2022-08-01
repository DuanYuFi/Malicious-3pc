#include "Math/Z2k.hpp"
#include "Math/gfp.hpp"
#include "Math/bigint.hpp"
#include "Math/BitVec.h"

#include <iostream>
#include <random>
#include <ctime>
#include <chrono>

using namespace std;

typedef BitVec_<long> T;

int main() {

    T v1(1);

    
    unsigned long x = v1.get();


    cout << x << endl;

    return 0;
}