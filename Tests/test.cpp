#include "../Math/gfp.h"
#include "../Tools/Hash.h"
#include "../Tools/random.h"

#include <cstdlib>
#include <ctime>
#include <chrono>
#include <iostream>
#include <vector>

using namespace std;

typedef unsigned __int128 uint128_t;

class MyPRNG {
    const static int LENGTH = 10;
    int status[LENGTH];
    int coefs[LENGTH];
    int buffer;
    int buffer_size;
public:
    MyPRNG(): buffer(0), buffer_size(0) {}
    MyPRNG(int seed): MyPRNG() {
        SetSeed(seed);
    }

    void SetSeed(int seed) {
        srand(seed);
        for (int i = 0; i < LENGTH; i ++) {
            status[i] = rand();
        }
        for (int i = 0; i < LENGTH; i ++) {
            coefs[i] = rand();
        }
    }

    void ReSeed() {
        SetSeed(rand());
    }

    unsigned int get_uint() {
        unsigned int ret = status[0] * coefs[0];
        for (int i = 1; i < LENGTH; i ++) {
            ret += status[i] * coefs[i];
            status[i-1] = status[i];
        }
        status[LENGTH - 1] = ret;
        return ret;
    }

    bool get_bit() {
        if (buffer_size == 0) {
            buffer = get_uint();
            buffer_size = 32;
        }
        bool ret = buffer & 1;
        buffer_size -= 1;
        buffer >>= 1;
        return ret;
    }

    uint128_t getDoubleWord() {
        uint128_t res = get_uint();
        res = (res << 32) | get_uint();
        res = (res << 32) | get_uint();
        res = (res << 32) | get_uint();
        return res;
    }
};

void print(uint128_t x) {
    if (x < 0) {
        putchar('-');
        x = -x;
    }
    if (x > 9) print(x / 10);
    putchar(x % 10 + '0');
}

int main() {
    
    MyPRNG prng;
    prng.ReSeed();
    unsigned int a = prng.get_uint();

    vector<array<bool, 2>> shares;

    for (int i = 0; i < 32; i ++) {
        bool bit = prng.get_bit();
        shares.push_back({bit, (bool) (((a >> i) & 1) ^ bit)});
    }

    unsigned int b = 0;
    for (int i = 0; i < 32; i ++) {
        b = b + (shares[i][0] << i) + (shares[i][1] << i) - (shares[i][0] << (i + 1)) * shares[i][1];
    }

    cout << a << " " << b << endl;

    // print(a * b);


    return 0;
}