#include "../Math/gfp.h"
#include "../Tools/Hash.h"
#include "../Tools/random.h"

#include <cstdlib>
#include <ctime>
#include <chrono>
#include <iostream>
#include <vector>
#include <queue>

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

    void get_bits(bool *bits, size_t length) {
        for (int i = 0; i < length / 32; i ++) {
            unsigned int tmp = get_uint();
            for (int j = 0; j < 32; j ++) {
                bits[i * 32 + j] = tmp & 1;
                tmp >>= 1;
            }
        }
        unsigned int tmp = get_uint();
        for (int i = 0; i < length % 32; i ++) {
            bits[length - 1 - i] = tmp & 1;
            tmp >>= 1;
        }
    }
};

const size_t batch_size = 1000000;
const int KAPPA = 40;

int main() {
    bool *delta = new bool[batch_size];
    
    MyPRNG prng;
    prng.ReSeed();

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < KAPPA; i ++) {
        prng.get_bits(delta, batch_size);
    }

    auto end = std::chrono::high_resolution_clock::now();
    // std::chrono::duration<double> diff = ;
    cout << "Time: " << (end - start).count() / 1e6 << " ms" << endl;

    return 0;
}