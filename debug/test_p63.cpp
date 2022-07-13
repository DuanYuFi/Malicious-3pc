// #define GFP_MOD_SZ 1

#include "Math/gfp.hpp"
#include "Math/bigint.hpp"

#include <iostream>
#include <random>
#include <ctime>
#include <chrono>

using namespace std;

const int VECTOR_LENGTH = 10000;
const int TEST_TIMES = 100000;
const unsigned long long p = 6089328253619682521;
const bigint bp = bigint(Integer(p));

typedef gfp_<0, 1> T;

mt19937_64 RNG = mt19937_64(time(0));
uniform_int_distribution<long long> dist(0, p);

class VectorPrime {

private:
    T data[VECTOR_LENGTH];

public:
    VectorPrime() {
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            data[i].init_field(bp);
        }
    }
    void set_random() {
        // set all data with random 64bit numbers.
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            data[i] = dist(RNG);
        }
    }

    T operator*(const VectorPrime& other) {
        T result = 0;
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            result += data[i] * other.data[i];
        }
        return result;
    }

};

int main() {
    VectorPrime v1;
    VectorPrime v2;
    auto start = std::chrono::high_resolution_clock::now(), end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> total = start - start;
    for (int i = 0; i < TEST_TIMES; i++) {
        v1.set_random();
        v2.set_random();
        start = std::chrono::high_resolution_clock::now();
        v1 * v2;
        total += std::chrono::high_resolution_clock::now() - start;
    }

    cout << "Time: " << total.count() << "ms" << endl;
    return 0;

}