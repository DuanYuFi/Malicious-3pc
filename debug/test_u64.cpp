#include <iostream>
#include <random>
#include <ctime>
#include <chrono>

using namespace std;

typedef unsigned long long T;
const int VECTOR_LENGTH = 10000;
const int TEST_TIMES = 100000;

mt19937_64 RNG = mt19937_64(time(0));
uniform_int_distribution<T> dist(0, 0xFFFFFFFFFFFFFFFF);

class Vector64 {
private:
    T data[VECTOR_LENGTH];

public:
    Vector64() {}
    void set_random() {
        // set all data with random 64bit numbers.
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            data[i] = dist(RNG);
        }
    }

    T operator*(const Vector64& other) {
        T result = 0;
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            result += data[i] * other.data[i];
        }
        return result;
    }

};


int main() {
    
    Vector64 v1, v2;
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