#include <cstdlib>
#include "Math/gf2nlong.h"
#include <chrono>

typedef gf2n_long Field;

#define LENGTH 10000000

uint64_t get_int64() {
    uint64_t ret = rand();
    ret = ret << 16;
    ret = ret | rand();
    ret = ret << 16;
    ret = ret | rand();
    ret = ret << 16;
    ret = ret | rand();
    return ret;
}

int get_int() {
    int ret = rand();
    ret = ret << 16;
    ret = ret | rand();
    return ret;
}

Field vector1[LENGTH], vector2[LENGTH];

void test1() {
    auto start = chrono::high_resolution_clock::now();

    Field answer = 0;

    for (int i = 0; i < LENGTH; ++i) {
        answer += vector1[i] * vector2[i];
    }

    auto end = chrono::high_resolution_clock::now();

    cout << answer << endl;

    cout << "GF2N<64> with multiple mod op (" << LENGTH << " times): " << (end - start).count() / 1e6 << " ms" << endl;
}

void test2() {
    auto start = chrono::high_resolution_clock::now();

    Field answer;
    __m128i tmp = _mm_setzero_si128();

    for (int i = 0; i < LENGTH; ++i) {
        tmp ^= clmul<0>(int128(vector1[i].get()).a, int128(vector2[i].get()).a);
    }

    int128 _tmp(tmp);
    answer.reduce(_tmp.get_upper(), _tmp.get_lower());

    auto end = chrono::high_resolution_clock::now();

    cout << answer << endl;
    cout << "GF2N<64> with one mod op (" << LENGTH << " times): " << (end - start).count() / 1e6 << " ms" << endl;

}

int main() {

    // srand(time(0));

    Field::init_field(64);

    for (int i = 0; i < LENGTH; ++i) {
        vector1[i] = Field(get_int());
        vector2[i] = Field(get_int());
    }

    test1();
    test2();

    return 0;
}