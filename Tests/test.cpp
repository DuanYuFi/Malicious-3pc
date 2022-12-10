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

uint64_t get_uint64() {
    uint64_t ret = rand();
    ret = ret << 32 | rand();
    return ret;
}

uint128_t get_uint128() {
    uint128_t ret = get_uint64();
    return ret << 64 | get_uint64();
}

void print_uint128(uint128_t x) {
    if (x > 9) print_uint128(x / 10);
    putchar(x % 10 + '0');
}

#define show_uint128(value) \
    cout << #value << " = "; \
    print_uint128(value); \
    cout << endl;

int main() {
    uint128_t z1 = get_uint64();
    uint128_t z2 = get_uint64();

    // uint128_t z3 = z1 * z2;

    show_uint128(z1 * z2);
    show_uint128(z1 * (uint64_t) z2);
    show_uint128((uint64_t) z1 * (uint64_t) z2);
    // show_uint128((uint64_t) z1 - (uint64_t) z2);


    return 0;
}