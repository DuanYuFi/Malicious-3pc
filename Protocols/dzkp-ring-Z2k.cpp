// #include "../Math/gfp.h"
// #include "../Tools/Hash.h"
// #include "../Tools/random.h"

#ifndef PROTOCOLS_DZKP_RING_Z2K_CPP_
#define PROTOCOLS_DZKP_RING_Z2K_CPP_

#include <cstdlib>
#include <ctime>
#include <chrono>
#include <iostream>
#include <vector>
#include <queue>
#include <cstring>
#include <array>
#include <cassert>

using namespace std;

typedef unsigned __int128 uint128_t;
typedef uint64_t MulRing;
typedef uint128_t VerifyRing;

const int N = 64;
const int KAPPA = 40;
const int EBITS = 64;
const size_t BATCH_SIZE = (1 << 24);
const int K = 8;

void print_uint128(uint128_t x) {
    if (x < 0) {
        putchar('-');
        x = -x;
    }
    if (x > 9) print_uint128(x / 10);
    putchar(x % 10 + '0');
}

#define show_uint128(value) \
    cout << #value << " = "; \
    print_uint128(value); \
    cout << endl;


typedef array<MulRing, 2> RSShare;
struct MultiShare {
    RSShare x, y;
    RSShare z;
    RSShare rho;

    MultiShare() {
        x = {0, 0};
        y = {0, 0};
        z = {0, 0};
        rho = {0, 0};
    }
    
    MultiShare(RSShare x, RSShare y, RSShare z, RSShare rho) {
        this->x = x;
        this->y = y;
        this->z = z;
        this->rho = rho;
    }
};

MulRing getRand64Bits() {
    MulRing a = 0;
    a = rand();
    a = (a << 32) | rand();
    return a;
}

template <typename T>
T inner_product(T* v1, T* v2, size_t length) {
    T res = 0;
    for (int i = 0; i < length; i ++) {
        res += v1[i] * v2[i];
    }

    return res;
}

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

    uint128_t get_doubleword() {
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

typedef array<MultiShare, 3> RSShares;
typedef array<VerifyRing, 3> MulTriple;

RSShares get_share() {
    MulRing x0, x1, x2, y0, y1, y2, x, y, rho0, rho1, rho2, z0, z1, z2;
    x = getRand64Bits();
    y = getRand64Bits();
    
    x0 = getRand64Bits();
    x1 = getRand64Bits();
    x2 = x - x1 - x0;
    y0 = getRand64Bits();
    y1 = getRand64Bits();
    y2 = y - y1 - y0;

    rho0 = getRand64Bits();
    rho1 = getRand64Bits();
    rho2 = -(rho0 + rho1);

    z0 = x0 * y1 + x1 * y0 + x1 * y1 + rho1 - rho0;
    z1 = x1 * y2 + x2 * y1 + x2 * y2 + rho2 - rho1;
    z2 = x2 * y0 + x0 * y2 + x0 * y0 + rho0 - rho2;

    assert (z0 + z1 + z2 == x * y);

    MultiShare shares0 = {
        {x0, x1}, 
        {y0, y1},
        {z0, z1},
        {rho0, rho1}
    };

    MultiShare shares1 = {
        {x1, x2},
        {y1, y2},
        {z1, z2},
        {rho1, rho2}
    };

    MultiShare shares2 = {
        {x2, x0},
        {y2, y0},
        {z2, z0},
        {rho2, rho0}
    };

    return {shares0, shares1, shares2};
}

// uint128_t get_doubleword(PRNG& g) {
//     uint128_t res = g.get_uint();
//     res = (res << 32) | g.get_uint();
//     res = (res << 32) | g.get_uint();
//     res = (res << 32) | g.get_uint();
//     return res;
// }

// This function just uses in debug.
void receive_coef(VerifyRing coefs[], MyPRNG &prng, int length) {
    for (int i = 0; i < length; i ++) {
        coefs[i] = prng.get_doubleword();
    }
}

struct InnerProducts {
    VerifyRing _inner_products[K][K];

    InnerProducts() {}
};

queue<InnerProducts> inner_product_right;


void prove(
    MultiShare* shares,
    int seed,
    int seed_left,
    int batch_size,
    int k,
    VerifyRing *share_right,     // with size KAPPA
    int verify_seed = 0
) {

    // cout << "\tUnpacking datas" << endl;
    auto p1 = std::chrono::high_resolution_clock::now();

    size_t new_batch_size = batch_size * 2;


    VerifyRing *X, *Y;
    X = new VerifyRing[new_batch_size + k];
    Y = new VerifyRing[new_batch_size + k];

    // VerifyRing Z = 0, *_Z = new VerifyRing[KAPPA];

    VerifyRing *E;
    E = new VerifyRing[batch_size];

    for (int i = 0; i < batch_size; i ++) {

        auto share = shares[i];
        VerifyRing z1 = share.z[0] + share.rho[0], z2 = - share.x[1] * share.y[1] - share.rho[1];
        X[i * 2] = (uint128_t) share.y[0];
        X[i * 2 + 1] = (uint128_t) share.x[0];
        Y[i * 2] = (uint128_t) share.x[1];
        Y[i * 2 + 1] = (uint128_t) share.y[1];

        E[i] = X[i * 2] * Y[i * 2];
        E[i] += X[i * 2 + 1] * Y[i * 2 + 1];
        E[i] -= (z1 + z2);
    }

    auto p2 = std::chrono::high_resolution_clock::now();
    cout << "\tUnpack datas costs: " << (p2 - p1).count() / 1e6 << " ms" << endl;

    MyPRNG prng, prng_left;

    prng.SetSeed(seed);
    prng_left.SetSeed(seed_left);

    // cout << "\tPreparing (length batch_size + e_bits^2) Polynomial" << endl;
    auto p3 = std::chrono::high_resolution_clock::now();

    bool **choices = new bool*[KAPPA];
    for (int i = 0; i < KAPPA; i ++) {
        choices[i] = new bool[batch_size];
    }

    VerifyRing *counter = new VerifyRing[batch_size];
    VerifyRing *random_coef = new VerifyRing[KAPPA];

    memset(counter, 0, sizeof(int) * batch_size);

    for (int _ = 0; _ < KAPPA; _ ++) {

        prng.get_bits(choices[_], batch_size);

        VerifyRing e = 0;

        for (int i = 0; i < batch_size; i ++) {
            // auto share = shares[i];
            // VerifyRing z1 = share.z[0] + share.rho[0], z2 = - share.x[1] * share.y[1] - share.rho[1];
            // _Z[_] += z1 + z2;

            e += E[i] * choices[_][i];
        }

        e = e >> 64;
        
        VerifyRing share_left = prng_left.get_doubleword();
        share_right[_] = e - share_left;
    }

    auto p35 = std::chrono::high_resolution_clock::now();
    cout << "\tTransform part 1: " << (p35 - p3).count() / 1e6 << " ms" << endl;

    for (int i = 0; i < KAPPA; i ++) {
        random_coef[i] = prng.get_doubleword();
    }

    for (int i = 0; i < KAPPA; i ++) {
        for (int j = 0; j < batch_size; j ++) {
            counter[j] += choices[i][j] * random_coef[i];
        }
        // Z += _Z[i] * random_coef[i];
    }
    

    for (int i = 0; i < batch_size; i ++) {
        X[i * 2] *= counter[i];
        X[i * 2 + 1] *= counter[i];
    }

    // show_uint128(Z);

    VerifyRing Z = 0;
    for (int i = 0; i < batch_size * 2; i ++) {
        Z += X[i] * Y[i];
    }

    show_uint128(Z);


    auto p4 = std::chrono::high_resolution_clock::now();
    cout << "\tTransform to one inner-product costs: " << (p4 - p3).count() / 1e6 << " ms" << endl;

    int s = new_batch_size;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX[k], coeffsY[k];
    
    MyPRNG verify_prng;
    verify_prng.SetSeed(verify_seed);

    // cout << "\tChoping" << endl;
    auto p5 = std::chrono::high_resolution_clock::now();

    while (true) {

        InnerProducts local_right;

        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                if (i == 0 && j == 0) {
                    continue;
                }
                VerifyRing r = prng_left.get_doubleword();
                local_right._inner_products[i][j] = inner_product(X + i * vector_length, Y + j * vector_length, vector_length) - r;
            }
        }

        inner_product_right.push(local_right);

        receive_coef(coeffsX, verify_prng, k);
        receive_coef(coeffsY, verify_prng, k);

        for (int j = 0; j < vector_length; j ++) {
            X[j] *= coeffsX[0];
            Y[j] *= coeffsY[0];
        }
        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                X[j] += X[j + i * vector_length] * coeffsX[i];
                Y[j] += Y[j + i * vector_length] * coeffsY[i];
            }
        }

        for (int i = 0; i < vector_length; i ++) {
            X[vector_length + i] = 0;
            Y[vector_length + i] = 0;
        }
        
        if (vector_length == 1) {
            auto p6 = std::chrono::high_resolution_clock::now();
            cout << "\tChop costs: " << (p6 - p5).count() / 1e6 << " ms" << endl;
            break;
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }

}

pair<VerifyRing, VerifyRing> verify_left(
    MultiShare* shares,
    int seed,
    int seed_left,
    int seed_verify,
    int batch_size,
    int k
) {

    VerifyRing *origin_right = new VerifyRing[batch_size];
    VerifyRing *X, Z = 0, *_Z = new VerifyRing[KAPPA];
    X = new VerifyRing[batch_size * 2 + k];

    MyPRNG prng, prng_left;
    prng.SetSeed(seed);
    prng_left.SetSeed(seed_left);

    // cout << "\tUnpacking datas" << endl;
    auto p1 = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < batch_size; i ++) {
        auto share = shares[i];
        X[i * 2] = share.y[1];
        X[i * 2 + 1] = share.x[1];
        origin_right[i] = share.z[1] + share.rho[1];
    }

    auto p2 = std::chrono::high_resolution_clock::now();
    cout << "\tUnpack datas costs: " << (p2 - p1).count() / 1e6 << " ms" << endl;

    int new_batch_size = batch_size * 2;

    // cout << "\tPreparing Polynomials" << endl;
    auto p3 = std::chrono::high_resolution_clock::now();

    bool **choices = new bool*[KAPPA];
    for (int i = 0; i < KAPPA; i ++) {
        choices[i] = new bool[batch_size];
    }

    VerifyRing *counter = new VerifyRing[batch_size];
    VerifyRing *random_coef = new VerifyRing[KAPPA];

    for (int _ = 0; _ < KAPPA; _ ++) {
        // share_right[i] = new int128[KAPPA];
        // for (int i = 0; i < batch_size; i ++) {
        //     choices[i] = prng.get_bit();
        // }

        prng.get_bits(choices[_], batch_size);
        
        for (int i = 0; i < batch_size; i ++) {
            _Z[_] += origin_right[i] * choices[_][i];
        }

        VerifyRing share_left = prng_left.get_doubleword();
        _Z[_] += share_left << 64;

    }

    for (int i = 0; i < KAPPA; i ++) {
        random_coef[i] = prng.get_doubleword();
    }

    for (int i = 0; i < KAPPA; i ++) {
        for (int j = 0; j < batch_size; j ++) {
            counter[j] += choices[i][j] * random_coef[i];
        }
        Z += _Z[i] * random_coef[i];
    }

    for (int i = 0; i < batch_size; i ++) {
        X[i * 2] *= counter[i];
        X[i * 2 + 1] *= counter[i];
    }

    // show_uint128(X[0]);
    
    auto p4 = std::chrono::high_resolution_clock::now();
    cout << "\tTransform to one inner-product costs: " << (p4 - p3).count() / 1e6 << " ms" << endl;


    int s = new_batch_size;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX[k], coeffsY[k];

    MyPRNG verify_prng;
    verify_prng.SetSeed(seed_verify);

    InnerProducts local_left;
    VerifyRing *res = new VerifyRing[k];

    // cout << "\tChoping" << endl;
    auto p5 = std::chrono::high_resolution_clock::now();

    while (true) {

        // cout << "\t\tnext vector length = " << vector_length << endl;
        // cout << "\t\tnow vector length = " << s << endl << endl;

        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                if (i == 0 && j == 0) {
                    continue;
                }
                VerifyRing r = prng_left.get_doubleword();
                local_left._inner_products[i][j] = r;
            }
        }

        local_left._inner_products[0][0] = Z;
        for (int i = 1; i < k; i ++) {
            local_left._inner_products[0][0] -= local_left._inner_products[i][i];
        }

        receive_coef(coeffsX, verify_prng, k);
        receive_coef(coeffsY, verify_prng, k);

        for (int j = 0; j < vector_length; j ++) {
            X[j] *= coeffsX[0];
        }
        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                X[j] += X[j + i * vector_length] * coeffsX[i];
            }
        }

        for (int i = 0; i < vector_length; i ++) {
            X[vector_length + i] = 0;
        }
        
        for (int i = 0; i < k; i ++) {
            res[i] = 0;
            for (int j = 0; j < k; j ++) {
                res[i] += coeffsY[j] * local_left._inner_products[i][j];
            }
        }

        Z = 0;
        for (int i = 0; i < k; i ++) {
            Z += res[i] * coeffsX[i];
        }

        if (vector_length == 1) {
            auto p6 = std::chrono::high_resolution_clock::now();
            cout << "\tChop costs: " << (p6 - p5).count() / 1e6 << " ms" << endl;
            return make_pair(X[0], Z);
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }

}

pair<VerifyRing, VerifyRing> verify_right(
    MultiShare* shares,
    int seed,
    VerifyRing *share_right,
    int seed_verify,
    int batch_size,
    int k
) {

    VerifyRing *origin_left = new VerifyRing[batch_size * 2], *origin_right = new VerifyRing[batch_size];
    VerifyRing *Y, Z = 0, *_Z = new VerifyRing[KAPPA];
    Y = new VerifyRing[batch_size * 2 + k];

    MyPRNG prng;
    prng.SetSeed(seed);

    // cout << "\tUnpacking datas" << endl;
    auto p1 = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < batch_size; i ++) {
        auto share = shares[i];
        Y[i * 2] = share.x[0];
        Y[i * 2 + 1] = share.y[0];
        origin_right[i] = -share.x[0] * share.y[0] - share.rho[0];
    }

    auto p2 = std::chrono::high_resolution_clock::now();
    cout << "\tUnpack datas costs: " << (p2 - p1).count() / 1e6 << " ms" << endl;

    int new_batch_size = batch_size * 2;

    // cout << "\tPreparing Polynomials" << endl;
    auto p3 = std::chrono::high_resolution_clock::now();

    bool *choices = new bool[batch_size];

    VerifyRing *random_coef = new VerifyRing[KAPPA];

    for (int _ = 0; _ < KAPPA; _ ++) {
        prng.get_bits(choices, batch_size);
        
        for (int i = 0; i < batch_size; i ++) {
            _Z[_] += origin_right[i] * choices[i];
        }

        _Z[_] += share_right[_] << 64;
    }

    for (int i = 0; i < KAPPA; i ++) {
        random_coef[i] = prng.get_doubleword();
    }

    for (int i = 0; i < KAPPA; i ++) {
        Z += _Z[i] * random_coef[i];
    }

    // show_uint128(Y[0]);

    auto p4 = std::chrono::high_resolution_clock::now();
    cout << "\tTransform to one inner-product costs: " << (p4 - p3).count() / 1e6 << " ms" << endl;
    
    int s = new_batch_size;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX[k], coeffsY[k];

    MyPRNG verify_prng;
    verify_prng.SetSeed(seed_verify);

    InnerProducts local_right;
    VerifyRing *res = new VerifyRing[k];

    // cout << "\tChoping" << endl;
    auto p5 = std::chrono::high_resolution_clock::now();

    while (true) {
        
        local_right = inner_product_right.front();
        inner_product_right.pop();

        local_right._inner_products[0][0] = Z;
        for (int i = 1; i < k; i ++) {
            local_right._inner_products[0][0] -= local_right._inner_products[i][i];
        }

        receive_coef(coeffsX, verify_prng, k);
        receive_coef(coeffsY, verify_prng, k);

        for (int j = 0; j < vector_length; j ++) {
            Y[j] *= coeffsY[0];
        }
        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                Y[j] += Y[j + i * vector_length] * coeffsY[i];
            }
        }

        for (int i = 0; i < vector_length; i ++) {
            Y[vector_length + i] = 0;
        }
        
        for (int i = 0; i < k; i ++) {
            res[i] = 0;
            for (int j = 0; j < k; j ++) {
                res[i] += coeffsY[j] * local_right._inner_products[i][j];
            }
        }

        Z = 0;
        for (int i = 0; i < k; i ++) {
            Z += res[i] * coeffsX[i];
        }

        if (vector_length == 1) {
            auto p6 = std::chrono::high_resolution_clock::now();
            cout << "\tChop costs: " << (p6 - p5).count() / 1e6 << " ms" << endl;
            return make_pair(Y[0], Z);
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }
}

int main() {

    // srand(time(0));

    RSShares rss_share;
    MultiShare *party0, *party1, *party2;

    party0 = new MultiShare[BATCH_SIZE];
    party1 = new MultiShare[BATCH_SIZE];
    party2 = new MultiShare[BATCH_SIZE];

    VerifyRing *share_right;

    share_right = new VerifyRing[KAPPA];

    cout << "Generating triples. Prove " << BATCH_SIZE << " in one verify. " << endl;
    cout << "Parameter settings: " << endl;
    cout << "\tProver: P1. Verifiers: P0, P2" << endl;
    cout << "\tBATCH_SIZE = " << BATCH_SIZE << endl;
    cout << "\tK = " << K << endl;
    cout << "\tKAPPA = " << KAPPA << endl;
    cout << "\tbit_length of e = " << EBITS << endl;
    cout << "\tOrigin multiply ring: " << "Z2^64" << endl;
    cout << "\tVerify Ring: " << "Z2^128" << endl;


    for (int i = 0; i < BATCH_SIZE; i ++) {
        rss_share = get_share();
        party0[i] = rss_share[0];
        party1[i] = rss_share[1];
        party2[i] = rss_share[2];

        // MulRing x = rss_share[0].x[0] + rss_share[1].x[0] + rss_share[1].x[1];
        // MulRing y = rss_share[0].y[0] + rss_share[1].y[0] + rss_share[1].y[1];
        // MulRing z = rss_share[0].z + rss_share[1].z + rss_share[2].z;
        // assert(x * y == z);
    }

    // cout << "Generating seeds" << endl;

    MyPRNG seed_prng;
    seed_prng.ReSeed();

    int global_seed = rand();
    int seed_left = rand();
    int verify_seed = rand();

    // cout << "Generating random bits" << endl;

    // unsigned int buffer = 0, buffer_bits = 0;
    // for (int i = 0; i < KAPPA; i ++) {
    //     for (int j = 0; j < batch_size; j ++) {
    //         global_rand_bits[i][j] = seed_prng.get_bit();
    //     }
    // }

    // for (int i = 0; i < KAPPA; i ++) {
    //     for (int j = 0; j < EBITS; j ++) {
    //         left_rand_bits[i][j] = seed_prng.get_bit();
    //     }
    // }

    puts("= = = = = = = = = = = = = = = = = = = = = = = = = = = =");
    
    cout << "Prove part: " << endl;

    auto p1 = std::chrono::high_resolution_clock::now();
    prove(party1, global_seed, seed_left, BATCH_SIZE, K, share_right, verify_seed);
    auto p2 = std::chrono::high_resolution_clock::now();
    
    cout << "Prove part costs: " << (p2 - p1).count() / 1e6 << " ms" << endl;
    puts("= = = = = = = = = = = = = = = = = = = = = = = = = = = =");

    cout << "verify_left part: " << endl;

    auto p3 = std::chrono::high_resolution_clock::now();
    auto response1 = verify_left(party0, global_seed, seed_left, verify_seed, BATCH_SIZE, K);
    auto p4 = std::chrono::high_resolution_clock::now();

    cout << "verify_left part costs: " << (p4 - p3).count() / 1e6 << " ms" << endl;
    puts("= = = = = = = = = = = = = = = = = = = = = = = = = = = =");

    cout << "verify_right part: " << endl;

    auto p5 = std::chrono::high_resolution_clock::now();
    auto response2 = verify_right(party2, global_seed, share_right, verify_seed, BATCH_SIZE, K);
    auto p6 = std::chrono::high_resolution_clock::now();

    cout << "verify_right part costs: " << (p6 - p5).count() / 1e6 << " ms" << endl;

    print_uint128(response1.first);
    cout << " * ";
    print_uint128(response2.first);
    cout << " % 2 ** 128 should be equal to ";
    print_uint128(response1.second + response2.second);
    cout << endl;
    // cout << int128(response1.first) << " * " << int128(response2.first) << " should be equal to " << int128(response1.second + response2.second) << endl;
    cout << (response1.first * response2.first == (response1.second + response2.second)) << endl;

    return 0;
}

#endif