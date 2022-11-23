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
typedef uint64_t MulRing;
typedef uint128_t VerifyRing;

const int N = 64;
const int KAPPA = 40;
const int EBITS = 64;
const size_t BATCH_SIZE = 10000;
const int K = 8;

#define DEBUG

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

class LocalHash {
    octetStream buffer;
public:

    void update(int128 data) {
        buffer.store(data.get_lower());
        buffer.store(data.get_upper());
    }

    template <typename T>
    void update(T data) {
        buffer.store(data);
    }

    int128 final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        word lower, upper;
        octetStream byte_result = hash.final();
        byte_result.get(lower);
        byte_result.get(upper);
        int128 result(upper, lower);
        return result;
    }

    void append_one_msg(int128 msg) {
        update(msg);
    }

    void append_msges(vector<int128> msges) {
        for(int128 msg: msges) {
            update(msg);
        }
    }

    int128 get_challenge() {
        int128 r = final();
        return r;
    }
};

void getHash(bool **data, int n, int m) {
    LocalHash hash;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            hash.update((int) data[i][j]);
        }
    }
    int128 result = hash.final();
    cout << "Hash = " << result << endl;
}

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

    uint128_t getDoubleWord() {
        uint128_t res = get_uint();
        res = (res << 32) | get_uint();
        res = (res << 32) | get_uint();
        res = (res << 32) | get_uint();
        return res;
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

uint128_t getDoubleWord(PRNG& g) {
    uint128_t res = g.get_uint();
    res = (res << 32) | g.get_uint();
    res = (res << 32) | g.get_uint();
    res = (res << 32) | g.get_uint();
    return res;
}

// This function just uses in debug.
void receive_coef(VerifyRing coefs[], MyPRNG &prng, int length) {
    for (int i = 0; i < length; i ++) {
        coefs[i] = prng.getDoubleWord();
    }
}

struct InnerProducts {
    VerifyRing _inner_products[K][K];

    InnerProducts() {}
};

queue<InnerProducts> inner_product_right;

// bool global_rand_bits[KAPPA][BATCH_SIZE];
// bool left_rand_bits[KAPPA][EBITS];

void prove(
    MultiShare* shares,
    int seed,
    int seed_left,
    int batch_size,
    int k,
    bool **share_right,     // with size KAPPA * EBITS
    int verify_seed = 0
) {

    cout << "\tUnpacking datas" << endl;

    vector<MulTriple> triples;
    for (int i = 0; i < batch_size; i ++) {
        auto share = shares[i];
        triples.push_back({(uint128_t) share.x[1], (uint128_t) share.y[0], share.z[0] + share.rho[0]});
        triples.push_back({(uint128_t) share.x[0], (uint128_t) share.y[1], - share.x[1] * share.y[1] - share.rho[1]});
    }

    size_t new_batch_size = batch_size * 2;

    MyPRNG prng, prng_left;
    // SeededPRNG local_prng;

    prng.SetSeed(seed);
    prng_left.SetSeed(seed_left);

    VerifyRing *X, *Y, Z = 0;
    VerifyRing Z1 = 0, Z2 = 0;
    X = new VerifyRing[new_batch_size + EBITS * KAPPA + k];
    Y = new VerifyRing[new_batch_size + EBITS * KAPPA + k];
    memset(X, 0, sizeof(VerifyRing) * (new_batch_size + EBITS * KAPPA + k));
    memset(Y, 0, sizeof(VerifyRing) * (new_batch_size + EBITS * KAPPA + k));

    // int128 **share_right = new int128*[KAPPA];

    cout << "\tPreparing Polynomials" << endl;
    VerifyRing LHS = 0, RHS = 0;

    bool *choices = new bool[batch_size];
    int *counter = new int[batch_size];

    memset(counter, 0, sizeof(int) * batch_size);

    for (int _ = 0; _ < KAPPA; _ ++) {

        // cout << "\t\tRound: " << _ << endl;

        for (int i = 0; i < batch_size; i ++) {
            choices[i] = prng.get_bit();
        }

        VerifyRing e;

        LHS = 0;
        RHS = 0;
        for (int i = 0; i < batch_size; i ++) {
            if (choices[i]) {
                LHS += triples[i * 2][0] * triples[i * 2][1];
                LHS += triples[i * 2 + 1][0] * triples[i * 2 + 1][1];
                RHS += triples[i * 2][2];
                RHS += triples[i * 2 + 1][2];
            }   
        }

        e = (LHS - RHS) >> 64;
        // assert ((uint64_t) (LHS - RHS) == 0);


        for (int i = 0; i < batch_size; i ++) {
            if (choices[i]) {
                counter[i] ++;
                Z += triples[i * 2][2];
                Z += triples[i * 2 + 1][2];

                Z1 += triples[i * 2][2];
                Z2 += triples[i * 2 + 1][2];
            }
        }
        // RHS += (e << 64);

        assert (LHS == RHS + (e << 64));

        // VerifyRing e_bits = 0;

        for (int i = 0; i < EBITS; i ++) {
            bool share_left = prng_left.get_bit();
            share_right[_][i] = ((e >> i) & 1) ^ share_left;
            X[new_batch_size + i + _ * EBITS] = 2 * ((uint128_t) share_left << i) << 64;
            Y[new_batch_size + i + _ * EBITS] = (uint128_t) share_right[_][i];
            Z += ((uint128_t) share_left << i) << 64;
            Z += ((uint128_t) share_right[_][i] << i) << 64;

            if (share_left) {
                Z1 += ((uint128_t) 1 << i) << 64;
            }
            if (share_right[_][i]) {
                Z2 += ((uint128_t) 1 << i) << 64;
            }
        }

        assert (Z == Z1 + Z2);
    }

    for (int i = 0; i < batch_size; i ++) {

        X[i * 2] = triples[i * 2][0] * counter[i];
        Y[i * 2] = triples[i * 2][1];

        X[i * 2 + 1] = triples[i * 2 + 1][0] * counter[i];
        Y[i * 2 + 1] = triples[i * 2 + 1][1];
    }

    getHash(share_right, KAPPA, EBITS);

    // LHS = 0;
    // RHS = 0;
    // for (int i = 0; i < new_batch_size + KAPPA * EBITS; i ++) {
    //     LHS += X[i] * Y[i];
    // }
    // for (int i = 0; i < batch_size; i ++) {
    //     RHS += counter[i] * triples[i * 2][2];
    // }

    // puts("\t\tFinal Round: ");
    // print_uint128(LHS);
    // // cout << (uint64_t) LHS;
    // puts("");
    // print_uint128(Z);
    // // cout << (uint64_t) RHS;
    // puts("");
    show_uint128(Z);

    return ;

    

    int s = new_batch_size + EBITS * KAPPA;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX[k], coeffsY[k];
    
    // the verify_prng should not known by prover, this is just for debug.
    MyPRNG verify_prng;
    verify_prng.SetSeed(verify_seed);

    // int128 *newX, *newY;
    // newX = new int128[new_batch_size + KAPPA + k];
    // newY = new int128[new_batch_size + KAPPA + k];

    cout << "\tChoping" << endl;

    VerifyRing *res = new VerifyRing[k];

    while (true) {

        // cout << "\t\tnext vector length = " << vector_length << endl;
        // cout << "\t\tnow vector length = " << s << endl << endl;

        InnerProducts local_right;

        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                if (i == 0 && j == 0) {
                    continue;
                }
                VerifyRing r = prng_left.getDoubleWord();
                local_right._inner_products[i][j] = inner_product(X + i * vector_length, Y + j * vector_length, vector_length) - r;
            }
        }

        cout << "<X0, Y0> = ";
        print_uint128(inner_product(X, Y, vector_length));
        puts("");

        inner_product_right.push(local_right);

        receive_coef(coeffsX, verify_prng, k);
        receive_coef(coeffsY, verify_prng, k);

        // Debug code start

        for (int i = 0; i < k; i ++) {
            res[i] = 0;
            for (int j = 0; j < k; j ++) {
                res[i] += coeffsY[j] * inner_product(X + i * vector_length, Y + j * vector_length, vector_length);
                // Z += coeffsX[i] * coeffsY[j] * inner_product(X + i * vector_length, Y + j * vector_length, vector_length);
            }
        }

        Z = 0;
        for (int i = 0; i < k; i ++) {
            Z += res[i] * coeffsX[i];
        }

        // Debug code end

        for (int j = 0; j < vector_length; j ++) {
            X[j] *= coeffsX[0];
            Y[j] *= coeffsY[0];
        }
        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                X[j] += X[j + i * vector_length] * coeffsX[i];
                Y[j] += Y[j + i * vector_length] * coeffsY[i];

                X[j + i * vector_length] = 0;
                Y[j + i * vector_length] = 0;
            }
        }
        
        assert (inner_product(X, Y, vector_length) == Z);

        if (vector_length == 1) {
            assert (X[0] * Y[0] == Z);
            show_uint128(Z);
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

    vector<VerifyRing> origin_left, origin_right;

    MyPRNG prng, prng_left;
    prng.SetSeed(seed);
    prng_left.SetSeed(seed_left);

    cout << "\tUnpacking datas" << endl;

    for (int i = 0; i < batch_size; i ++) {
        auto share = shares[i];
        origin_left.push_back(share.y[1]);
        origin_left.push_back(share.x[1]);
        origin_right.push_back(share.z[1] + share.rho[1]);
    }

    VerifyRing *X, Z = 0;
    X = new VerifyRing[batch_size * 2 + EBITS * KAPPA + k];
    memset(X, 0, sizeof(VerifyRing) * (batch_size * 2 + EBITS * KAPPA + k));

    int new_batch_size = batch_size * 2;

    cout << "\tPreparing Polynomials" << endl;

    bool *choices = new bool[batch_size];
    int *counter = new int[batch_size];
    memset(counter, 0, sizeof(int) * batch_size);

    for (int _ = 0; _ < KAPPA; _ ++) {
        // share_right[i] = new int128[KAPPA];
        for (int i = 0; i < batch_size; i ++) {
            choices[i] = prng.get_bit();
        }
        
        for (int i = 0; i < batch_size; i ++) {
            if (choices[i]) {
                counter[i] ++;
                Z += origin_right[i];
            }
        }

        for (int i = 0; i < EBITS; i ++) {
            bool share_left = prng_left.get_bit();
            if (share_left) {
                X[new_batch_size + i + _ * EBITS] = 2 * ((uint128_t) 1 << i) << 64;
                Z += ((uint128_t) 1 << i) << 64;
            }
        }
    }

    for (int i = 0; i < batch_size; i ++) {
        X[i * 2] = origin_left[i * 2] * counter[i];
        X[i * 2 + 1] = origin_left[i * 2 + 1] * counter[i];
    }
    
    show_uint128(Z);
    return make_pair(0, 0);

    int s = new_batch_size + EBITS * KAPPA;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX[k], coeffsY[k];

    MyPRNG verify_prng;
    verify_prng.SetSeed(seed_verify);

    InnerProducts local_left;
    VerifyRing *res = new VerifyRing[k];

    cout << "\tChoping" << endl;

    while (true) {

        // cout << "\t\tnext vector length = " << vector_length << endl;
        // cout << "\t\tnow vector length = " << s << endl << endl;

        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                if (i == 0 && j == 0) {
                    continue;
                }
                VerifyRing r = prng_left.getDoubleWord();
                local_left._inner_products[i][j] = r;
            }
        }

        local_left._inner_products[0][0] = Z;
        for (int i = 1; i < k; i ++) {
            local_left._inner_products[0][0] -= local_left._inner_products[i][i];
        }

        cout << "[<X0, Y0>] = ";
        print_uint128(local_left._inner_products[0][0]);
        puts("");

        receive_coef(coeffsX, verify_prng, k);
        receive_coef(coeffsY, verify_prng, k);

        for (int j = 0; j < vector_length; j ++) {
            X[j] *= coeffsX[0];
        }
        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                X[j] += X[j + i * vector_length] * coeffsX[i];
                X[j + i * vector_length] = 0;
            }
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
            return make_pair(X[0], Z);
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }

}

pair<VerifyRing, VerifyRing> verify_right(
    MultiShare* shares,
    int seed,
    bool **share_right,
    int seed_verify,
    int batch_size,
    int k
) {

    vector<VerifyRing> origin_left, origin_right;

    MyPRNG prng;
    prng.SetSeed(seed);

    cout << "\tUnpacking datas" << endl;

    for (int i = 0; i < batch_size; i ++) {
        auto share = shares[i];
        origin_left.push_back(share.x[0]);
        origin_left.push_back(share.y[0]);
        origin_right.push_back((uint64_t) (-share.x[0] * share.y[0] - share.rho[0]));
    }

    VerifyRing *Y, Z = 0;
    Y = new VerifyRing[batch_size * 2 + EBITS * KAPPA + k];
    memset(Y, 0, sizeof(VerifyRing) * (batch_size * 2 + EBITS * KAPPA + k));

    int new_batch_size = batch_size * 2;

    cout << "\tPreparing Polynomials" << endl;

    bool *choices = new bool[batch_size];
    int *counter = new int[batch_size];

    for (int _ = 0; _ < KAPPA; _ ++) {
        // share_right[i] = new int128[KAPPA];
        for (int i = 0; i < batch_size; i ++) {
            choices[i] = prng.get_bit();
        }
        
        for (int i = 0; i < batch_size; i ++) {
            if (choices[i]) {
                counter[i] = 1;
                Z += origin_right[i];
            }
        }

        for (int i = 0; i < EBITS; i ++) {
            if (share_right[_][i]) {
                Y[new_batch_size + i + _ * EBITS] = 1;
                Z += ((uint128_t) 1 << i) << 64;
            }
        }
    }

    for (int i = 0; i < batch_size; i ++) {
        Y[i * 2] = origin_left[i * 2] * counter[i];
        Y[i * 2 + 1] = origin_left[i * 2 + 1] * counter[i];
    }

    getHash(share_right, KAPPA, EBITS);

    show_uint128(Z);
    return make_pair(0, 0);
    
    int s = new_batch_size + EBITS * KAPPA;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX[k], coeffsY[k];

    MyPRNG verify_prng;
    verify_prng.SetSeed(seed_verify);

    InnerProducts local_right;
    VerifyRing *res = new VerifyRing[k];

    cout << "\tChoping" << endl;

    while (true) {

        // cout << "\t\tnext vector length = " << vector_length << endl;
        // cout << "\t\tnow vector length = " << s << endl << endl;
        
        local_right = inner_product_right.front();
        inner_product_right.pop();

        local_right._inner_products[0][0] = Z;
        for (int i = 1; i < k; i ++) {
            local_right._inner_products[0][0] -= local_right._inner_products[i][i];
        }

        cout << "[<X0, Y0>] = ";
        print_uint128(local_right._inner_products[0][0]);
        puts("");

        receive_coef(coeffsX, verify_prng, k);
        receive_coef(coeffsY, verify_prng, k);

        for (int j = 0; j < vector_length; j ++) {
            Y[j] *= coeffsY[0];
        }
        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                Y[j] += Y[j + i * vector_length] * coeffsY[i];
                Y[j + i * vector_length] = 0;
            }
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
            return make_pair(Y[0], Z);
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }
}

int _main() {

    RSShares rss_share;
    MultiShare *party0, *party1, *party2;

    party0 = new MultiShare[BATCH_SIZE];
    party1 = new MultiShare[BATCH_SIZE];
    party2 = new MultiShare[BATCH_SIZE];

    bool **share_right;

    share_right = new bool*[KAPPA];
    for (int i = 0; i < KAPPA; i ++) {
        share_right[i] = new bool[EBITS];
    }

    cout << "Generating triples" << endl;

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

    cout << "Generating seeds" << endl;

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
    
    cout << "Proving" << endl;

    prove(party1, global_seed, seed_left, BATCH_SIZE, K, share_right, verify_seed);

    cout << "verify_left" << endl;

    auto response1 = verify_left(party0, global_seed, seed_left, verify_seed, BATCH_SIZE, K);

    cout << "verify_right" << endl;

    auto response2 = verify_right(party2, global_seed, share_right, verify_seed, BATCH_SIZE, K);

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

int _debug() {
    RSShares rss_share;
    MultiShare *party0, *party1, *party2;

    party0 = new MultiShare[BATCH_SIZE];
    party1 = new MultiShare[BATCH_SIZE];
    party2 = new MultiShare[BATCH_SIZE];

    bool **share_right;

    share_right = new bool*[KAPPA];
    for (int i = 0; i < KAPPA; i ++) {
        share_right[i] = new bool[EBITS];
    }

    cout << "Generating triples" << endl;

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

    cout << "Generating seeds" << endl;

    MyPRNG seed_prng;
    seed_prng.ReSeed();

    int global_seed = rand();
    int seed_left = rand();
    int verify_seed = rand();
    

    prove(party1, global_seed, seed_left, BATCH_SIZE, K, share_right, verify_seed);

    auto response1 = verify_left(party0, global_seed, seed_left, verify_seed, BATCH_SIZE, K);

    auto response2 = verify_right(party2, global_seed, share_right, verify_seed, BATCH_SIZE, K);

    return 0;
}

int main() {

    // srand(0xdeadbeef);
#ifdef DEBUG
    return _debug();
#else
    return _main();
#endif

}