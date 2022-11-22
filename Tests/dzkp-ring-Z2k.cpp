#include "../Math/gfp.h"
#include "../Tools/Hash.h"
#include "../Tools/random.h"

#include <cstdlib>
#include <ctime>
#include <chrono>
#include <iostream>
#include <vector>

using namespace std;

typedef int128 R;
const int N = 64;
const int KAPPA = 40;
// const int128 MASK = (1 << (N + KAPPA)) - 1;
// const int128 MOD = 1 << (N + KAPPA);

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

class ArithDZKProof {
    vector<int128> X, Y;
    int128 Z;

    ArithDZKProof() {}
    ArithDZKProof(vector<int128> X, vector<int128> Y, int128 Z) {
        this->X = X;
        this->Y = Y;
        this->Z = Z;
    }
};

typedef pair<R, R> RSShare;
struct MultiShare {
    RSShare x, y;
    R z;
    RSShare rho;

    MultiShare() {
        x = make_pair(0, 0);
        y = make_pair(0, 0);
        z = 0;
        rho = make_pair(0, 0);
    }
    
    MultiShare(RSShare x, RSShare y, R z, RSShare rho) {
        this->x = x;
        this->y = y;
        this->z = z;
        this->rho = rho;
    }
};

R getRand64Bits() {
    R a = 0;
    a = rand();
    a = (a << 32) | rand();
    return a;
}

typedef array<MultiShare, 3> RSShares;
typedef array<R, 3> MulTriple;

RSShares get_share() {
    R x0, x1, x2, y0, y1, y2, x, y, rho0, rho1, rho2;
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

    MultiShare shares0 = {
        make_pair(x0, x1),
        make_pair(y0, y1),
        x0 * y1 + x1 * y0 + x1 * y1 + rho1 - rho0,
        make_pair(rho0, rho1)
    };

    MultiShare shares1 = {
        make_pair(x1, x2),
        make_pair(y1, y2),
        x1 * y2 + x2 * y1 + x2 * y2 + rho2 - rho1,
        make_pair(rho1, rho2)
    };

    MultiShare shares2 = {
        make_pair(x2, x0),
        make_pair(y2, y0),
        x2 * y0 + x0 * y2 + x0 * y0 + rho0 - rho2,
        make_pair(rho2, rho0)
    };

    return {shares0, shares1, shares2};
}

// This function just uses in debug.
void receive_coef(array<int128, k>& coefs, PRNG &prng, int length) {
    for (int i = 0; i < length; i ++) {
        coefs[i] = prng.get_doubleword() & MASK;
    }
}

int128 inner_product(int128* v1, int128* v2, size_t length) {
    int128 res = 0;
    for (int i = 0; i < length; i ++) {
        res += v1[i] * v2[i];
    }

    return res;
}

R prove(
    MultiShare* shares,
    octet* seed,
    octet* seed_left,
    int m,
    int batch_size,
    int k,
    bool **share_right,
    octet* verify_seed = NULL
) {
    vector<MulTriple> triples;
    for (int i = 0; i < batch_size; i ++) {
        auto share = shares[i];
        triples.push_back({share.x[1], share.y[0], share.z[1] - share.x[1] * share.y[1] - share.rho[1]});
        triples.push_back({share.x[0], share.y[1], share.rho[0]});
    }

    int new_batch_size = batch_size * 2;

    PRNG prng, prng_left;
    prng.SetSeed(seed);
    prng_left.SetSeed(seed_left);

    int128 Z = 0;
    int128 *X, *Y;
    X = new int128[new_batch_size + KAPPA + k];
    Y = new int128[new_batch_size + KAPPA + k];
    memset(X, 0, sizeof(X));
    memset(Y, 0, sizeof(Y));

    // int128 **share_right = new int128*[KAPPA];


    bool *choices = new bool[new_batch_size];
    for (int _ = 0; _ < KAPPA; _ ++) {
        // share_right[i] = new int128[KAPPA];
        for (int i = 0; i < new_batch_size; i ++) {
            choices[i] = prng.get_bit();
        }

        int128 e = 0;
        for (int i = 0; i < new_batch_size; i ++) {
            if (choices[i])  {
                e += (triples[i][2] - triples[i][0] * triples[i][1]);
            }
        }

        e >>= 64;
        
        for (int i = 0; i < new_batch_size; i ++) {
            if (choices[i]) {
                X[i] += triples[i][0];
                Y[i] += triples[i][1];

                Z += triples[i][2];
            }
        }

        for (int i = 0; i < KAPPA; i ++) {
            bool share_left = prng_left.get_bit();
            share_right[_][i] = ((e >> i) & 1) ^ share_left
            X[new_batch_size + i] += (1 << (65 + i)) * share_left;
            Y[new_batch_size + i] += (1 << (65 + i)) * share_right[_][i];
            Z += (1 << (64 + i)) * share_left;
            Z += (1 << (64 + i)) * share_right[_][i];
        }
    }

    int s = new_batch_size + KAPPA;
    int vector_length = (s - 1) / k + 1;
    array<int128, k> coeffsX, coeffsY;

    int128 **inner_products;
    inner_products = new int128*[k];

    for (int i = 0; i < k; i ++) {
        inner_products[i] = new int128[k];
    }
    
    // the verify_prng should not known by prover, this is just for debug.
    PRNG verify_prng;
    verify_prng.ReSeed(verify_seed);

    // int128 *newX, *newY;
    // newX = new int128[new_batch_size + KAPPA + k];
    // newY = new int128[new_batch_size + KAPPA + k];

    while (true) {

        if (vector_length == 1) {

        }
        
        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                inner_products[i][j] = inner_product(X + i * vector_length, Y + j * vector_length, vector_length);
            }
        }

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
        
        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }


}

void verify_left(
    RSShares* shares,
    octet* seed,
    octet* seed_left,
    octet* seed_verify,
    int m,
    int batch_size
) {

    vector<R> origin;
    for (int i = 0; i < batch_size; i ++) {
        origin.push_back(shares[i].x[1]);
        origin.push_back(shares[j].y[1]);
    }


}

void verify_right(
    RSShares* shares,
    octet* seed,
    int128** share_right,
    octet* seed_verify,
    int m,
    int batch_size
) {

}




int main() {

    return 0;
}
