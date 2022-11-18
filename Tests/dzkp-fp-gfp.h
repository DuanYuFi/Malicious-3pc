#ifndef PROTOCOLS_ARITHMETICCHECK_H_
#define PROTOCOLS_ARITHMETICCHECK_H_

#include <vector>

#include "../Tools/Hash.h"
#include "../Math/gfp.h"

using namespace std;

struct ArithDZKProof {
    vector<vector<gfp>> p_evals_masked;

    void print_out() {
        cout << "proof: ";
        for(auto row: p_evals_masked) {
            for(auto x: row) {
                cout << x << " ";
            }
        }
        cout << endl;
    }
};

struct ArithVerMsg {
    vector<gfp> b_ss;
    gfp final_input;
    gfp final_result_ss;

    ArithVerMsg() {}
    ArithVerMsg(vector<gfp> b_ss, gfp final_input, gfp final_result_ss) {
        this->b_ss = b_ss;
        this->final_input = final_input;
        this->final_result_ss = final_result_ss;
    }
};

class LocalHash {
    octetStream buffer;
public:

    template <typename T>
    void update(T data) {
        buffer.store(data);
    }

    gfp final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        gfp result;
        hash.final().get(result);
        return result;
    }

    void append_one_msg(gfp msg) {
        update(msg);
    }

    void append_msges(vector<gfp> msges) {
        for(gfp msg: msges) {
            update(msg);
        }
    }

    gfp get_challenge() {
        gfp r = final();
        return r;
    }
};


class Langrange {
public:
    static void get_bases(uint64_t n, gfp** result);
    static void evaluate_bases(uint64_t n, gfp r, gfp* result);
};

inline void Langrange::get_bases(uint64_t n, gfp** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j].assign_one();
            for(uint64_t l = 0; l < n; l++) {
                if (l != j) {
                    gfp denominator, numerator;
                    denominator = gfp(j) - gfp(l);
                    numerator = gfp(i + n - l);
                    result[i][j] = result[i][j] * denominator.invert() * numerator;
                }
            }
        }
    }
}

inline void Langrange::evaluate_bases(uint64_t n, gfp r, gfp* result) {
    for(uint64_t i = 0; i < n; i++) {
        result[i].assign_one();
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                gfp denominator, numerator; 
                denominator = gfp(i) - gfp(j);
                numerator = r - gfp(j);
                result[i] = result[i] * denominator.invert() * numerator;
            }
        }
    }
}

#endif