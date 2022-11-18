#include <vector>

#include "../Tools/Hash.h"
#include "../Math/mersenne.hpp"

using namespace std;
typedef unsigned __int128 uint128_t;



class LocalHash {
    octetStream buffer;
public:

    template <typename T>
    void update(T data) {
        buffer.store(data);
    }

    uint64_t final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        uint64_t result;
        hash.final().get(result);
        return result;
    }

    void append_one_msg(uint64_t msg) {
        update(msg);
    }

    void append_msges(vector<uint64_t> msges) {
        for(uint64_t msg: msges) {
            update(msg);
        }
    }

    uint64_t get_challenge() {
        uint64_t r = final();
        return r & Mersenne::PR;
    }
};


class Langrange {
public:
    static void get_bases(uint64_t n, uint64_t** result);
    static void evaluate_bases(uint64_t n, uint64_t r, uint64_t* result);
};

inline void Langrange::get_bases(uint64_t n, uint64_t** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j] = 1;
            for(uint64_t l = 0; l < n; l++) {
                if (l != j) {
                    uint64_t denominator, numerator;
                    if (j > l) {
                        denominator = j - l;
                    }
                    else {
                        denominator = Mersenne::neg(l - j);
                    }
                    numerator = i + n - l;
                    result[i][j] = Mersenne::mul(result[i][j], Mersenne::mul(Mersenne::inverse(denominator), numerator));
                }
            }
        }
    }
}

inline void Langrange::evaluate_bases(uint64_t n, uint64_t r, uint64_t* result) {
    for(uint64_t i = 0; i < n; i++) {
        result[i] = 1;
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                uint64_t denominator, numerator; 
                if (i > j) { 
                    denominator = i - j;
                } 
                else { 
                    denominator = Mersenne::neg(j - i);
                }
                if (r > j) { 
                    numerator = r - j; 
                } 
                else { 
                    numerator = Mersenne::neg(j - r);
                }
                result[i] = Mersenne::mul(result[i], Mersenne::mul(Mersenne::inverse(denominator), numerator));
            }
        }
    }
}


struct ArithDZKProof {
    vector<vector<uint64_t>> p_evals_masked;

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
    vector<uint64_t> b_ss;
    uint64_t final_input;
    uint64_t final_result_ss;

    ArithVerMsg() {}
    ArithVerMsg(vector<uint64_t> b_ss, uint64_t final_input, uint64_t final_result_ss) {
        this->b_ss = b_ss;
        this->final_input = final_input;
        this->final_result_ss = final_result_ss;
    }
};