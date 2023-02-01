#include <vector>

#include "../Tools/Hash.h"
#include "../Math/gf2n.h"

using namespace std;

struct ArithDZKProof {
    vector<vector<gf2n_long>> p_evals_masked;

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
    vector<gf2n_long> b_ss;
    gf2n_long final_input;
    gf2n_long final_result_ss;

    ArithVerMsg() {}
    ArithVerMsg(vector<gf2n_long> b_ss, gf2n_long final_input, gf2n_long final_result_ss) {
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

    gf2n_long final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        gf2n_long result;
        hash.final().get(result);
        return result;
    }

    void append_one_msg(gf2n_long msg) {
        update(msg);
    }

    void append_msges(vector<gf2n_long> msges) {
        for(gf2n_long msg: msges) {
            update(msg);
        }
    }

    gf2n_long get_challenge() {
        gf2n_long r = final();
        return r;
    }
};


class Langrange {
public:
    static void get_bases(uint64_t n, gf2n_long** result);
    static void evaluate_bases(uint64_t n, gf2n_long r, gf2n_long* result);
};

inline void Langrange::get_bases(uint64_t n, gf2n_long** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j].assign_one();
            for(uint64_t l = 0; l < n; l++) {
                if (l != j) {
                    gf2n_long denominator, numerator;
                    denominator = gf2n_long(j) - gf2n_long(l);
                    numerator = gf2n_long(i + n - l);
                    result[i][j] = result[i][j] * denominator.invert() * numerator;
                }
            }
        }
    }
}

inline void Langrange::evaluate_bases(uint64_t n, gf2n_long r, gf2n_long* result) {
    for(uint64_t i = 0; i < n; i++) {
        result[i].assign_one();
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                gf2n_long denominator, numerator; 
                denominator = gf2n_long(i) - gf2n_long(j);
                numerator = r - gf2n_long(j);
                result[i] = result[i] * denominator.invert() * numerator;
            }
        }
    }
}