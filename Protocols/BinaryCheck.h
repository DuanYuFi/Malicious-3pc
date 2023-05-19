#ifndef PROTOCOLS_BINARYCHECK_H_
#define PROTOCOLS_BINARYCHECK_H_

#include <vector>
#include "Tools/Hash.h"
#include "Math/gf2n.h"

using namespace std;

#define BLOCK_SIZE 64

typedef unsigned __int128 uint128_t;
typedef gf2n_short Field;

class LocalHash {
    octetStream buffer;
public:

    template <typename T>
    void update(T data) {
        buffer.store(data);
    }

    Field final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        Field result;
        hash.final().get(result);
        return result;
    }

    void append_one_msg(Field msg) {
        update(msg);
    }

    void append_msges(vector<Field> msges) {
        for(Field msg: msges) {
            update(msg);
        }
    }

    Field get_challenge() {
        Field r = final();
        return r;
    }
};

struct DZKProof {
    vector<vector<Field>> p_evals_masked;

    void print_out() {
        cout << "proof: ";
        for(auto row: p_evals_masked) {
            for(auto x: row) {
                cout << x << " ";
            }
        }
        cout << endl;
    }

    size_t get_size() {
        size_t size = 0;
        for (auto& v : p_evals_masked) {
            size += v.size();
        }
        return size;
    }

    Field get_hash() {
        LocalHash hash;
        for (auto p_eval : p_evals_masked) {
            for (auto each : p_eval) {
                hash.update(each);
            }
        }
        return hash.final();
    }

    void pack(octetStream &os) {
        os.store(p_evals_masked.size());
        for (auto each: p_evals_masked) {
            os.store(each.size());
            for (auto each_eval: each) {
                os.store(each_eval);
            }
        }
    }

    void unpack(octetStream &os) {
        size_t num_p_evals_masked = 0;
        size_t num_p_evals_masked_each = 0;

        os.get(num_p_evals_masked);
        p_evals_masked.resize(num_p_evals_masked);
        for (size_t i = 0; i < num_p_evals_masked; i++) {
            os.get(num_p_evals_masked_each);
            p_evals_masked[i].resize(num_p_evals_masked_each);
            for (size_t j = 0; j < num_p_evals_masked_each; j++) {
                os.get(p_evals_masked[i][j]);
            }
        }
    }
};

struct VerMsg {
    vector<Field> b_ss;
    Field final_input;
    Field final_result_ss;

    VerMsg() {}
    VerMsg(vector<Field> b_ss, Field final_input, Field final_result_ss) {
        this->b_ss = b_ss;
        this->final_input = final_input;
        this->final_result_ss = final_result_ss;
    }

    Field get_hash() {
        LocalHash hash;
        for (Field each: b_ss) {
            hash.update(each);
        }
        hash.update(final_input);
        hash.update(final_result_ss);
        return hash.final();
    }

    void pack(octetStream &os) {
        os.store(b_ss.size());
        for(size_t i = 0; i < b_ss.size(); i++) {
            os.store(b_ss[i]);
        }
        os.store(final_input);
        os.store(final_result_ss);
    }

    void unpack(octetStream &os) {
        size_t size = 0;
        os.get(size);
        b_ss.resize(size);
        for(size_t i = 0; i < size; i++) {
            os.get(b_ss[i]);
        }
        os.get(final_input);
        os.get(final_result_ss);
    }
};

class Langrange {
public:
    static void get_bases(size_t n, Field** result);
    static void evaluate_bases(size_t n, Field r, Field* result);
};

inline void Langrange::get_bases(size_t n, Field** result) {
    for (size_t i = 0; i < n - 1; i++) {
        for(size_t j = 0; j < n; j++) {
            result[i][j] = 1;
            for(size_t l = 0; l < n; l++) {
                if (l != j) {
                    Field denominator, numerator;
                    denominator = Field(j) - Field(l);
                    numerator = Field(i + n - l);
                    result[i][j] = result[i][j] * denominator.invert() * numerator;
                }
            }
        }
    }
}

inline void Langrange::evaluate_bases(size_t n, Field r, Field* result) {
    for(size_t i = 0; i < n; i++) {
        result[i] = 1;
        for(size_t j = 0; j < n; j++) {
            if (j != i) {
                Field denominator, numerator; 
                denominator = Field(i) - Field(j);
                numerator = r - Field(j);
                result[i] = result[i] * denominator.invert() * numerator;
            }
        }
    }
}

#endif