#ifndef PROTOCOLS_BINARYCHECK_H_
#define PROTOCOLS_BINARYCHECK_H_

#include <vector>
#include "Tools/Hash.h"

using namespace std;

typedef unsigned __int128 uint128_t;
typedef gf2n_long Field;

// clock_t begin_time, finish_time;
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

struct ArithDZKProof {
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
        os.store(p_evals_masked[0].size());
        for (auto each: p_evals_masked) {
            for (auto each_eval: each) {
                os.store(each_eval);
            }
        }
    }

    void unpack(octetStream &os) {
        size_t num_p_evals_masked = 0;
        size_t num_p_evals_masked_each = 0;

        os.get(num_p_evals_masked);
        os.get(num_p_evals_masked_each);
        p_evals_masked.resize(num_p_evals_masked);
        for (size_t i = 0; i < num_p_evals_masked; i++) {
            p_evals_masked[i].resize(num_p_evals_masked_each);
            for (size_t j = 0; j < num_p_evals_masked_each; j++) {
                os.get(p_evals_masked[i][j]);
            }
        }
    }
};

struct ArithVerMsg {
    vector<Field> b_ss;
    Field final_input;
    Field final_result_ss;

    ArithVerMsg() {}
    ArithVerMsg(vector<Field> b_ss, Field final_input, Field final_result_ss) {
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
        for(uint64_t i = 0; i < b_ss.size(); i++) {
            os.store(b_ss[i]);
        }
        os.store(final_input);
        os.store(final_result_ss);
    }

    void unpack(octetStream &os) {
        uint64_t size = 0;
        os.get(size);
        b_ss.resize(size);
        for(uint64_t i = 0; i < size; i++) {
            os.get(b_ss[i]);
        }
        os.get(final_input);
        os.get(final_result_ss);
    }
};

class Langrange {
public:
    static void get_bases(uint64_t n, Field** result);
    static void evaluate_bases(uint64_t n, Field r, Field* result);
};

inline void Langrange::get_bases(uint64_t n, Field** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j].assign_one();
            for(uint64_t l = 0; l < n; l++) {
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

inline void Langrange::evaluate_bases(uint64_t n, Field r, Field* result) {
    for(uint64_t i = 0; i < n; i++) {
        result[i].assign_one();
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                Field denominator, numerator; 
                denominator = Field(i) - Field(j);
                numerator = r - Field(j);
                result[i] = result[i] * denominator.invert() * numerator;
            }
        }
    }
}

/*
struct DZKProof {
    vector<vector<Field>> p_evals_masked;

    DZKProof() {}
    DZKProof(vector<vector<Field>> _x): p_evals_masked(_x) {}

    size_t get_size() {
        size_t size = 0;
        for (auto& v : p_evals_masked) {
            size += v.size();
        }
        return size;
    }

    uint64_t get_hash() {
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
        os.store(p_evals_masked[0].size());
        for (auto each: p_evals_masked) {
            for (auto each_eval: each) {
                os.store(each_eval);
            }
        }
    }

    void unpack(octetStream &os) {
        size_t num_p_evals_masked = 0;
        size_t num_p_evals_masked_each = 0;

        os.get(num_p_evals_masked);
        os.get(num_p_evals_masked_each);
        p_evals_masked.resize(num_p_evals_masked);
        for (size_t i = 0; i < num_p_evals_masked; i++) {
            p_evals_masked[i].resize(num_p_evals_masked_each);
            for (size_t j = 0; j < num_p_evals_masked_each; j++) {
                os.get(p_evals_masked[i][j]);
            }
        }
    }

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

struct VerMsg {
    vector<Field> p_eval_ksum_ss;
    vector<Field> p_eval_r_ss;
    Field final_input;
    Field final_result_ss;

    VerMsg() {}
    VerMsg(vector<Field> p_eval_ksum_ss, vector<Field> p_eval_r_ss, Field final_input, Field final_result_ss) {
        this->p_eval_ksum_ss = p_eval_ksum_ss;
        this->p_eval_r_ss = p_eval_r_ss;
        this->final_input = final_input;
        this->final_result_ss = final_result_ss;
    }

    size_t get_size() {
        return p_eval_ksum_ss.size() + p_eval_r_ss.size() + 2;
    }

    uint64_t get_hash() {
        LocalHash hash;
        for (Field each: p_eval_ksum_ss) {
            hash.update(each);
        }
        for (Field each: p_eval_r_ss) {
            hash.update(each);
        }
        hash.update(final_input);
        hash.update(final_result_ss);
        return hash.final();
    }

    void pack(octetStream &os) {
        os.store(p_eval_ksum_ss.size());
        for(uint64_t i = 0; i < p_eval_ksum_ss.size(); i++) {
            os.store(p_eval_ksum_ss[i]);
        }
        os.store(p_eval_r_ss.size());
        for(uint64_t i = 0; i < p_eval_r_ss.size(); i++) {
            os.store(p_eval_r_ss[i]);
        }
        os.store(final_input);
        os.store(final_result_ss);
    }

    void unpack(octetStream &os) {
        uint64_t size = 0;
        os.get(size);
        p_eval_ksum_ss.resize(size);
        for(uint64_t i = 0; i < size; i++) {
            os.get(p_eval_ksum_ss[i]);
        }
        os.get(size);
        p_eval_r_ss.resize(size);
        for(uint64_t i = 0; i < size; i++) {
            os.get(p_eval_r_ss[i]);
        }
        os.get(final_input);
        os.get(final_result_ss);
    }
};

uint64_t get_rand();
uint64_t** get_bases(uint64_t n);
uint64_t* evaluate_bases(uint64_t n, uint64_t r);

void append_one_msg(LocalHash &hash, uint64_t msg);
void append_msges(LocalHash &hash, vector<uint64_t> msges);
uint64_t get_challenge(LocalHash &hash);

DZKProof prove(
    uint64_t** input_left, 
    uint64_t** input_right, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid,
    uint64_t** masks
);

VerMsg gen_vermsg(
    DZKProof proof, 
    uint64_t** input,
    uint64_t** input_mono, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
);

bool _verify(
    DZKProof proof, 
    uint64_t** input,
    uint64_t** input_mono, 
    VerMsg other_vermsg, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
);
*/

#endif