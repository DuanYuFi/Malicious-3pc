#include "Math/gf2n.h"
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <cmath>


#include <vector>
#include "Tools/Hash.h"
#include "Math/gf2n.h"

using namespace std;

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

    size_t get_size() {
        return b_ss.size() + 2;
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


ArithDZKProof arith_prove(
    Field** input_left, 
    Field** input_right, 
    Field** masks,
    uint64_t batch_size, 
    uint64_t k, 
    Field sid
) {
    // cout << "in arith_prove..." << endl;

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    Field eta = transcript_hash.get_challenge();

    // cout << "checkpoint 1, s: " << s << "T: " << T << endl;

    // auto start = std::chrono::high_resolution_clock::now();

    Field eta_power = 1;
    // Linear combination using randomness eta
    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            input_left[i][2 * j] = input_left[i][2 * j] * eta_power;
            input_left[i][2 * j + 1] = input_left[i][2 * j + 1] * eta_power;
            eta_power = eta_power * eta;
        }
    }

    // auto end = std::chrono::high_resolution_clock::now();
    // cout << "Linear Combination Time: " << (end - start).count() / 1e6 << " ms" << endl;

    // start = std::chrono::high_resolution_clock::now();

    // cout << "checkpoint 1.2" << endl;

    // Vectors of masked evaluations of polynomial p(X)
    vector<vector<Field>> p_evals_masked;
    // Evaluations of polynomial p(X)
    Field* eval_p_poly = new Field[2 * k - 1];  

    Field** base = new Field*[k - 1];
    for (uint64_t i = 0; i < k - 1; i++) {
        base[i] = new Field[k];
    }
    // Langrange::get_bases(k, base);

    // cout << "checkpoint 1.5" << endl;
    
    Field* eval_base = new Field[k];
    Field** eval_result = new Field*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = (Field*)calloc(k, sizeof(Field));
    }

    size_t index = 0;
    uint64_t cnt = 0;
    s *= 2;
    uint64_t s0 = s;

    // cout << "checkpoint 2" << endl;

    while(true){
        // auto start = std::chrono::high_resolution_clock::now();

        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                for(uint64_t l = 0; l < s; l++) {
                    eval_result[i][j] += input_left[i][l] * input_right[j][l];
                }
            }
        }

        for(uint64_t i = 0; i < k; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(uint64_t i = 0; i < k - 1; i++) {
            eval_p_poly[i + k] = 0;
            for(uint64_t j = 0; j < k; j++) {
                for (uint64_t l = 0; l < k; l++) {
                    eval_p_poly[i + k] = eval_p_poly[i + k] + base[i][j] * eval_result[j][l] * base[i][l];
                }
            }
        }    

        vector<Field> ss(2 * k - 1);       
        for(uint64_t i = 0; i < 2 * k - 1; i++) {           
            ss[i] = eval_p_poly[i] - masks[cnt][i];
        }
        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        transcript_hash.append_msges(ss);
        Field r = transcript_hash.get_challenge();

        Langrange::evaluate_bases(k, r, eval_base);

        s0 = s;
        s = (s - 1) / k + 1;
       
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
               
                if (index < s0) {
                    Field temp_result;
                    temp_result.assign_zero();
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input_left[l][index];
                    }
                    input_left[i][j] = temp_result;

                    temp_result.assign_zero();
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input_right[l][index];
                    }
                    input_right[i][j] = temp_result;
                }
                else {
                    input_left[i][j].assign_zero();
                    input_right[i][j].assign_zero();
                }
            }
        }
        cnt++;
    }

    // end = std::chrono::high_resolution_clock::now();
    // cout << "Recursion Time: " << (end - start).count() / 1e6 << " ms" << endl;

    // cout << "checkpoint 3" << endl;

    for(uint64_t i = 0; i < k; i++) {
        delete[] eval_result[i];
    }
    delete[] eval_result;
    delete[] eval_p_poly;

    for (uint64_t i = 0; i < k - 1; i++) {
        delete[] base[i];
    }
    delete[] base;
    delete[] eval_base;

    for(uint64_t i = 0; i < k; i++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for (uint64_t j = 0; j < cnt; j ++) {
        delete[] masks[j];
    }
    delete[] masks;

    ArithDZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

ArithVerMsg arith_gen_vermsg(
    ArithDZKProof proof, 
    Field** input,
    Field** input_mono,
    Field** masks_ss,
    uint64_t batch_size, 
    uint64_t k, 
    Field sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
   
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(2 * T) / log(k) + 1;

    vector<Field> b_ss(len);
    Field final_input, final_result_ss;
    final_input.assign_zero(), final_result_ss.assign_zero();

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    Field eta = transcript_hash.get_challenge();
    Field eta_power = 1;
    uint64_t cnt = 0;

    Field out_ss, sum_ss;
    out_ss.assign_zero();
    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            out_ss += input_mono[i][j] * eta_power;
            eta_power = eta_power * eta;
        }
    }
    
    sum_ss.assign_zero();
    for(uint64_t j = 0; j < k; j++) { 
        sum_ss += proof.p_evals_masked[cnt][j];
    }
    b_ss[cnt] = sum_ss - out_ss;

    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;
    if(prev_party) {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = proof.p_evals_masked[cnt][i] + masks_ss[cnt][i];
        } 
    } else {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }
    
    Field* eval_base = new Field[k];
    Field* eval_base_2k = new Field[2 * k - 1];

    size_t index = 0;
    s *= 2;
    uint64_t s0 = s;
    Field r;

    while(true)
    {
        transcript_hash.append_msges(proof.p_evals_masked[cnt]);

        if(prev_party) {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = proof.p_evals_masked[cnt][i] + masks_ss[cnt][i];
            } 
        } else {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        sum_ss.assign_zero();
        for(uint64_t j = 0; j < k; j++) { 
            sum_ss += proof.p_evals_masked[cnt][j];
        }

        r = transcript_hash.get_challenge();
        Langrange::evaluate_bases(2 * k - 1, r, eval_base_2k);
        out_ss.assign_zero();
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            out_ss += eval_base_2k[i] * proof.p_evals_masked[cnt][i];
        }

        b_ss[cnt] = sum_ss - out_ss;

        if(s == 1) {
            r = transcript_hash.get_challenge();
            Langrange::evaluate_bases(k, r, eval_base);
            
            for(uint64_t i = 0; i < k; i++) {
                final_input += eval_base[i] * input[i][0];
            }
            Langrange::evaluate_bases(2 * k - 1, r, eval_base_2k);

            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                final_result_ss += eval_base_2k[i] * proof.p_evals_masked[cnt][i];
            }

            break;
        }

        Langrange::evaluate_bases(k, r, eval_base);
        s0 = s;
        s = (s - 1) / k + 1;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    Field temp_result;
                    temp_result.assign_zero();
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input[l][index];
                    }
                    input[i][j] = temp_result;
                }
                else {
                    input[i][j].assign_zero();
                }
            }
        }

        cnt++;
    }

    delete[] eval_base;
    delete[] eval_base_2k;

    for(uint64_t i = 0; i < k; i++) {
        delete[] input[i];
        delete[] input_mono[i];
    }

    delete[] input;
    delete[] input_mono;

    for (uint64_t j = 0; j < cnt; j ++) {
        delete[] masks_ss[j];
    }
    delete[] masks_ss;

    ArithVerMsg vermsg(
        b_ss,
        final_input,
        final_result_ss
    );
    return vermsg;
}

bool arith_verify(
    ArithDZKProof proof, 
    ArithVerMsg other_vermsg, 
    Field** input,
    Field** input_mono,
    Field** masks_ss,
    uint64_t batch_size, 
    uint64_t k, 
    Field sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    // cout << "in arith_verify..." << endl;
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t len = log(2 * T) / log(k) + 1;
    
    ArithVerMsg self_vermsg = arith_gen_vermsg(proof, input, input_mono, masks_ss, batch_size, k, sid, prover_ID, party_ID);

    Field b;

    for(uint64_t i = 0; i < len; i++) {
        b = self_vermsg.b_ss[i] + other_vermsg.b_ss[i];
        
        if(!b.is_zero()) {    
            // cout << "b != 0 at index " << i << endl; 
            return false;
        }
    }
    Field res = self_vermsg.final_input + other_vermsg.final_input;
    Field p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    
    if(res != p_eval_r) {   
        // cout << "res != p_eval_r" << endl;
        return false;
    } 

    // cout << "out of arith_verify..." << endl;
    return true;
}


int main() {

    Field::init_field(64);

    srand(time(0));
    SeededPRNG prng;
    auto seed = prng.get_seed();

    uint64_t T = 10000000; 
    uint64_t k = 8;

    int cnt = log(2 * T) / log(k) + 1;
    int cols = (T - 1) / k + 1;

    Field **input_left, **input_right, **input_left_next, **input_right_prev, **input_mono_prev, **input_mono_next, **masks, **masks_prev, **masks_next;
    masks = new Field*[cnt];
    masks_prev = new Field*[cnt];
    masks_next = new Field*[cnt];

    for (int i = 0; i < cnt; i++) {
        masks[i] = new Field[2 * k - 1];
        masks_prev[i] = new Field[2 * k - 1];
        masks_next[i] = new Field[2 * k - 1];

        for (int j = 0; j < 2 * k - 1; j++) {
            masks_prev[i][j].randomize(prng);
            masks_next[i][j].randomize(prng);
            masks[i][j] = masks_prev[i][j] + masks_next[i][j];
        }
    }

    input_left = new Field*[k];
    input_right = new Field*[k];
    input_left_next = new Field*[k];
    input_right_prev = new Field*[k];
    input_mono_prev = new Field*[k];
    input_mono_next = new Field*[k];

    int temp_pointer = 0; 

    for (int i = 0; i < k; i++) {
        input_left[i] = new Field[cols * 2];
        input_right[i] = new Field[cols * 2];
        input_right_prev[i] = new Field[cols * 2];
        input_left_next[i] = new Field[cols * 2];
        input_mono_prev[i] = new Field[cols];
        input_mono_next[i] = new Field[cols];

        for (int j = 0; j < cols; j++) {
            if (temp_pointer >= T) {
                input_left[i][j * 2].assign_zero();
                input_left[i][j * 2 + 1].assign_zero();
                input_right[i][j * 2].assign_zero();
                input_right[i][j * 2 + 1].assign_zero();
                input_left_next[i][j * 2].assign_zero();
                input_left_next[i][j * 2 + 1].assign_zero();
                input_right_prev[i][j * 2].assign_zero();
                input_right_prev[i][j * 2 + 1].assign_zero();
                input_mono_prev[i][j].assign_zero();
                input_mono_next[i][j].assign_zero();
            } else {
                Field x_first, x_second, y_first, y_second, rho_first, rho_second;
                x_first.randomize(prng);
                x_second.randomize(prng);
                y_first.randomize(prng);
                y_second.randomize(prng);
                rho_first.randomize(prng);
                rho_second.randomize(prng);
                Field z = x_first * (y_first + y_second) + x_second * y_first + rho_first - rho_second;

                // Share with P_{i+1}
                input_left[i][j * 2] = x_first;
                input_left[i][j * 2 + 1] = y_first;
                // Share with P_{i-1}
                input_right[i][j * 2] = y_second;
                input_right[i][j * 2 + 1] = x_second;

                input_left_next[i][j * 2] = x_first;
                input_left_next[i][j * 2 + 1] = y_first;

                input_right_prev[i][j * 2] = y_second;
                input_right_prev[i][j * 2 + 1] = x_second;

                input_mono_prev[i][j] = z - x_first * y_first - rho_first;
                input_mono_next[i][j] = rho_second;

                Field left = input_left[i][j * 2] * input_right[i][j * 2] + input_left[i][j * 2 + 1] * input_right[i][j * 2 + 1];
                Field right = input_mono_prev[i][j] +input_mono_next[i][j];
                assert(left == right);

            }
            temp_pointer++;
            // cout << "chcekpoint 3" << endl;
        }
    }

    Field sid;
    sid.randomize(prng);

    auto start = std::chrono::high_resolution_clock::now();
    ArithDZKProof proof = arith_prove(input_left, input_right, masks, T, k, sid);
    auto end = std::chrono::high_resolution_clock::now();
    cout << "Proving time: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
    ArithVerMsg other_vermsg = arith_gen_vermsg(proof, input_left_next, input_mono_next, masks_next, T, k, sid, 0, 1);
    bool res = arith_verify(proof, other_vermsg, input_right_prev, input_mono_prev, masks_prev, T, k, sid, 0, 2);
    end = std::chrono::high_resolution_clock::now();
    cout << "Verifying time: " << (end - start).count() / 1e6 << " ms" << endl;

    cout << "size: " << proof.get_size() + other_vermsg.get_size() << endl;
    cout << "sizeof(Field): " << sizeof(Field) << endl;
    cout << "commu: " << (proof.get_size() + other_vermsg.get_size()) * sizeof(Field)  << endl;
    return 0;
} 