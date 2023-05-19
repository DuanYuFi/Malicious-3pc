#include "Math/mersenne.hpp"
#include "Math/Z2k.h"
#include "Tools/Hash.h"
#include <cstdlib>
#include <ctime>
#include <vector>
#include <chrono>

using namespace std;

typedef unsigned __int128 uint128_t;

// clock_t begin_time, finish_time;
class LocalHash {
    octetStream buffer;
public:
    template <typename T>
    void update(T data) {
        buffer.store(data);
    }

    uint64_t final() {
        Hash hash;
        hash.update(buffer);
        uint64_t result;
        hash.final().get(result);
        return result;
    }
};

struct DZKProof {
    vector<vector<uint64_t>> p_evals_masked;

    void pack(octetStream &os) {
        os.store(p_evals_masked.size());
        os.store(p_evals_masked[0].size());
        for (auto each: p_evals_masked) {
            for (uint64_t each_eval: each) {
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

// uint64_t get_rand() {
//     uint64_t left, right;
//     left = rand();
//     right = ((uint64_t)rand()) + (left<<32);
//     return right & Mersenne::PR;
// }

uint64_t** get_bases(uint64_t n) {
    uint64_t** result = new uint64_t*[n-1];
    for (uint64_t i = 0; i < n - 1; i++) {
        result[i] = new uint64_t[n];
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
    return result;
}

uint64_t* evaluate_bases(uint64_t n, uint64_t r) {
    uint64_t* result = new uint64_t[n];
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
    return result;
}

void append_one_msg(LocalHash &hash, uint64_t msg) {
    hash.update(msg);
}

void append_msges(LocalHash &hash, vector<uint64_t> msges) {
    for(uint64_t msg: msges) {
        hash.update(msg);
    }
}

uint64_t get_challenge(LocalHash &hash) {
    // octetStream buffer;
    // hash.final(buffer);

    uint64_t eta = hash.final();
    // return Mersenne::modp(eta);
    return eta & Mersenne::PR;
}

DZKProof prove(
    uint64_t** input_left, 
    uint64_t** input_right, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid,
    uint64_t** masks
) {
    // cout<<"in prove"<<endl;
    // cout<<"sid: "<< sid << endl;

    uint64_t T = batch_size;
    uint64_t s = (T - 1) / k + 1;

    LocalHash transcript_hash;

    append_one_msg(transcript_hash, sid);
    uint64_t eta = get_challenge(transcript_hash);
    // uint64_t eta = 1;
    // uint64_t eta = 200;
    // cout << "eta: " << eta << endl;
    assert(eta < Mersenne::PR);

    uint64_t eta_power = 1;
    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            input_left[i][2 * j] = Mersenne::mul(input_left[i][2 * j], eta_power);
            input_left[i][2 * j + 1] = Mersenne::mul(input_left[i][2 * j + 1], eta_power);
            eta_power = Mersenne::mul(eta_power, eta);
        }
    }

    s *= 2;
    vector<vector<uint64_t>> p_evals_masked;
    uint64_t** base = get_bases(k);
    uint64_t* eval_base;
    uint64_t s0;
    uint64_t** eval_result = new uint64_t*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = new uint64_t[k];
    }
    uint64_t* eval_p_poly = new uint64_t[2 * k - 1];
    // uint64_t r;
    uint128_t temp_result;
    uint64_t index;

    uint16_t cnt = 1;

    while(true){

        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }

        for(uint64_t i = 0; i < k; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(uint64_t i = 0; i < k - 1; i++) {
            eval_p_poly[i + k] = 0;
            for(uint64_t j = 0; j < k; j++) {
                for (uint64_t l = 0; l < k; l++) {
                    eval_p_poly[i+k] = Mersenne::add(eval_p_poly[i+k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
                }
            }
        }

        vector<uint64_t> ss(2 * k - 1);
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            // cout << "masks[" << cnt - 1 << "][" << i << "]: " << masks[cnt - 1][i] << endl;
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt - 1][i]);
        }

        uint64_t res = 0;
        for(uint64_t j = 0; j < k; j++) {
            res += eval_p_poly[j];
        }
        res = Mersenne::modp(res);

        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        append_msges(transcript_hash, ss);
        uint64_t r = get_challenge(transcript_hash);
        // uint64_t r = 200;
        assert(r < Mersenne::PR);

        // cout << "r: " << r << endl;
        eval_base = evaluate_bases(k, r);

        s0 = s;
        s = (s - 1) / k + 1;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_left[l][index]);
                    }
                    input_left[i][j] = Mersenne::modp_128(temp_result);

                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_right[l][index]);
                    }
                    input_right[i][j] = Mersenne::modp_128(temp_result);
                }
                else {
                    input_left[i][j] = 0;
                    input_right[i][j] = 0;
                }
            }
        }
        cnt++;
    }

    for(uint64_t i = 0; i < k; i++) {
        delete[] eval_result[i];
    }
    delete[] eval_result;
    delete[] eval_p_poly;
    
    DZKProof proof = { 
        p_evals_masked,
    };
    return proof;
}

struct VerMsg {
    vector<uint64_t> p_eval_ksum_ss;
    vector<uint64_t> p_eval_r_ss;
    uint64_t final_input;
    uint64_t final_result_ss;

    VerMsg() {}
    VerMsg(vector<uint64_t> p_eval_ksum_ss, vector<uint64_t> p_eval_r_ss, uint64_t final_input, uint64_t final_result_ss) {
        this->p_eval_ksum_ss = p_eval_ksum_ss;
        this->p_eval_r_ss = p_eval_r_ss;
        this->final_input = final_input;
        this->final_result_ss = final_result_ss;
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
) {
    // cout<<"in gen_vermsg"<<endl;
    // cout<<"sid: "<< sid << endl;

    // uint64_t L = var;
    uint64_t T = batch_size;
    // uint64_t s = T / k;
    uint64_t s = (T - 1) / k + 1;

    LocalHash transcript_hash;

    append_one_msg(transcript_hash, sid);
    uint64_t eta = get_challenge(transcript_hash);
    // uint64_t eta = 1;
    // uint64_t eta = 200;
    // cout << "eta: " << eta << endl;
    assert(eta < Mersenne::PR);

    // uint64_t eta = rands[0];

    uint64_t* eval_base;
    uint64_t r, s0, index, cnt = 1;
    uint128_t temp_result;

    uint64_t len = log(2 * T) / log(k) + 2;

    vector<uint64_t> p_eval_ksum_ss(len);
    vector<uint64_t> p_eval_r_ss(len);
    uint64_t final_input;
    uint64_t final_result_ss;

    if(false) {
        // Compute ETA
        // begin_time = clock();
        uint64_t** eta_power = new uint64_t*[k];
        for(uint64_t i = 0; i < k; i++) {
            eta_power[i] = new uint64_t[s];
            if (i == 0) {
                eta_power[i][0] = 1;
            }
            else {
                eta_power[i][0] = Mersenne::mul(eta_power[i - 1][s - 1], eta); 
            }
            for(uint64_t j = 1; j < s; j ++) {
                eta_power[i][j] = Mersenne::mul(eta_power[i][j - 1], eta);
            }
        }

        if ((party_ID + 1 - prover_ID) % 3 == 0) {
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {
                    input[i][2 * j] = Mersenne::mul(input[i][2 * j], eta_power[i][j]);
                    input[i][2 * j + 1] = Mersenne::mul(input[i][2 * j + 1], eta_power[i][j]);
                }
            }
        }

        p_eval_r_ss[0] = 0;
        for(uint64_t i = 0; i < k; i++) {
            p_eval_r_ss[0] += Mersenne::inner_product(eta_power[i], input_mono[i], s);
        }
        p_eval_r_ss[0] = Mersenne::modp(p_eval_r_ss[0]);
    }
    else {
        if ((party_ID + 1 - prover_ID) % 3 == 0) {
            temp_result = 0;
            uint64_t eta_temp = 1;
            int cnt_num = 0;
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {
                    if(input_mono[i][j] != 0) {
                        cnt_num++;
                    }
                    input[i][2 * j] = Mersenne::mul(input[i][2 * j], eta_temp);
                    input[i][2 * j + 1] = Mersenne::mul(input[i][2 * j + 1], eta_temp);
                    temp_result += Mersenne::mul(input_mono[i][j], eta_temp);
                    eta_temp = Mersenne::mul(eta_temp, eta);
                }
            }
            p_eval_r_ss[0] = Mersenne::modp_128(temp_result);
        }
        else {
            temp_result = 0;
            uint64_t eta_temp = 1;
            int cnt_num = 0;
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {
                    if(input_mono[i][j] != 0) {
                        cnt_num++;
                    }
                    temp_result += Mersenne::mul(input_mono[i][j], eta_temp);
                    eta_temp = Mersenne::mul(eta_temp, eta);
                }
            }
            p_eval_r_ss[0] = Mersenne::modp_128(temp_result);
            
        }
    }
    
    s *= 2;
    while(true)
    {
        
        append_msges(transcript_hash, proof.p_evals_masked[cnt - 1]);


        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt - 1][i] = Mersenne::add(proof.p_evals_masked[cnt - 1][i], masks_ss[cnt - 1][i]);
        } 
        uint64_t res = 0;
        for(uint64_t j = 0; j < k; j++) { // Assume k < 8
            res += proof.p_evals_masked[cnt - 1][j];
        }
        p_eval_ksum_ss[cnt - 1] = Mersenne::modp(res);
        if(s == 1) {
            r = get_challenge(transcript_hash);
            // r = 200;
            assert(r < Mersenne::PR);
            // r = 1;
            // cout << "r: " << r << endl;
            eval_base = evaluate_bases(k, r);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) input[i][0]);
            }

            final_input = Mersenne::modp_128(temp_result);
            eval_base = evaluate_bases(2 * k - 1, r);
            temp_result = 0;
            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) proof.p_evals_masked[cnt - 1][i]);
            }
            final_result_ss = Mersenne::modp_128(temp_result);
            break;
        }

        r = get_challenge(transcript_hash);
        // r = 200;
        assert(r < Mersenne::PR);
        // r = 1;
        // cout << "r: " << r << endl;
        eval_base = evaluate_bases(2 * k - 1, r);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) proof.p_evals_masked[cnt - 1][i]);
        }
        p_eval_r_ss[cnt] = Mersenne::modp_128(temp_result);

        eval_base = evaluate_bases(k, r);
        s0 = s;
        s = (s - 1) / k + 1;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input[l][index]);
                    }
                    input[i][j] = Mersenne::modp_128(temp_result);
                }
                else {
                    input[i][j] = 0;
                }
            }
        }
        
        cnt++;
    }

    VerMsg vermsg(
        p_eval_ksum_ss,
        p_eval_r_ss,
        final_input,
        final_result_ss
    );
    return vermsg;
}

bool verify(
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
) {
    // cout<<"in verify"<<endl;
    // cout<<"sid: "<< sid << endl;

    uint64_t T = batch_size;
    uint64_t len = log(2 * T) / log(k) + 2;
    
    VerMsg self_vermsg = gen_vermsg(proof, input, input_mono, batch_size, k, sid, masks_ss, prover_ID, party_ID);
    
    uint64_t p_eval_ksum, p_eval_r;

    for(uint64_t i = 0; i < len; i++) {
        p_eval_ksum = Mersenne::add(self_vermsg.p_eval_ksum_ss[i], other_vermsg.p_eval_ksum_ss[i]);
        p_eval_r = Mersenne::add(self_vermsg.p_eval_r_ss[i], other_vermsg.p_eval_r_ss[i]);
        
        if(p_eval_ksum != p_eval_r) {
            // cout << i << "-th sum check didn't pass" << endl;
            return false;
        }
    }
    uint64_t last_input_left;
    uint64_t last_input_right;
    if((party_ID + 1 - prover_ID) % 3 == 0) {
        last_input_left = self_vermsg.final_input;
        last_input_right = other_vermsg.final_input;
    }
    else {
        last_input_left = other_vermsg.final_input;
        last_input_right = self_vermsg.final_input;
    }
    uint64_t res = Mersenne::mul(last_input_left, last_input_right);
    p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    if(res != p_eval_r) {
        // cout << "last check didn't pass" << endl;
        return false;
    }
    
    return true;
}

uint64_t get_rand() {
    uint64_t x = 0;
    x = rand();
    x <<= 16;
    x |= rand();
    x <<= 16;
    x |= rand();
    x <<= 16;
    x |= rand();
    return x;
}

int main() {
    uint64_t T = 100000000; 
    uint64_t k = 8;

    int cnt = log(2 * T) / log(k) + 1;
    int cols = (T - 1) / k + 1;

    uint64_t **input_left, **input_right, **input_left_next, **input_right_prev, **input_mono_prev, **input_mono_next, **masks, **masks_prev, **masks_next;
    masks = new uint64_t*[cnt];
    masks_prev = new uint64_t*[cnt];
    masks_next = new uint64_t*[cnt];

    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2 * k - 1];
        masks_prev[i] = new uint64_t[2 * k - 1];
        masks_next[i] = new uint64_t[2 * k - 1];

        for (int j = 0; j < 2 * k - 1; j++) {
            masks_prev[i][j] = get_rand();
            masks_next[i][j] = get_rand();
            masks[i][j] = Mersenne::add(masks_prev[i][j], masks_next[i][j]);
        }
    }

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_left_next = new uint64_t*[k];
    input_right_prev = new uint64_t*[k];
    input_mono_prev = new uint64_t*[k];
    input_mono_next = new uint64_t*[k];

    int temp_pointer = 0;

    for (int i = 0; i < k; i++) {
        input_left[i] = new uint64_t[cols * 2];
        input_right[i] = new uint64_t[cols * 2];
        input_right_prev[i] = new uint64_t[cols * 2];
        input_left_next[i] = new uint64_t[cols * 2];
        input_mono_prev[i] = new uint64_t[cols];
        input_mono_next[i] = new uint64_t[cols];

        for (int j = 0; j < cols; j++) {
            if (temp_pointer >= T) {
                input_left[i][j * 2] = 0;
                input_left[i][j * 2 + 1] = 0;
                input_right[i][j * 2] = 0;
                input_right[i][j * 2 + 1] = 0;
                input_left_next[i][j * 2] = 0;
                input_left_next[i][j * 2 + 1] = 0;
                input_right_prev[i][j * 2] = 0;
                input_right_prev[i][j * 2 + 1] = 0;
                input_mono_prev[i][j] = 0;
                input_mono_next[i][j] = 0;
            } else {
                uint64_t x_first = get_rand();
                uint64_t x_second = get_rand();
                uint64_t y_first = get_rand();
                uint64_t y_second = get_rand();
                uint64_t rho_first = get_rand();
                uint64_t rho_second = get_rand();
                uint64_t z = Mersenne::sub(Mersenne::add(Mersenne::add(Mersenne::mul(x_first, Mersenne::add(y_first, y_second)), Mersenne::mul(x_second, y_first)), rho_first), rho_second);

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

                input_mono_prev[i][j] = Mersenne::sub(Mersenne::sub(z, Mersenne::mul(x_first, y_first)), rho_first);
                input_mono_next[i][j] = rho_second;

                uint64_t left = Mersenne::add(Mersenne::mul(input_left[i][j * 2], input_right[i][j * 2]), Mersenne::mul(input_left[i][j * 2 + 1], input_right[i][j * 2 + 1]));
                uint64_t right = Mersenne::add(input_mono_prev[i][j], input_mono_next[i][j]);
                // assert(left == right);

            }
            temp_pointer++;
            // cout << "chcekpoint 3" << endl;
        }
    }

    uint64_t sid = get_rand() && Mersenne::PR;

    auto start = std::chrono::high_resolution_clock::now();
    DZKProof proof = prove(input_left, input_right, T, k, sid, masks);
    auto end = std::chrono::high_resolution_clock::now();
    cout << "Proving time: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
    VerMsg other_vermsg = gen_vermsg(proof, input_left_next, input_mono_next, T, k, sid, masks_next, 0, 1);
    bool res = verify(proof, input_right_prev, input_mono_prev, other_vermsg, T, k, sid, masks_prev, 0, 2);
    end = std::chrono::high_resolution_clock::now();
    cout << "Verifying time: " << (end - start).count() / 1e6 << " ms" << endl;

    // cout << "res: " << res << endl;
    return 0;
} 