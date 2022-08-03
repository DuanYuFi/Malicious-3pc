#ifndef PROTOCOLS_BINSRYCHECK_HPP_
#define PROTOCOLS_BINSRYCHECK_HPP_

#include "Math/mersenne.hpp"
#include "Math/Z2k.h"
#include "Tools/Hash.h"
#include <cstdlib>
#include <ctime>
#include <vector>

using namespace std;

typedef unsigned __int128 uint128_t;

// clock_t begin_time, finish_time;

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

uint64_t get_rand() {
    uint64_t left, right;
    left = rand();
    right = ((uint64_t)rand()) + (left<<32);
    return right & Mersenne::PR;
}

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

void append_one_msg(Hash &hash, uint64_t msg) {
    octetStream buffer;
    buffer.store(msg);
    hash.update(buffer);
}

void append_msges(Hash &hash, vector<uint64_t> msges) {
    octetStream buffer;
    for(uint64_t msg: msges) {
        buffer.store(msg);
    }
    hash.update(buffer);
}

uint64_t get_challenge(Hash &hash) {
    octetStream buffer;
    hash.final(buffer);
    // Z2<64> eta_2k;
    // eta_2k.unpack(buffer);
    // uint64_t eta = eta_2k.get_limb(0);
    uint64_t eta;
    buffer.get(eta);
    return eta;
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

    uint64_t T = batch_size;
    uint64_t s = (T - 1) / k + 1;

    // cout<<"T : "<<s<<endl;

    Hash transcript_hash;

    append_one_msg(transcript_hash, sid);
    uint64_t eta = get_challenge(transcript_hash);

    // return DZKProof();
    //Prepare Input
    // begin_time = clock();
    uint64_t eta_power = 1;
    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            input_left[i][2 * j] = Mersenne::mul(input_left[i][2 * j], eta_power);
            input_left[i][2 * j + 1] = Mersenne::mul(input_left[i][2 * j + 1], eta_power);
            eta_power = Mersenne::mul(eta_power, eta);
        }
    }
    // finish_time = clock();
    // cout<<"Prepare Input Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;

    s *= 2;
    vector<vector<uint64_t>> p_evals_masked;
    // vector<vector<uint64_t>> p_evals_masked2;
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
        // cout<<"s : "<<s<<endl;
        // cout<<"k : "<<k<<endl;

        //Compute P(X)
        // begin_time = clock();
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }

        // cout<<"checkpoint 1"<<endl;

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
        // cout<<"checkpoint 2"<<endl;

        // finish_time = clock();
        // cout<<"Interpolation Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;

        //generate proof
        // begin_time = clock();
        // vector<uint64_t> ss1(2 * k - 1), ss2(2 * k - 1);
        // uint64_t temp;
        // for(uint64_t i = 0; i < 2 * k - 1; i++) {
        //     ss1[i] = get_rand();
        //     if(eval_p_poly[i] > ss1[i]) {
        //         temp = eval_p_poly[i] - ss1[i];
        //     }
        //     else {
        //         temp = Mersenne::PR - ss1[i] + eval_p_poly[i];
        //     }
        //     ss2[i] = temp;
        // }
        // p_evals_masked1.push_back(ss1);
        // p_evals_masked2.push_back(ss2);
        // finish_time = clock();
        // cout<<"Generate DZKProof Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;

        vector<uint64_t> ss(2 * k - 1);
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt - 1][i]);
        }
        p_evals_masked.push_back(ss);
        append_msges(transcript_hash, ss);

        // cout<<"checkpoint 3"<<endl;

        if (s == 1) {
            // cout << "breaking.. cnt: " << cnt << endl;
            break;
        }

        // Prepare Next Input
        // begin_time = clock();
        // r = masks[cnt];
        uint64_t r = get_challenge(transcript_hash);
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
        // finish_time = clock();
        // cout<<"Prepare Input Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;

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
    // uint64_t var, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    cout<<"in gen_vermsg"<<endl;
    cout<<"masks_ss[0][0]"<<masks_ss[0][0]<<endl;

    // uint64_t L = var;
    uint64_t T = batch_size;
    // uint64_t s = T / k;
    uint64_t s = (T - 1) / k + 1;

    Hash transcript_hash;

    append_one_msg(transcript_hash, sid);
    uint64_t eta = get_challenge(transcript_hash);

    // uint64_t eta = rands[0];

    uint64_t* eval_base;
    uint64_t r, s0, index, cnt = 1;
    uint128_t temp_result;

    uint64_t len = log(2 * T) / log(k) + 2;

    vector<uint64_t> p_eval_ksum_ss(len);
    vector<uint64_t> p_eval_r_ss(len);
    uint64_t final_input;
    uint64_t final_result_ss;

    // if(false) {
    //     // Compute ETA
    //     // begin_time = clock();
    //     uint64_t** eta_power = new uint64_t*[k];
    //     for(uint64_t i = 0; i < k; i++) {
    //         eta_power [i] = new uint64_t[s];
    //         if (i == 0) {
    //             eta_power[i][0] = 1;
    //         }
    //         else {
    //             eta_power[i][0] = Mersenne::mul(eta_power[i - 1][s - 1], eta); 
    //         }
    //         for(uint64_t j = 1; j < s; j ++) {
    //             eta_power[i][j] = Mersenne::mul(eta_power[i][j - 1], eta);
    //         }
    //     }
    //     // finish_time = clock();
    //     // cout<<"Compute ETA Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;
        
    //     // Prepare Input
    //     if ((party_ID + 1 - prover_ID) % 3 == 0) {
    //         // begin_time = clock();
    //         for(uint64_t i = 0; i < k; i++) {
    //             for(uint64_t j = 0; j < s; j++) {
    //                 input[i][2 * j] = Mersenne::mul(input[i][2 * j], eta_power[i][j]);
    //                 input[i][2 * j + 1] = Mersenne::mul(input[i][2 * j + 1], eta_power[i][j]);
    //             }
    //         }
    //         // finish_time = clock();
    //         // cout<<"Prepare Input Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;
    //     }

    //     // begin_time = clock();
    //     p_eval_r_ss[0] = 0;
    //     for(uint64_t i = 0; i < k; i++) {
    //         p_eval_r_ss[0] += Mersenne::inner_product(eta_power[i], input_mono[i], s);
    //     }
    //     p_eval_r_ss[0] = Mersenne::modp(p_eval_r_ss[0]);
    //     // finish_time = clock();
    //     // cout<<"Compute Monomial Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;
    // }
    // else {
        // begin_time = clock();
        if ((party_ID + 1 - prover_ID) % 3 == 0) {
            temp_result = 0;
            uint64_t eta_temp = 1;
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {
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
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {
                    temp_result += Mersenne::mul(input_mono[i][j], eta_temp);
                    eta_temp = Mersenne::mul(eta_temp, eta);
                }
            }
            p_eval_r_ss[0] = Mersenne::modp_128(temp_result);
        }
        // finish_time = clock();
        // cout<<"Prepare Input + Compute Monomial Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;
    // }
    //  vector<uint64_t> proof.p_evals_masked[cnt - 1](2 * k - 1);
    
    s *= 2;
    while(true)
    {
        cout<<"s : "<<s<<endl;
        cout<<"k : "<<k<<endl;
        cout << "cnt:" << cnt << endl;
        
        cout << "proof.p_evals_masked.size(): " << proof.p_evals_masked.size() << endl;
        cout << "proof.p_evals_masked[cnt - 1].size(): " << proof.p_evals_masked[cnt - 1].size() << endl;

        append_msges(transcript_hash, proof.p_evals_masked[cnt - 1]);

        cout<<"checkpoint 1"<<endl;

        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt - 1][i] = Mersenne::add(proof.p_evals_masked[cnt - 1][i], masks_ss[cnt - 1][i]);
        } 
        cout<<"checkpoint 2"<<endl;

        // Compute share of sum of p's evaluations over [0, k - 1]
        uint64_t res = 0;
        for(uint64_t j = 0; j < k; j++) { // Assume k < 8
            res += proof.p_evals_masked[cnt - 1][j];
        }
        p_eval_ksum_ss[cnt - 1] = Mersenne::modp(res);
        cout<<"checkpoint 3"<<endl;

        // r = rands[cnt];
        r = get_challenge(transcript_hash);

        cout << "checkpoint 3.1" << endl;
        if(s == 1) {
            cout<<"in s== 1 loop..."<<endl;

            eval_base = evaluate_bases(k, r);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) input[i][0]);
            }
            cout<<"checkpoint 6"<<endl;

            final_input = Mersenne::modp_128(temp_result);
            eval_base = evaluate_bases(2 * k - 1, r);
            temp_result = 0;
            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) proof.p_evals_masked[cnt - 1][i]);
            }
            final_result_ss = Mersenne::modp_128(temp_result);
            // delete[] proof.p_evals_masked[cnt - 1];
            cout<<"breaking..."<<endl;
            break;
        }

        // Compute share of p's evaluation at r
        eval_base = evaluate_bases(2 * k - 1, r);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) proof.p_evals_masked[cnt - 1][i]);
        }
        cout<<"p_eval_r_ss.size(): " << p_eval_r_ss.size() << endl;
        p_eval_r_ss[cnt] = Mersenne::modp_128(temp_result);
        cout<<"checkpoint 4"<<endl;

        // Compute New Input
        // begin_time = clock();
        eval_base = evaluate_bases(k, r);
        s0 = s;
        s = (s - 1) / k + 1;
        cout << "checkpoint 4.1" << endl;
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
        cout<<"checkpoint 5"<<endl;

        // finish_time = clock();
        // cout<<"Prepare Input Time = "<<double(finish_time-begin_time)/CLOCKS_PER_SEC * 1000<<"ms"<<endl;

        cnt++;
    }

    // delete[] proof.p_evals_masked[cnt - 1];
    cout<<"constructing vermsg"<<endl;

    VerMsg vermsg(
        p_eval_ksum_ss,
        p_eval_r_ss,
        final_input,
        final_result_ss
    );
    cout<<"returning..."<<endl;
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
    cout<<"in verify"<<endl;

    // uint64_t L = var;
    uint64_t T = batch_size;
    // uint64_t s = T / k;
    uint64_t len = log(2 * T) / log(k) + 2;
    
    // VerMsg self_vermsg = gen_vermsg(p_eval_ss, input, input_mono, var, batch_size, k, sid, rands, prover_ID, party_ID);
    VerMsg self_vermsg = gen_vermsg(proof, input, input_mono, batch_size, k, sid, masks_ss, prover_ID, party_ID);
    // cout << "size of p_eval_ksum_ss: " << self_vermsg.p_eval_ksum_ss.size() << endl;
    // cout << "size of p_eval_r_ss: " << self_vermsg.p_eval_r_ss.size() << endl;

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

#endif

