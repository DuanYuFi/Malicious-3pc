#ifndef PROTOCOLS_BINSRYCHECK_HPP_
#define PROTOCOLS_BINSRYCHECK_HPP_

#include "BinaryCheck.h"

#include "Math/mersenne.hpp"
#include "Math/Z2k.h"
#include <cstdlib>
#include <ctime>


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
   // cout << "in prove" << endl;
    //// cout<<"sid: "<< sid << endl;

    uint64_t T = batch_size;
    uint64_t s = (T - 1) / k + 1;
    // uint64_t s = T / k;

    // for(uint64_t i = 0; i < k; i++) {
    //     for(uint64_t j = 0; j < s; j++) {
    //        // cout << "input_left[" << i << "][" << 2 * j << "]: " << input_left[i][2 * j] << endl;
    //        // cout << "input_left[" << i << "][" << 2 * j + 1 << "]: " << input_left[i][2 * j + 1] << endl;
    //        // cout << "input_right[" << i << "][" << 2 * j << "]: " << input_right[i][2 * j] << endl;
    //        // cout << "input_right[" << i << "][" << 2 * j + 1 << "]: " << input_right[i][2 * j + 1] << endl;
    //     }
    // }


    LocalHash transcript_hash;

    append_one_msg(transcript_hash, sid);
    uint64_t eta = get_challenge(transcript_hash);
    // uint64_t eta = 1;
    // uint64_t eta = 200;
    //// cout << "eta: " << eta << endl;
    // assert(eta < Mersenne::PR);

   // cout << "prove: checkpoint 1" << endl;

    uint64_t eta_power = 1;
    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            input_left[i][2 * j] = Mersenne::mul(input_left[i][2 * j], eta_power);
            input_left[i][2 * j + 1] = Mersenne::mul(input_left[i][2 * j + 1], eta_power);
            eta_power = Mersenne::mul(eta_power, eta);
        }
    }

   // cout << "prove: checkpoint 2" << endl;

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
   // cout << "prove: checkpoint 3" << endl;

    while(true){

        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }

       // cout << "prove: checkpoint 4" << endl;


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
       // cout << "prove: checkpoint 5" << endl;

        // for(uint64_t i = 0; i < 2 * k - 1; i++) {
        //    // cout << "eval_p_poly[" << i << "]: " << eval_p_poly[i] << endl;
        // }

        vector<uint64_t> ss(2 * k - 1);
       // cout << "cnt: " << cnt << endl;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            //// cout << "masks[" << cnt - 1 << "][" << i << "]: " << masks[cnt - 1][i] << endl;
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt - 1][i]);
        }

       // cout << "prove: checkpoint 6" << endl;

        // uint64_t res = 0;
        // for(uint64_t j = 0; j < k; j++) {
        //     res += eval_p_poly[j];
        // }
        // res = Mersenne::modp(res);

        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        append_msges(transcript_hash, ss);
        uint64_t r = get_challenge(transcript_hash);
        // uint64_t r = 200;
        // assert(r < Mersenne::PR);

        //// cout << "r: " << r << endl;
        eval_base = evaluate_bases(k, r);
       // cout << "prove: checkpoint 7" << endl;

        s0 = s;
        s = (s - 1) / k + 1;
       // cout << "s0: " << s0 << ", s: " << s << endl;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
               // cout << "index: " << index << endl;
                if (index < s0) {
                    //// cout << "index < s0, index: " << index << ", s0: " << s0 << endl;
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_left[l][index]);
                    }
                   // cout << "prove: checkpoint 7.1" << endl;

                    input_left[i][j] = Mersenne::modp_128(temp_result);
                   // cout << "prove: checkpoint 7.2" << endl;


                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_right[l][index]);
                    }
                   // cout << "prove: checkpoint 7.3" << endl;

                    input_right[i][j] = Mersenne::modp_128(temp_result);
                   // cout << "prove: checkpoint 7.4" << endl;
                }
                else {
                    input_left[i][j] = 0;
                   // cout << "prove: checkpoint 7.5" << endl;
                    input_right[i][j] = 0;
                }
               // cout << "prove: checkpoint 7.6" << endl;

            }
        }
        cnt++;
    }

   // cout << "prove: checkpoint 8" << endl;

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
   // cout << "in gen_vermsg" << endl;
    //// cout<<"sid: "<< sid << endl;
    //// cout << "party_ID: " << party_ID << endl;
    //// cout << "prover_ID: " << prover_ID << endl;

    // uint64_t L = var;
    uint64_t T = batch_size;
    // uint64_t s = T / k;
    uint64_t s = (T - 1) / k + 1;

    // for(uint64_t i = 0; i < k; i++) {
    //     for(uint64_t j = 0; j < s; j++) {
    //        // cout << "input[" << i << "][" << 2 * j << "]: " << input[i][2 * j] << endl;
    //        // cout << "input[" << i << "][" << 2 * j + 1 << "]: " << input[i][2 * j + 1] << endl;

    //        // cout << "input_mono[" << i << "][" << j << "]: " << input_mono[i][j] << endl;
    //     }
    // }

    LocalHash transcript_hash;

    append_one_msg(transcript_hash, sid);
    uint64_t eta = get_challenge(transcript_hash);
    // uint64_t eta = 1;
    // uint64_t eta = 200;
    //// cout << "eta: " << eta << endl;
    // assert(eta < Mersenne::PR);

    // uint64_t eta = rands[0];
   // cout << "in gen_vermsg: checkpoint 1" << endl;


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
    //         eta_power[i] = new uint64_t[s];
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

    //     if ((party_ID + 1 - prover_ID) % 3 == 0) {
    //         for(uint64_t i = 0; i < k; i++) {
    //             for(uint64_t j = 0; j < s; j++) {
    //                 input[i][2 * j] = Mersenne::mul(input[i][2 * j], eta_power[i][j]);
    //                 input[i][2 * j + 1] = Mersenne::mul(input[i][2 * j + 1], eta_power[i][j]);
    //             }
    //         }
    //     }

    //     p_eval_r_ss[0] = 0;
    //     for(uint64_t i = 0; i < k; i++) {
    //         p_eval_r_ss[0] += Mersenne::inner_product(eta_power[i], input_mono[i], s);
    //     }
    //     p_eval_r_ss[0] = Mersenne::modp(p_eval_r_ss[0]);
    // }
    // else {
        if (((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
            int cnt_non_zeros = 0;
            temp_result = 0;
            uint64_t eta_temp = 1;
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {

                    //// cout << "input_mono[" << i << "][" << j << "]: " << input_mono[i][j] << endl;
                    if (input_mono[i][j] != 0) {
                        cnt_non_zeros++;
                    }

                    input[i][2 * j] = Mersenne::mul(input[i][2 * j], eta_temp);
                    input[i][2 * j + 1] = Mersenne::mul(input[i][2 * j + 1], eta_temp);
                    temp_result += Mersenne::mul(input_mono[i][j], eta_temp);
                    eta_temp = Mersenne::mul(eta_temp, eta);
                }
            }
            p_eval_r_ss[0] = Mersenne::modp_128(temp_result);
            //// cout << "cnt_non_zeros: " << cnt_non_zeros << endl;
        }
        else {
            temp_result = 0;
            uint64_t eta_temp = 1;
            int cnt_non_zeros = 0;
            for(uint64_t i = 0; i < k; i++) {
                for(uint64_t j = 0; j < s; j++) {

                    //// cout << "input_mono[" << i << "][" << j << "]: " << input_mono[i][j] << endl;
                    if(input_mono[i][j] != 0) {
                        cnt_non_zeros++;
                    }
                    
                    temp_result += Mersenne::mul(input_mono[i][j], eta_temp);
                    eta_temp = Mersenne::mul(eta_temp, eta);
                }
            }
            p_eval_r_ss[0] = Mersenne::modp_128(temp_result);
            //// cout << "cnt_non_zeros: " << cnt_non_zeros << endl;
        }
    // }

   // cout << "in gen_vermsg: checkpoint 2" << endl;

    s *= 2;
    while(true)
    {
        
        append_msges(transcript_hash, proof.p_evals_masked[cnt - 1]);

        if(((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
            //// cout << "(party_ID + 1 - prover_ID) % 3 == 0" << endl;
            //// cout << "party_ID: " << party_ID << endl;
            //// cout << "prover_ID: " << prover_ID << endl;
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt - 1][i] = Mersenne::add(proof.p_evals_masked[cnt - 1][i], masks_ss[cnt - 1][i]);
               // cout << "masks_ss[cnt - 1][i]: " << masks_ss[cnt - 1][i] << endl;
            } 
        } else {
            //// cout << "(party_ID + 1 - prover_ID) % 3 != 0" << endl;
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt - 1][i] = masks_ss[cnt - 1][i];
            }
        }
        
       // cout << "in gen_vermsg: checkpoint 3" << endl;

        uint64_t res = 0;
        for(uint64_t j = 0; j < k; j++) { 
            res += proof.p_evals_masked[cnt - 1][j];
        }
        p_eval_ksum_ss[cnt - 1] = Mersenne::modp(res);

       // cout << "in gen_vermsg: checkpoint 4" << endl;

        if(s == 1) {
            r = get_challenge(transcript_hash);
            // r = 200;
            assert(r < Mersenne::PR);
            // r = 1;
            //// cout << "r: " << r << endl;
            eval_base = evaluate_bases(k, r);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) input[i][0]);
            }
            final_input = Mersenne::modp_128(temp_result);

           // cout << "in gen_vermsg: checkpoint 5" << endl;

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
        //// cout << "r: " << r << endl;
        eval_base = evaluate_bases(2 * k - 1, r);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) proof.p_evals_masked[cnt - 1][i]);
        }
        p_eval_r_ss[cnt] = Mersenne::modp_128(temp_result);

       // cout << "in gen_vermsg: checkpoint 6" << endl;

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

       // cout << "in gen_vermsg: checkpoint 7" << endl;
        
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
   // cout << "in verify" << endl;
    //// cout<<"sid: "<< sid << endl;
    //// cout << "party_ID: " << party_ID << endl;
    //// cout << "prover_ID: " << prover_ID << endl;

    uint64_t T = batch_size;
    uint64_t len = log(2 * T) / log(k) + 2;
    
   // cout << "verify: checkpoint 1" << endl;

    VerMsg self_vermsg = gen_vermsg(proof, input, input_mono, batch_size, k, sid, masks_ss, prover_ID, party_ID);
    
    uint64_t p_eval_ksum, p_eval_r;

    for(uint64_t i = 0; i < len; i++) {
        p_eval_ksum = Mersenne::add(self_vermsg.p_eval_ksum_ss[i], other_vermsg.p_eval_ksum_ss[i]);
        p_eval_r = Mersenne::add(self_vermsg.p_eval_r_ss[i], other_vermsg.p_eval_r_ss[i]);
        //// cout << "self_vermsg.p_eval_r_ss: " << self_vermsg.p_eval_r_ss[i] << endl;
        //// cout << "other_vermsg.p_eval_r_ss: " << other_vermsg.p_eval_r_ss[i] << endl;
        //// cout << "self_vermsg.p_eval_ksum_ss[" << i << "]: " << self_vermsg.p_eval_ksum_ss[i] << endl;
        //// cout << "other_vermsg.p_eval_ksum_ss[" << i << "]: " << other_vermsg.p_eval_ksum_ss[i] << endl;

        //// cout << "p_eval_ksum: " << p_eval_ksum << endl;
        //// cout << "p_eval_r: " << p_eval_r << endl;
       // cout << "verify: checkpoint 2" << endl;

        if(p_eval_ksum != p_eval_r) {
           // cout << i << "-th sum check didn't pass" << endl;
            return false;
        }
    }
    // uint64_t last_input_left;
    // uint64_t last_input_right;
    // if(((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
    //     last_input_left = self_vermsg.final_input;
    //     last_input_right = other_vermsg.final_input;
    // }
    // else {
    //     last_input_left = other_vermsg.final_input;
    //     last_input_right = self_vermsg.final_input;
    // }
    //// cout << "last_input_left: " << last_input_left << endl;
    //// cout << "last_input_right: " << last_input_right << endl;
    //// cout << "self_vermsg.final_input: " << self_vermsg.final_input << endl;
    //// cout << "other_vermsg.final_input: " << other_vermsg.final_input << endl;
    //// cout << "self_vermsg.final_result_ss: " << self_vermsg.final_result_ss << endl;
    //// cout << "other_vermsg.final_result_ss: " << other_vermsg.final_result_ss << endl;

    // uint64_t res = Mersenne::mul(last_input_left, last_input_right);
    uint64_t res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
   // cout << "verify: checkpoint 3" << endl;

    //// cout << "res: " << res << endl;
    //// cout << "p_eval_r: " << p_eval_r << endl;
    if(res != p_eval_r) {
       // cout << "last check didn't pass" << endl;
        return false;
    }
   // cout << "verify: checkpoint 4" << endl;
    
    return true;
}

#endif

