#ifndef PROTOCOLS_BINSRYCHECK_HPP_
#define PROTOCOLS_BINSRYCHECK_HPP_

#include "BinaryCheck.h"
#include "Malicious3PCMC.h"

#include "Math/mersenne.hpp"
#include "Math/Z2k.h"
#include <cstdlib>
#include <ctime>

#define NEG_ONE (Mersenne::PR - 1)
#define NEG_TWO (Mersenne::PR - 2)
#define NEG_TWO_INVERSE Mersenne::neg(two_inverse)
#define input_x(i, j) input1[start + (i * cols + (j & 3))]
#define input_y(i, j) input2[start + (i * cols + (j & 3))]
#define input_z(i, j) results[start + (i * cols + (j & 3))]
#define input_rho(i, j) rhos[start + (i * cols + (j & 3))]
#define input_e(i, j) (input_z(i, j).first ^ (input_x(i, j).first & input_y(i, j).first) ^ input_rho(i, j).first)
#define input_t1(i, j) (input_e(i, j) ? NEG_ONE : 1)
#define input_t2(i, j) (input_rho(i, j).second ? NEG_ONE : 1)
#define input_e_2(i, j) (input_z(i, j).second ^ (input_x(i, j).second & input_y(i, j).second) ^ input_rho(i, j).second)
#define input_t1_2(i, j) (input_e_2(i, j) ? NEG_ONE : 1)
#define input_t2_2(i, j) (input_rho(i, j).first ? NEG_ONE : 1)

#define INPUT_LEFT(i, j) (j % 4 == 0 ? \
    (input_x(i, j).first & input_y(i, j).first ? (input_e(i, j) ? 2 : NEG_TWO) : 0) : \
    (j % 4 == 1 ? (input_y(i, j).first ? input_t1(i, j) : 0) : \
    (j % 4 == 2 ? (input_x(i, j).first ? input_t1(i, j) : 0) : \
    (input_e(i, j) ? two_inverse : NEG_TWO_INVERSE))))

#define INPUT_RIGHT(i, j) (j % 4 == 0 ? \
    (input_y(i, j).second & input_x(i, j).second ? input_t2(i, j) : 0) : \
    (j % 4 == 1 ? (input_x(i, j).second ? input_t2(i, j) : 0) : \
    (j % 4 == 2 ? (input_y(i, j).second ? input_t2(i, j) : 0) : \
    (input_t2(i, j)))))

#define INPUT_PREV(i, j) ( \
    j % 4 == 0 ? (input_y(i, j).first & input_x(i, j).first ? input_t2_2(i, j) : 0) : \
    (j % 4 == 1 ? (input_x(i, j).first ? input_t2_2(i, j) : 0) : \
    (j % 4 == 2 ? (input_y(i, j).first ? input_t2_2(i, j) : 0) : \
    (input_t2_2(i, j)))))

#define INPUT_NEXT(i, j) ( \
    j % 4 == 0 ? (input_x(i, j).second & input_y(i, j).second ? (input_e_2(i, j) ? 2 : NEG_TWO) : 0) : \
    (j % 4 == 1 ? (input_y(i, j).second ? input_t1_2(i, j) : 0) : \
    (j % 4 == 2 ? (input_x(i, j).second ? input_t1_2(i, j) : 0) : \
    (input_e_2(i, j) ? two_inverse : NEG_TWO_INVERSE))))

uint64_t get_rand() {
    uint64_t left, right;
    left = rand();
    right = ((uint64_t)rand()) + (left<<32);
    return right & Mersenne::PR;
}

void get_bases(uint64_t n, uint64_t** result) {
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

void evaluate_bases(uint64_t n, uint64_t r, uint64_t* result) {

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

void append_one_msg(LocalHash &hash, uint64_t msg) {
    hash.update(msg);
}

void append_msges(LocalHash &hash, vector<uint64_t> msges) {
    for(uint64_t msg: msges) {
        hash.update(msg);
    }
}

uint64_t get_challenge(LocalHash &hash) {
    
    

    uint64_t r = hash.final();
    return r & Mersenne::PR;
}

template <class _T>
DZKProof Malicious3PCProtocol<_T>::prove(
    int node_id,
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t** masks
) {

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    LocalHash transcript_hash;

    vector<vector<uint64_t>> p_evals_masked;

    uint64_t** base = new uint64_t*[k - 1];
    for (uint64_t i = 0; i < k - 1; i++) {
        base[i] = new uint64_t[k];
    }

    get_bases(k, base);

    uint64_t* eval_base = new uint64_t[k];
    uint64_t s0;
    uint64_t** eval_result = new uint64_t*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = (uint64_t*)calloc(k, sizeof(uint64_t));
    }
    uint64_t* eval_p_poly = new uint64_t[2 * k - 1];  
    uint128_t temp_result;
    uint64_t index;
    uint16_t cnt = 0;
    
    /*
                    ==================================================================================
                        From this comment to next comment (comment mark two), the codes between are 
                        the first round in the new optimize 
                        for reducing the time cost in prepare data for prove and gen_vermsg.
                    ==================================================================================
    */

    uint64_t **input_left, **input_right;
    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    size_t cols = s;
    
    size_t start = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size;
    uint64_t neg_two_inverse = NEG_TWO_INVERSE;
    uint64_t extra_addition = Mersenne::neg(s / 2);
    if (s % 2 == 1) {
        extra_addition = Mersenne::add(extra_addition, neg_two_inverse);   
    }

    for (int column = 0; column < (int) s; column ++) {
        
        // split the inner product into monomials' sum
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                
                if (i * s + column >= batch_size || j * s + column >= batch_size) {
                    eval_result[i][j] = Mersenne::add(eval_result[i][j], two_inverse);
                    continue;
                }
                
                if (i == j) {
                    // eval_result[i][j] = Mersenne::add(eval_result[i][j], two_inverse);
                    continue;
                }

                bool this_value = 0;

                this_value ^= (input1[start + column + i * s].first & input2[start + column + j * s].second);
                this_value ^= (input1[start + column + j * s].second & input2[start + column + i * s].first);

                this_value ^= (results[start + column + i * s].first ^ rhos[start + column + i * s].first);
                this_value ^= (input1[start + column + i * s].first & input2[start + column + i * s].first);
                
                this_value ^= rhos[start + column + j * s].second;

                eval_result[i][j] += this_value;
            }
        }
    }

    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < k; j++) {
            eval_result[i][j] = Mersenne::add(eval_result[i][j], extra_addition);
        }
    }
    
    s *= 4;

    for(uint64_t i = 0; i < k; i++) {
        eval_p_poly[i] = eval_result[i][i];
    }

    for(uint64_t i = 0; i < k - 1; i++) {
        eval_p_poly[i + k] = 0;
        for(uint64_t j = 0; j < k; j++) {
            for (uint64_t l = 0; l < k; l++) {
                eval_p_poly[i + k] = Mersenne::add(eval_p_poly[i + k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
            }
        }
    }  

    vector<uint64_t> ss(2 * k - 1);       
    for(uint64_t i = 0; i < 2 * k - 1; i++) {           
        ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
    }

    uint64_t sum = 0;
    for(uint64_t j = 0; j < k; j++) {
        sum += eval_p_poly[j];
    }
    sum = Mersenne::modp(sum);

    p_evals_masked.push_back(ss);
    
    append_msges(transcript_hash, ss);
    uint64_t r = get_challenge(transcript_hash);

    evaluate_bases(k, r, eval_base);

    s0 = s;
    s = (s - 1) / k + 1;
    
    for(uint64_t i = 0; i < k; i++) {

        input_left[i] = new uint64_t[s];
        input_right[i] = new uint64_t[s];

        for(uint64_t j = 0; j < s; j++) {
            index = i * s + j;
            
            if (index < s0) {
                
                temp_result = 0;
                for(uint64_t l = 0; l < k; l++) {
                    temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) INPUT_LEFT(l, index));
                }

                input_left[i][j] = Mersenne::modp_128(temp_result);
                temp_result = 0;
                for(uint64_t l = 0; l < k; l++) {
                    temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) INPUT_RIGHT(l, index));
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

    /*
                                            =========================
                                                comment mark two.
                                            =========================
    */
    
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
                    eval_p_poly[i + k] = Mersenne::add(eval_p_poly[i + k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
                }
            }
        }    

        vector<uint64_t> ss(2 * k - 1);       
        for(uint64_t i = 0; i < 2 * k - 1; i++) {           
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
        }

        uint64_t sum = 0;
        for(uint64_t j = 0; j < k; j++) {
            sum += eval_p_poly[j];
        }
        sum = Mersenne::modp(sum);

        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        append_msges(transcript_hash, ss);
        uint64_t r = get_challenge(transcript_hash);

        evaluate_bases(k, r, eval_base);

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

    DZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

template <class _T>
VerMsg Malicious3PCProtocol<_T>::gen_vermsg(
    DZKProof proof, 
    int node_id,
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID,
    bool is_verify
) {
   
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    LocalHash transcript_hash;

    uint64_t* eval_base = new uint64_t[k];
    uint64_t* eval_base_2k = new uint64_t[2 * k - 1];
    uint64_t r, s0, index, cnt = 0;
    uint128_t temp_result;

    uint64_t len = log(4 * T) / log(k) + 1;

    vector<uint64_t> p_eval_ksum_ss(len);
    vector<uint64_t> p_eval_r_ss(len);
    uint64_t final_input;
    uint64_t final_result_ss;
    s *= 4;

    /*
                    ==================================================================================
                        From this comment to next comment (comment mark two), the codes between are 
                        the first round in the new optimize 
                        for reducing the time cost in prepare data for prove and gen_vermsg.
                    ==================================================================================
    */

    uint64_t **input;
    input = new uint64_t*[k];

    size_t start = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size;
    size_t cols = (T - 1) / k + 1;

    append_msges(transcript_hash, proof.p_evals_masked[cnt]);

    if(((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
            
        } 
    } else {
        
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }
    
    uint64_t res = 0;
    for(uint64_t j = 0; j < k; j++) { 
        res += proof.p_evals_masked[cnt][j];
    }
    p_eval_ksum_ss[cnt] = Mersenne::modp(res);

    r = get_challenge(transcript_hash);

    evaluate_bases(2 * k - 1, r, eval_base_2k);
    temp_result = 0;
    for(uint64_t i = 0; i < 2 * k - 1; i++) {
        temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
    }
    p_eval_r_ss[cnt] = Mersenne::modp_128(temp_result);

    evaluate_bases(k, r, eval_base);
    s0 = s;
    s = (s - 1) / k + 1;

    if (is_verify) {
        for(uint64_t i = 0; i < k; i++) {
            input[i] = new uint64_t[s];

            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) INPUT_PREV(l, index));
                    }
                    input[i][j] = Mersenne::modp_128(temp_result);
                }
                else {
                    input[i][j] = 0;
                }
            }
        }
    }

    else {
        for(uint64_t i = 0; i < k; i++) {
            input[i] = new uint64_t[s];

            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) INPUT_NEXT(l, index));
                    }
                    input[i][j] = Mersenne::modp_128(temp_result);
                }
                else {
                    input[i][j] = 0;
                }
            }
        }
    }

    cnt++;


    /*
                                            =========================
                                                comment mark two.
                                            =========================
    */

    while(true)
    {
        append_msges(transcript_hash, proof.p_evals_masked[cnt]);

        if(((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
               
            } 
        } else {
            
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        
        uint64_t res = 0;
        for(uint64_t j = 0; j < k; j++) { 
            res += proof.p_evals_masked[cnt][j];
        }
        p_eval_ksum_ss[cnt] = Mersenne::modp(res);

        if(s == 1) {
            r = get_challenge(transcript_hash);
            
            assert(r < Mersenne::PR);
            
            evaluate_bases(k, r, eval_base);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) input[i][0]);
            }
            final_input = Mersenne::modp_128(temp_result);

           

            evaluate_bases(2 * k - 1, r, eval_base_2k);
            temp_result = 0;
            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
            }
            final_result_ss = Mersenne::modp_128(temp_result);
            break;
        }


        r = get_challenge(transcript_hash);

        evaluate_bases(2 * k - 1, r, eval_base_2k);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
        }
        p_eval_r_ss[cnt] = Mersenne::modp_128(temp_result);

       

        evaluate_bases(k, r, eval_base);
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

    delete[] eval_base;
    delete[] eval_base_2k;

    VerMsg vermsg(
        p_eval_ksum_ss,
        p_eval_r_ss,
        final_input,
        final_result_ss
    );
    return vermsg;
}

template <class _T>
bool Malicious3PCProtocol<_T>::_verify(
    DZKProof proof, 
    int node_id,
    VerMsg other_vermsg, 
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t len = log(4 * T) / log(k) + 1;
    
    VerMsg self_vermsg = gen_vermsg(proof, node_id, batch_size, k, masks_ss, prover_ID, party_ID, true);
    
    uint64_t p_eval_ksum, p_eval_r;
    uint64_t first_output = Mersenne::mul(NEG_TWO_INVERSE, batch_size);

    p_eval_ksum = Mersenne::add(self_vermsg.p_eval_ksum_ss[0], other_vermsg.p_eval_ksum_ss[0]);
    
    if(p_eval_ksum != first_output) {  
        cout << "p_eval_ksum != first_output" << endl;
        return false;
    }

    for(uint64_t i = 1; i < len; i++) {
        p_eval_ksum = Mersenne::add(self_vermsg.p_eval_ksum_ss[i], other_vermsg.p_eval_ksum_ss[i]);
        p_eval_r = Mersenne::add(self_vermsg.p_eval_r_ss[i - 1], other_vermsg.p_eval_r_ss[i - 1]);
        
        if(p_eval_ksum != p_eval_r) {    
            cout << "p_eval_ksum != p_eval_r at index " << i << endl; 
            return false;
        }
    }
    uint64_t res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    if(res != p_eval_r) {   
        cout << "res != p_eval_r" << endl;   
        return false;
    } 
    return true;
}

#endif

