#ifndef PROTOCOLS_BINSRYCHECK_HPP_
#define PROTOCOLS_BINSRYCHECK_HPP_

#include "BinaryCheck.h"

#include "Math/mersenne.hpp"
#include "Math/Z2k.h"
#include <cstdlib>
#include <ctime>


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

/*

uint64_t get_rand() {
    uint64_t left, right;
    left = rand();
    right = ((uint64_t)rand()) + (left<<32);
    return right & Mersenne::PR;
}

void get_bases(uint64_t n, Field** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j] = 1;
            for(uint64_t l = 0; l < n; l++) {
                if (l != j) {
                    Field denominator, numerator;
                    denominator = j - l;
                    numerator = i + n - l;
                    result[i][j] = result[i][j] * denominator.invert() * numerator;
                }
            }
        }
    }
}

void evaluate_bases(uint64_t n, uint64_t r, Field* result) {

    for(uint64_t i = 0; i < n; i++) {
        result[i] = 1;
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                Field denominator, numerator; 
                denominator = i - j;
                numerator = r - j; 
                result[i] = result[i] * denominator.invert() * numerator;
            }
        }
    }
}

void append_one_msg(LocalHash &hash, uint64_t msg) {
    hash.update(msg);
}

void append_msges(LocalHash &hash, vector<Field> msges) {
    for(Field msg: msges) {
        hash.update(msg);
    }
}

uint64_t get_challenge(LocalHash &hash) {
    
    

    uint64_t r = hash.final();
    return r & Mersenne::PR;
}

DZKProof prove(
    Field** input_left, 
    Field** input_right, 
    uint64_t batch_size, 
    uint64_t k, 
    Field** masks
) {

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    LocalHash transcript_hash;

    s *= 4;
    vector<vector<Field>> p_evals_masked;

    Field** base = new Field*[k - 1];
    for (uint64_t i = 0; i < k - 1; i++) {
        base[i] = new Field[k];
    }

    get_bases(k, base);

    Field* eval_base = new Field[k];
    uint64_t s0;
    Field** eval_result = new Field*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = new Field[k];
    }
    Field* eval_p_poly = new Field[2 * k - 1];  
    Field temp_result;
    uint64_t index;
    uint16_t cnt = 0;
    
    
    while(true){

        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < k; j++) {
                for (uint64_t u = 0; u < s; u ++) {
                    eval_result[i][j] += input_left[i][u] * input_right[j][u];
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

        Field sum = 0;
        for(uint64_t j = 0; j < k; j++) {
            sum += eval_p_poly[j];
        }

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
                        temp_result += eval_base[l] * input_left[l][index];
                    }

                    input_left[i][j] = temp_result;
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input_right[l][index];
                    }
                   

                    input_right[i][j] = temp_result;
                   
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

    DZKProof proof(p_evals_masked);
    
    return proof;
}


VerMsg gen_vermsg(
    DZKProof proof, 
    Field** input,
    uint64_t batch_size, 
    uint64_t k, 
    Field** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
) {
   
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    LocalHash transcript_hash;

    Field* eval_base = new Field[k];
    Field* eval_base_2k = new Field[2 * k - 1];
    uint64_t r, s0, index, cnt = 0;
    Field temp_result;

    uint64_t len = log(4 * T) / log(k) + 1;

    vector<Field> p_eval_ksum_ss(len);
    vector<Field> p_eval_r_ss(len);
    Field final_input;
    Field final_result_ss;
    s *= 4;
    while(true)
    {
        append_msges(transcript_hash, proof.p_evals_masked[cnt]);

        if(((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0) {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = proof.p_evals_masked[cnt][i] + masks_ss[cnt][i];
               
            } 
        } else {
            
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        
        Field res = 0;
        for(uint64_t j = 0; j < k; j++) { 
            res += proof.p_evals_masked[cnt][j];
        }
        p_eval_ksum_ss[cnt] = res;

        if(s == 1) {
            r = get_challenge(transcript_hash);
            
            assert(r < Mersenne::PR);
            
            evaluate_bases(k, r, eval_base);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += eval_base[i] * input[i][0];
            }
            final_input = temp_result;

           

            evaluate_bases(2 * k - 1, r, eval_base_2k);
            temp_result = 0;
            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                temp_result += eval_base_2k[i] * proof.p_evals_masked[cnt][i];
            }
            final_result_ss = temp_result;
            break;
        }


        r = get_challenge(transcript_hash);

        evaluate_bases(2 * k - 1, r, eval_base_2k);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += eval_base_2k[i] * proof.p_evals_masked[cnt][i];
        }
        p_eval_r_ss[cnt] = temp_result;

       

        evaluate_bases(k, r, eval_base);
        s0 = s;
        s = (s - 1) / k + 1;
        for(uint64_t i = 0; i < k; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    temp_result = 0;
                    for(uint64_t l = 0; l < k; l++) {
                        temp_result += eval_base[l] * input[l][index];
                    }
                    input[i][j] = temp_result;
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

bool _verify(
    DZKProof proof, 
    Field** input, 
    VerMsg other_vermsg, 
    uint64_t batch_size, 
    uint64_t k, 
    Field** masks_ss,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t len = log(4 * T) / log(k) + 1;
    
    VerMsg self_vermsg = gen_vermsg(proof, input, batch_size, k, masks_ss, prover_ID, party_ID);
    
    Field p_eval_ksum, p_eval_r;
    Field neg_inv2(2);
    neg_inv2 = -neg_inv2.invert();
    Field first_output = neg_inv2 * batch_size;

    p_eval_ksum = self_vermsg.p_eval_ksum_ss[0] + other_vermsg.p_eval_ksum_ss[0];
    
    if(p_eval_ksum != first_output) {  
        // return false;
    }

    for(uint64_t i = 1; i < len; i++) {
        p_eval_ksum = self_vermsg.p_eval_ksum_ss[i] + other_vermsg.p_eval_ksum_ss[i];
        p_eval_r = self_vermsg.p_eval_r_ss[i - 1] + other_vermsg.p_eval_r_ss[i - 1];
        
        if(p_eval_ksum != p_eval_r) {     
            // return false;
        }
    }
    Field res = self_vermsg.final_input * other_vermsg.final_input;
    p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    
    if(res != p_eval_r) {      
        // return false;
    } 
    return true;
}

*/

#endif
