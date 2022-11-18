#include "dzkp-fp-mersenne.h"

#include "../Math/Z2k.h"
#include <cstdlib>
#include <ctime>
#include <chrono>

ArithDZKProof arith_prove(
    uint64_t** input_left, 
    uint64_t** input_right, 
    uint64_t** masks,
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid
) {
    cout << "in arith_prove..." << endl;

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    uint64_t eta = transcript_hash.get_challenge();

    // cout << "checkpoint 1, s: " << s << "T: " << T << endl;

    uint64_t eta_power = 1;
    uint128_t temp_result = 0;

    // Linear combination using randomness eta
    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            input_left[i][2 * j] = Mersenne::mul(input_left[i][2 * j], eta_power);
            input_left[i][2 * j + 1] = Mersenne::mul(input_left[i][2 * j + 1], eta_power);
            eta_power = Mersenne::mul(eta_power, eta);
        }
    }

    // cout << "checkpoint 1.2" << endl;

    // Vectors of masked evaluations of polynomial p(X)
    vector<vector<uint64_t>> p_evals_masked;
    // Evaluations of polynomial p(X)
    uint64_t* eval_p_poly = new uint64_t[2 * k - 1];  

    uint64_t** base = new uint64_t*[k - 1];
    for (uint64_t i = 0; i < k - 1; i++) {
        base[i] = new uint64_t[k];
    }
    // Langrange::get_bases(k, base);

    // cout << "checkpoint 1.5" << endl;
    
    uint64_t* eval_base = new uint64_t[k];
    uint64_t** eval_result = new uint64_t*[k];
    for(uint64_t i = 0; i < k; i++) {
        eval_result[i] = (uint64_t*)calloc(k, sizeof(uint64_t));
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
        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        transcript_hash.append_msges(ss);
        uint64_t r = transcript_hash.get_challenge();

        Langrange::evaluate_bases(k, r, eval_base);

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


    for (int j = 0; j < cnt; j ++) {
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
    uint64_t** input,
    uint64_t** input_mono,
    uint64_t** masks_ss,
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
   
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(2 * T) / log(k) + 1;

    vector<uint64_t> b_ss(len);
    uint64_t final_input;
    uint64_t final_result_ss;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    uint64_t eta = transcript_hash.get_challenge();
    uint64_t eta_power = 1, cnt = 0;
    uint128_t temp_result = 0;

    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < s; j++) {
            temp_result += Mersenne::mul(input_mono[i][j], eta_power);
            eta_power = Mersenne::mul(eta_power, eta);
        }
    }
    uint64_t out_ss = Mersenne::modp_128(temp_result);
    
    uint64_t sum_ss = 0;
    for(uint64_t j = 0; j < k; j++) { 
        sum_ss += proof.p_evals_masked[cnt][j];
    }
    b_ss[cnt] = Mersenne::sub(Mersenne::modp(sum_ss), out_ss);

    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;
    if(prev_party) {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
        } 
    } else {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }
    
    uint64_t* eval_base = new uint64_t[k];
    uint64_t* eval_base_2k = new uint64_t[2 * k - 1];

    size_t index = 0;
    s *= 2;
    uint64_t s0 = s, r;

    while(true)
    {
        transcript_hash.append_msges(proof.p_evals_masked[cnt]);

        if(prev_party) {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
            } 
        } else {
            for(uint64_t i = 0; i < 2 * k - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        sum_ss = 0;
        for(uint64_t j = 0; j < k; j++) { 
            sum_ss += proof.p_evals_masked[cnt][j];
        }

        r = transcript_hash.get_challenge();
        Langrange::evaluate_bases(2 * k - 1, r, eval_base_2k);
        temp_result = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) {
            temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
        }
        out_ss = Mersenne::modp_128(temp_result);

        b_ss[cnt] = Mersenne::sub(Mersenne::modp(sum_ss), out_ss);

        if(s == 1) {
            r = transcript_hash.get_challenge();
            assert(r < Mersenne::PR);
            
            Langrange::evaluate_bases(k, r, eval_base);
            temp_result = 0;

            for(uint64_t i = 0; i < k; i++) {
                temp_result += ((uint128_t) eval_base[i]) * ((uint128_t) input[i][0]);
            }
            final_input = Mersenne::modp_128(temp_result);

            Langrange::evaluate_bases(2 * k - 1, r, eval_base_2k);
            temp_result = 0;
            for(uint64_t i = 0; i < 2 * k - 1; i++) {
                temp_result += ((uint128_t) eval_base_2k[i]) * ((uint128_t) proof.p_evals_masked[cnt][i]);
            }
            final_result_ss = Mersenne::modp_128(temp_result);
            break;
        }

        Langrange::evaluate_bases(k, r, eval_base);
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

    for(uint64_t i = 0; i < k; i++) {
        delete[] input[i];
        delete[] input_mono[i];
    }

    delete[] input;
    delete[] input_mono;

    for (int j = 0; j < cnt; j ++) {
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
    uint64_t** input,
    uint64_t** input_mono,
    uint64_t** masks_ss,
    uint64_t batch_size, 
    uint64_t k, 
    uint64_t sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    // cout << "in arith_verify..." << endl;
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t len = log(2 * T) / log(k) + 1;
    
    ArithVerMsg self_vermsg = arith_gen_vermsg(proof, input, input_mono, masks_ss, batch_size, k, sid, prover_ID, party_ID);

    uint64_t b;

    for(uint64_t i = 0; i < len; i++) {
        b = Mersenne::add(self_vermsg.b_ss[i], other_vermsg.b_ss[i]);
        
        if(b) {    
            // cout << "b != 0 at index " << i << endl; 
            return false;
        }
    }
    uint64_t res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    uint64_t p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    if(res != p_eval_r) {   
        // cout << "res != p_eval_r" << endl;   
        return false;
    } 

    // cout << "out of arith_verify..." << endl;
    return true;
}




int main() {
    uint64_t T = 10000000; 
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
            masks_prev[i][j] = Mersenne::get_rand();
            masks_next[i][j] = Mersenne::get_rand();
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
                uint64_t x_first = Mersenne::get_rand();
                uint64_t x_second = Mersenne::get_rand();
                uint64_t y_first = Mersenne::get_rand();
                uint64_t y_second = Mersenne::get_rand();
                uint64_t rho_first = Mersenne::get_rand();
                uint64_t rho_second = Mersenne::get_rand();
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
                assert(left == right);

            }
            temp_pointer++;
            // cout << "chcekpoint 3" << endl;
        }
    }

    uint64_t sid = Mersenne::get_rand();

    auto start = std::chrono::high_resolution_clock::now();
    ArithDZKProof proof = arith_prove(input_left, input_right, masks, T, k, sid);
    auto end = std::chrono::high_resolution_clock::now();
    cout << "Proving time: " << (start - end).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();
    ArithVerMsg other_vermsg = arith_gen_vermsg(proof, input_left_next, input_mono_next, masks_next, T, k, sid, 0, 1);
    bool res = arith_verify(proof, other_vermsg, input_right_prev, input_mono_prev, masks_prev, T, k, sid, 0, 2);
    end = std::chrono::high_resolution_clock::now();
    cout << "Verifying time: " << (start - end).count() / 1e6 << " ms" << endl;

    // cout << "res: " << res << endl;
    return 0;
} 

