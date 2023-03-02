#ifndef PROTOCOLS_BINARYCHECK_HPP_
#define PROTOCOLS_BINARYCHECK_HPP_

#include "BinaryCheck.h"

#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace std;

#define BOUND 63

template <class _T>
DZKProof Malicious3PCProtocol<_T>::_prove(
    int node_id,
    Field** masks,
    uint64_t batch_size, 
    Field sid
) {
    uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k2 = OnlineOptions::singleton.k2_size;

    // cout << "in _prove" << endl;
    // cout << "batch_size: " << T << ", s: " << s << endl;

    vector<vector<Field>> p_evals_masked;
    uint64_t k_max = max(k, k2);
    // Evaluations of polynomial p(X)
    Field* eval_p_poly = new Field[2 * k_max - 1];  

    Field** base = new Field*[k_max - 1];
    for (uint64_t i = 0; i < k_max - 1; i++) {
        base[i] = new Field[k_max];
    }

    Field** eval_result = new Field*[k_max];
    for(uint64_t i = 0; i < k_max; i++) {
        eval_result[i] = new Field[k_max];
    }

    Field* eval_base = new Field[k_max];

    // ===============================  First Round  ===============================

    auto start = std::chrono::high_resolution_clock::now();

    // Vectors of masked evaluations of polynomial p(X)
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);

    Langrange::get_bases(k, base);

    // cout << "cp 1.5" << endl;

    ShareTupleBlock k_share_tuple_blocks[k];
    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    uint64_t block_s = (s - 1) / BLOCK_SIZE + 1;
    int cur_k_blocks = 0;
    uint64_t block_batch_size = (batch_size - 1) / BLOCK_SIZE + 1;

    // cout << "block_s: " << block_s << endl;
    // cout << "block_batch_size: " << block_batch_size << endl;

    for (uint64_t block_col = 0; block_col < block_s; block_col ++) {
        // cout << "block_col: " << block_col << endl;
        // fetch k tuple_blocks
        memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, block_batch_size - cur_k_blocks));
        for(uint64_t i = 0; i < k; i++) { 
            // cout << "i:" << i << endl;
            ShareTupleBlock row_tuple_block = k_share_tuple_blocks[i];
            
            for(uint64_t j = 0; j < k; j++) {  
                // cout << "j: " << j << endl;

                if (cur_k_blocks + i >= block_batch_size || cur_k_blocks + j >= block_batch_size) {
                    // cout << "continue, > block_batch_size " << j << endl;
                    continue;
                }
                if (i == j) {
                    // cout << "continue, i=j " << j << endl;
                    eval_result[i][j] = 0;
                    continue;
                }
                ShareTupleBlock col_tuple_block = k_share_tuple_blocks[j];

                long this_value_block = 0;
                
                this_value_block ^= (row_tuple_block.input1.first & col_tuple_block.input2.second);
                this_value_block ^= (col_tuple_block.input1.second & row_tuple_block.input2.first);

                this_value_block ^= (row_tuple_block.result.first ^ row_tuple_block.rho.first);
                this_value_block ^= (row_tuple_block.input1.first & row_tuple_block.input2.first);
                
                this_value_block ^= col_tuple_block.rho.second;

                Field sum = (this_value_block >> 32) + (this_value_block & 0x00000000FFFFFFFF);
                eval_result[i][j] = Mersenne::add(eval_result[i][j], sum);
            }
        }
        cur_k_blocks += k;
    }

    uint64_t num = (0xFFFFFFFF - 1) * 2 * block_s;
    Field extra_addition = Mersenne::mul(neg_two_inverse, num);

    for(uint64_t i = 0; i < k; i++) {
        for(uint64_t j = 0; j < k; j++) {
            eval_result[i][j] = Mersenne::add(eval_result[i][j], extra_addition);
        }
    }

    for(uint64_t i = 0; i < k; i++) {
        eval_p_poly[i] = eval_result[i][i];
    }

    for(uint64_t i = 0; i < k - 1; i++) {
        eval_p_poly[i + k] = 0;
        for(uint64_t j = 0; j < k; j++) {
            for (uint64_t l = 0; l < k; l++) {
                // eval_p_poly[i + k] += base[i][j] * eval_result[j][l] * base[i][l];
                eval_p_poly[i + k] = Mersenne::add(eval_p_poly[i + k], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    cout << "First round (compute p coeffs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    uint16_t cnt = 0;

    // cout << "cp 1" << endl;

    vector<Field> ss(2 * k - 1);       
    for(uint64_t i = 0; i < 2 * k - 1; i++) {           
        // ss[i] = eval_p_poly[i] - masks[cnt][i];
        ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
    }
    p_evals_masked.push_back(ss);
    cnt++;

    // cout << "cp 2" << endl;

    transcript_hash.append_msges(ss);
    Field r = transcript_hash.get_challenge();

    Langrange::evaluate_bases(k, r, eval_base);

    s *= 4;
    uint64_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;

    // cout << "s: " << s << endl;
    // cout << "k2: " << k2 << endl;

    Field **input_left, **input_right;
    input_left = new Field*[k2];
    input_right = new Field*[k2];

    for(uint64_t i = 0; i < k2; i++) {
        input_left[i] = new Field[s];
        input_right[i] = new Field[s];
    }

    size_t index = 0;
    cur_k_blocks = 0;

    for (uint64_t block_col = 0; block_col < block_s; block_col ++) {
        // cout << "block_col: " << block_col << endl;

        // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
        memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, block_batch_size - cur_k_blocks));

        for (int l = 0; l < BLOCK_SIZE; l++) {
            int row = index / s;
            int col = index % s;

            // cout << "index: " << index << ", row: " << row << ", col: " << col << ", k: " << k << endl;

            if (index >= s0) {
                // cout << "cp 4" << endl;
                input_left[row][col] = input_left[row][col + 1] = input_left[row][col + 2] = input_left[row][col + 3] = 0;
                input_right[row][col] = input_right[row][col + 1] = input_right[row][col + 2] = input_right[row][col + 3] = 0;
            } 
            else {
                for(uint64_t i = 0; i < k; i++) {
                    long temp_e = k_share_tuple_blocks[i].result.first ^ (k_share_tuple_blocks[i].result.first & k_share_tuple_blocks[i].input2.first) ^ k_share_tuple_blocks[i].rho.first;
                    bool e = (temp_e >> l) & 1;
                    Field t1 = e ? Mersenne::neg(eval_base[i]) : eval_base[i];
                    Field t2 = ((k_share_tuple_blocks[i].rho.first >> l) & 1) ? Mersenne::neg(eval_base[i]) : eval_base[i];

                    bool x_first = (k_share_tuple_blocks[i].input1.first >> l) & 1;
                    bool y_first = (k_share_tuple_blocks[i].input2.first >> l) & 1;
                    bool x_second = (k_share_tuple_blocks[i].input1.first >> l) & 1;
                    bool y_second = (k_share_tuple_blocks[i].input2.first >> l) & 1;

                    input_left[row][col] += (x_first & y_first) ? ((e ? 2 : neg_two) * eval_base[i]) : 0;
                    input_left[row][col + 1] += y_first ? t1 : 0;
                    input_left[row][col + 2] += x_first ? t1 : 0;
                    input_left[row][col + 3] += (e ? two_inverse : neg_two_inverse) * eval_base[i];
                    
                    input_right[row][col] += (y_second & x_second) ? t2 : 0;
                    input_right[row][col + 1] += x_second ? t2 : 0;
                    input_right[row][col + 2] += y_second ? t2 : 0;
                    input_right[row][col + 3] += t2;

                }

                input_left[row][col] = Mersenne::modp(input_left[row][col]);
                input_left[row][col + 1] = Mersenne::modp(input_left[row][col + 1]);
                input_left[row][col + 2] = Mersenne::modp(input_left[row][col + 2]);
                input_left[row][col + 3] = Mersenne::modp(input_left[row][col + 3]);
                    
                input_right[row][col] = Mersenne::modp(input_right[row][col]);
                input_right[row][col + 1] = Mersenne::modp(input_right[row][col + 1]);
                input_right[row][col + 2] = Mersenne::modp(input_right[row][col + 2]);
                input_right[row][col + 3] = Mersenne::modp(input_right[row][col + 3]);
            }
            index += 4;
        }
        cur_k_blocks += k;
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    while(true){
        // auto start = std::chrono::high_resolution_clock::now();
        // cout << "s: " << s << endl;

        for(uint64_t i = 0; i < k2; i++) {
            for(uint64_t j = 0; j < k2; j++) {
                eval_result[i][j] = Mersenne::inner_product(input_left[i], input_right[j], s);
            }
        }
        // cout << "cp 1" << endl;

        for(uint64_t i = 0; i < k2; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        for(uint64_t i = 0; i < k2 - 1; i++) {
            eval_p_poly[i + k2] = 0;
            for(uint64_t j = 0; j < k2; j++) {
                for (uint64_t l = 0; l < k2; l++) {
                    // eval_p_poly[i + k] += base[i][j] * eval_result[j][l] * base[i][l];
                    eval_p_poly[i + k2] = Mersenne::add(eval_p_poly[i + k2], Mersenne::mul(base[i][j], Mersenne::mul(eval_result[j][l], base[i][l])));
                }
            }
        }
        // cout << "cp 2" << endl;

        vector<Field> ss(2 * k2 - 1);       
        for(uint64_t i = 0; i < 2 * k2 - 1; i++) {           
            // ss[i] = eval_p_poly[i] - masks[cnt][i];
            // cout << "i" << i << endl;
            ss[i] = Mersenne::sub(eval_p_poly[i], masks[cnt][i]);
        }
        p_evals_masked.push_back(ss);

        if (s == 1) {
            // cout << "breaking" << endl;
            break;
        }
        
        transcript_hash.append_msges(ss);
        Field r = transcript_hash.get_challenge();

        Langrange::evaluate_bases(k2, r, eval_base);

        s0 = s;
        s = (s - 1) / k2 + 1;
        // cout << "cp 3, s: " << s << endl;
       
        for(uint64_t i = 0; i < k2; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
               
                if (index < s0) {
                    uint128_t temp_result = 0;
                    for(uint64_t l = 0; l < k2; l++) {
                        // temp_result += eval_base[l] * input_left[l][index];
                        temp_result += ((uint128_t) eval_base[l]) * ((uint128_t) input_left[l][index]);
                    }
                    input_left[i][j] = Mersenne::modp_128(temp_result);

                    temp_result = 0;
                    for(uint64_t l = 0; l < k2; l++) {
                        // temp_result += eval_base[l] * input_right[l][index];
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
        // cout << "cp 4" << endl;
        cnt++;
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;

    // cout << "cp 3" << endl;

    // for(uint64_t i = 0; i < k; i++) {
    //     delete[] eval_result[i];
    // }
    // delete[] eval_result;
    // delete[] eval_p_poly;

    // for (uint64_t i = 0; i < k - 1; i++) {
    //     delete[] base[i];
    // }
    // delete[] base;
    // delete[] eval_base;

    // for(uint64_t i = 0; i < k; i++) {
    //     delete[] input_left[i];
    //     delete[] input_right[i];
    // }

    // delete[] input_left;
    // delete[] input_right;

    // for (uint64_t j = 0; j < cnt; j ++) {
    //     delete[] masks[j];
    // }
    // delete[] masks;

    DZKProof proof = {
        p_evals_masked,
    };
    return proof;
}

template <class _T>
VerMsg Malicious3PCProtocol<_T>::_gen_vermsg(
    DZKProof proof, 
    int node_id,
    Field** masks_ss,
    uint64_t batch_size, 
    Field sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    // cout << "in _gen_vermsg " << endl;
    uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k2 = OnlineOptions::singleton.k2_size;

    uint64_t k_max = max(k, k2);

    Field* eval_base = new Field[k_max];
    Field* eval_base_2k = new Field[2 * k_max - 1];    

    // ===============================  First Round  ===============================

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(4 * s) / log(k2) + 2;

    vector<Field> b_ss(len);
    Field final_input = 0, final_result_ss = 0;

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);

    uint64_t cnt = 0;
    Field out_ss = 0, sum_ss = 0;

    // recover proof
    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;
    if(prev_party) {
        uint64_t num = (0xFFFFFFFF - 1) * 2 * batch_size;
        out_ss = Mersenne::mul(neg_two_inverse, num);
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
        } 
    } else {
        out_ss = 0;
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }

    // compute random linear combination on the first k outputs using betas
    for(uint64_t j = 0; j < k; j++) { 
        sum_ss += proof.p_evals_masked[cnt][j];
    }

    b_ss[cnt] = Mersenne::sub(sum_ss, out_ss);
    cnt++;

    // new evaluations at random point r

    transcript_hash.append_msges(proof.p_evals_masked[cnt]);
    Field r = transcript_hash.get_challenge();
    Langrange::evaluate_bases(k, r, eval_base);

    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    uint64_t block_s = (s - 1) / BLOCK_SIZE + 1;
    uint64_t block_batch_size = (batch_size - 1) / BLOCK_SIZE + 1;
    int cur_k_blocks = 0;
    ShareTupleBlock k_share_tuple_blocks[k];

    s *= 4;
    uint64_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;
    size_t index = 0;
 
    // cout << "cp 3" << endl;

    Field **input = new Field*[k2];
    for(uint64_t i = 0; i < k2; i++) {
        input[i] = new Field[s];
    }

    if (prev_party) {
        for (uint64_t block_col = 0; block_col < block_s; block_col ++) {
            // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, block_batch_size - cur_k_blocks));
    
            for (int l = 0; l < BLOCK_SIZE; l++) {
                int row = index / s;
                int col = index % s;
                if (index >= s0) {
                    input[row][col] = input[row][col + 1] = input[row][col + 2] = input[row][col + 3] = 0;
                } 
                else {
                    for(uint64_t i = 0; i < k; i++) {
                    
                        Field t2 = ((k_share_tuple_blocks[i].rho.first >> l) & 1) ? Mersenne::neg(eval_base[i]) : eval_base[i];

                        bool x_first = (k_share_tuple_blocks[i].input1.first >> l) & 1;
                        bool y_first = (k_share_tuple_blocks[i].input2.first >> l) & 1;

                        input[row][col] += (x_first & y_first) ? t2 : 0;
                        input[row][col + 1] += x_first ? t2 : 0;
                        input[row][col + 2] += y_first ? t2 : 0;
                        input[row][col + 3] += t2;
                    }
                
                    input[row][col] = Mersenne::modp(input[row][col]);
                    input[row][col + 1] = Mersenne::modp(input[row][col + 1]);
                    input[row][col + 2] = Mersenne::modp(input[row][col + 2]);
                    input[row][col + 3] = Mersenne::modp(input[row][col + 3]);
                }
                index += 4;
            }
            cur_k_blocks += k;
        }    
    }
    else {
        for (uint64_t block_col = 0; block_col < block_s; block_col ++) {
            // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, block_batch_size - cur_k_blocks));

            for (int l = 0; l < BLOCK_SIZE; l++) {
                int row = index / s;
                int col = index % s;
                if (index >= s0) {
                    input[row][col] = input[row][col + 1] = input[row][col + 2] = input[row][col + 3] = 0;
                } 
                else {
                    for(uint64_t i = 0; i < k; i++) {
                    
                        long temp_e = k_share_tuple_blocks[i].result.second ^ (k_share_tuple_blocks[i].result.second & k_share_tuple_blocks[i].input2.second) ^ k_share_tuple_blocks[i].rho.second;
                        bool e = (temp_e >> l) & 1;
                        Field t1 = e ? Mersenne::neg(eval_base[i]) : eval_base[i];

                        bool x_second = (k_share_tuple_blocks[i].input1.second >> l) & 1;
                        bool y_second = (k_share_tuple_blocks[i].input2.second >> l) & 1;

                        input[row][col] += (x_second & y_second) ? ((e ? 2 : neg_two) * eval_base[i]) : 0;
                        input[row][col + 1] += y_second ? t1 : 0;
                        input[row][col + 2] += x_second ? t1 : 0;
                        input[row][col + 3] += (e ? two_inverse : neg_two_inverse) * eval_base[i];
                   
                    }
                
                    input[row][col] = Mersenne::modp(input[row][col]);
                    input[row][col + 1] = Mersenne::modp(input[row][col + 1]);
                    input[row][col + 2] = Mersenne::modp(input[row][col + 2]);
                    input[row][col + 3] = Mersenne::modp(input[row][col + 3]);
                }
                index += 4;
            }
            cur_k_blocks += k;
        }    
    }

    // cout << "cp 4" << endl;

    while(true)
    {
        transcript_hash.append_msges(proof.p_evals_masked[cnt]);

        if(prev_party) {
            for(uint64_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = Mersenne::add(proof.p_evals_masked[cnt][i], masks_ss[cnt][i]);
            } 
        } else {
            for(uint64_t i = 0; i < 2 * k2 - 1; i++) { 
                proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
            }
        }
        sum_ss = 0;
        for(uint64_t j = 0; j < k2; j++) { 
            sum_ss += proof.p_evals_masked[cnt][j];
        }

        r = transcript_hash.get_challenge();
        Langrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);
        uint128_t temp_result = 0;
        for(uint64_t i = 0; i < 2 * k2 - 1; i++) {
            temp_result += (uint128_t)eval_base_2k[i] * (uint128_t)proof.p_evals_masked[cnt][i];
        }
        out_ss = Mersenne::modp_128(temp_result);

        // b_ss[cnt] = sum_ss - out_ss;
        b_ss[cnt] = Mersenne::sub(sum_ss, out_ss);

        if(s == 1) {
            r = transcript_hash.get_challenge();
            Langrange::evaluate_bases(k2, r, eval_base);
            
            for(uint64_t i = 0; i < k2; i++) {
                final_input += eval_base[i] * input[i][0];
            }
            Langrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);

            final_result_ss = Mersenne::inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

            break;
        }

        Langrange::evaluate_bases(k2, r, eval_base);
        s0 = s;
        s = (s - 1) / k2 + 1;
        for(uint64_t i = 0; i < k2; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    uint128_t temp_result = 0;
                    for(uint64_t l = 0; l < k2; l++) {
                        temp_result += (uint128_t)eval_base[l] * (uint128_t)input[l][index];
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
    // cout << "cp 5" << endl;

    // delete[] eval_base;
    // delete[] eval_base_2k;

    // for(uint64_t i = 0; i < k; i++) {
    //     delete[] input_mono[i];
    //     delete[] input_mono[i];
    // }

    // delete[] input;
    // delete[] input_mono;

    // for (uint64_t j = 0; j < cnt; j ++) {
    //     delete[] masks_ss[j];
    // }
    // delete[] masks_ss;

    VerMsg vermsg(
        b_ss,
        final_input,
        final_result_ss
    );
    // cout << "cp 6" << endl;

    return vermsg;
}

template <class _T>
bool Malicious3PCProtocol<_T>::_verify(
    DZKProof proof, 
    VerMsg other_vermsg, 
    int node_id,
    Field** masks_ss,
    uint64_t batch_size, 
    Field sid,
    uint64_t prover_ID,
    uint64_t party_ID
) {
    // cout << "in _verify..." << endl;
    uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k2 = OnlineOptions::singleton.k2_size;
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(4 * s) / log(k2) + 2;
    
    VerMsg self_vermsg = _gen_vermsg(proof, node_id, masks_ss, batch_size, sid, prover_ID, party_ID);

    Field b;
    // cout << "in _verify, cp 1" << endl;
    for(uint64_t i = 0; i < len; i++) {
        // b = self_vermsg.b_ss[i] + other_vermsg.b_ss[i];
        b = Mersenne::add(self_vermsg.b_ss[i], other_vermsg.b_ss[i]);
        
        if(!b) {    
            // cout << "b != 0 at index " << i << endl; 
            return false;
        }
    }
    // cout << "in _verify, cp 2" << endl;

    // Field res = self_vermsg.final_input + other_vermsg.final_input;
    // Field p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    Field res = Mersenne::mul(self_vermsg.final_input, other_vermsg.final_input);
    Field p_eval_r = Mersenne::add(self_vermsg.final_result_ss, other_vermsg.final_result_ss);
    
    if(res != p_eval_r) {   
        // cout << "res != p_eval_r" << endl;
        return false;
    } 

    // cout << "out of _verify..." << endl;
    return true;
}

#endif
