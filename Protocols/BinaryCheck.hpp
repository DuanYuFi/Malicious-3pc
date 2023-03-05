#ifndef PROTOCOLS_BINARYCHECK_HPP_
#define PROTOCOLS_BINARYCHECK_HPP_

#include "BinaryCheck.h"

#include "Math/gf2n.h"
#include <cstdlib>
#include <ctime>
#include <chrono>

// Field general_reduce(int128 a) {
//     Field::internal_type hi,lo;

//     if (Field::MAX_N_BITS <= 64){
//         hi = a.get_upper();
//         lo = a.get_lower();
//     } 
//     else {
//         a.to(lo);
//         hi = 0;
//     }
//     Field res;
//     res.reduce(hi, lo);
//     return res;
// }

template <class _T>
DZKProof Malicious3PCProtocol<_T>::_prove(
    int node_id,
    Field** masks,
    uint64_t batch_size, 
    Field sid,
    PRNG prng
) {
    uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k2 = OnlineOptions::singleton.k2_size;

    // cout << "in _prove" << endl;
    // cout << "batch_size: " << T << ", s: " << s << endl;

    // Vectors of masked evaluations of polynomial p(X)
    vector<vector<Field>> p_evals_masked;
    uint64_t k_max = k > k2 ? k : k2;
    // cout << "k: " << k << ", k2: " << k2 << ", k_max: " << k_max << endl;

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

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;

    Field* thetas = new Field[s];
    for(uint64_t j = 0; j < s; j++) {
        thetas[j].randomize(prng);
    }

    // Transcript
    LocalHash transcript_hash;
    transcript_hash.append_one_msg(sid);
    
    Langrange::get_bases(k, base);

    ShareTupleBlock k_share_tuple_blocks[k];
    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    uint64_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    int cur_k_blocks = 0;
    uint64_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;

    // cout << "block_cols_num: " << block_cols_num << endl;
    // cout << "total_blocks_num: " << total_blocks_num << endl;

    for (uint64_t block_col = 0; block_col < block_cols_num; block_col ++) {
        // cout << "block_col: " << block_col << endl;
        // fetch k tuple_blocks
        memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, total_blocks_num - cur_k_blocks));
        
        for(uint64_t i = 0; i < k; i++) { 
            ShareTupleBlock row_tuple_block = k_share_tuple_blocks[i];
            
            for(uint64_t j = 0; j < k; j++) {  
                if (cur_k_blocks + i >= total_blocks_num || cur_k_blocks + j >= total_blocks_num) {
                    continue;
                }
                if (i == j) {
                    continue;
                }

                ShareTupleBlock col_tuple_block = k_share_tuple_blocks[j];

                long this_value_block = 0;
                this_value_block ^= (row_tuple_block.input1.first & col_tuple_block.input2.second);
                this_value_block ^= (row_tuple_block.input2.first & col_tuple_block.input1.second);

                for(int l = 0; l < BLOCK_SIZE; l++) {
                    if ((this_value_block >> l) & 1) {
                        eval_result[i][j] += thetas[block_col * BLOCK_SIZE + l];
                    }
                }
            }
        }
        cur_k_blocks += k;
    }

    for(uint64_t i = 0; i < k; i++) {
        eval_p_poly[i] = 0;
    }

    for(uint64_t i = 0; i < k - 1; i++) {
        eval_p_poly[i + k] = 0;
        for(uint64_t j = 0; j < k; j++) {
            for (uint64_t l = 0; l < k; l++) {
                eval_p_poly[i + k] += base[i][j] * eval_result[j][l] * base[i][l];
            }
        }
    }

    auto end = std::chrono::high_resolution_clock::now();
    cout << "First round (compute p coeffs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    uint16_t cnt = 0;

    vector<Field> ss(2 * k - 1);       
    for(uint64_t i = 0; i < 2 * k - 1; i++) {           
        ss[i] = eval_p_poly[i] - masks[cnt][i];
    }
    p_evals_masked.push_back(ss);
    cnt++;

    // cout << "checkpoint 2" << endl;
    transcript_hash.append_msges(ss);
    Field r = transcript_hash.get_challenge();

    Langrange::evaluate_bases(k, r, eval_base);

    s *= 2;
    uint64_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;

    // cout << "s0: " << s0 << ", s: " << s << ", k2: " << k2 << endl;

    Field **input_left, **input_right;
    input_left = new Field*[k2];
    input_right = new Field*[k2];

    for(uint64_t i = 0; i < k2; i++) {
        input_left[i] = new Field[s];
        input_right[i] = new Field[s];
    }

    size_t index = 0;
    cur_k_blocks = 0;

    uint64_t table_size = 1 << k;
    Field* input_table = new Field[table_size];

    for (uint64_t i = 0; i < table_size; i++) {
        Field sum = 0;
        for (uint64_t j = 0; j < k; j++) {
            if ((i >> j) & 1)
                sum += eval_base[j];
        }
        input_table[i] = sum;
    }

    for (uint64_t block_col = 0; block_col < block_cols_num; block_col ++) {
        // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
        memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, total_blocks_num - cur_k_blocks));
        
        for (int l = 0; l < BLOCK_SIZE; l++) {
            int row = index / s;
            int col = index % s;
            if (index >= s0) {
                if ((uint64_t)row == k2) {
                    break;
                }
                else {
                    input_left[row][col] = input_left[row][col + 1] = 0;
                    input_right[row][col] = input_right[row][col + 1] = 0;
                    // cout << "row: " << row << ", col: " << col << endl;
                }
            } 
            else {
                uint64_t left_id1 = 0, left_id2 = 0, right_id1 = 0, right_id2 = 0;

                for (uint64_t j = 0; j < k; j++) {
                    if ((k_share_tuple_blocks[j].input1.first >> l) & 1) left_id1 ^= 1 << k;
                    if ((k_share_tuple_blocks[j].input2.first >> l) & 1) left_id2 ^= 1 << k;
                    if ((k_share_tuple_blocks[j].input2.second >> l) & 1) right_id1 ^= 1 << k;
                    if ((k_share_tuple_blocks[j].input1.second >> l) & 1) right_id1 ^= 1 << k;
                }

                input_left[row][col] = input_table[left_id1] * thetas[block_col * BLOCK_SIZE + l];
                input_left[row][col + 1] = input_table[left_id2] * thetas[block_col * BLOCK_SIZE + l];
                input_right[row][col] = input_table[right_id1];
                input_right[row][col + 1] = input_table[right_id2];
            }
            index += 2;
        }
        cur_k_blocks += k;
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    while(true){
        // auto start = std::chrono::high_resolution_clock::now();
        // cout << "cp 1, s: " << s << ", k2: " << k2 << endl;

        for(uint64_t i = 0; i < k2; i++) {
            for(uint64_t j = 0; j < k2; j++) {
                // cout << "cp 1.5, i: " << i << ", j: " << j << endl;
                eval_result[i][j] = inner_product(input_left[i], input_right[j], s);
            }
        }
        // cout << "cp 2" << endl;

        for(uint64_t i = 0; i < k2; i++) {
            eval_p_poly[i] = eval_result[i][i];
        }

        // cout << "cp 3" << endl;

        for(uint64_t i = 0; i < k2 - 1; i++) {
            eval_p_poly[i + k2] = 0;
            for(uint64_t j = 0; j < k2; j++) {
                for (uint64_t l = 0; l < k2; l++) {
                    eval_p_poly[i + k2] += base[i][j] * eval_result[j][l] * base[i][l];
                }
            }
        }

        // cout << "cp 4" << endl;

        vector<Field> ss(2 * k2 - 1);       
        for(uint64_t i = 0; i < 2 * k2 - 1; i++) {           
            ss[i] = eval_p_poly[i] - masks[cnt][i];
        }
        p_evals_masked.push_back(ss);

        if (s == 1) {
            break;
        }
        
        transcript_hash.append_msges(ss);
        Field r = transcript_hash.get_challenge();

        Langrange::evaluate_bases(k2, r, eval_base);

        s0 = s;
        s = (s - 1) / k2 + 1;

        // cout << "cp 5" << endl;
       
        for(uint64_t i = 0; i < k2; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                // cout << "cp 5.5, index: " << index << endl;
               
                if (index < s0) {
                    Field temp_result;
                    temp_result = 0;
                    for(uint64_t l = 0; l < k2; l++) {
                        temp_result += eval_base[l] * input_left[l][index];
                    }
                    input_left[i][j] = temp_result;

                    temp_result = 0;
                    for(uint64_t l = 0; l < k2; l++) {
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
        // cout << "cp 6" << endl;
        cnt++;
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;

    // cout << "checkpoint 3" << endl;

    // for(uint64_t i = 0; i < k_max; i++) {
    //     delete[] eval_result[i];
    // }
    // delete[] eval_result;
    // delete[] eval_p_poly;

    // for (uint64_t i = 0; i < k_max - 1; i++) {
    //     delete[] base[i];
    // }
    // delete[] base;
    // delete[] eval_base;

    // for(uint64_t i = 0; i < k2; i++) {
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
    uint64_t party_ID,
    PRNG prng
) {
    // cout << "in _gen_vermsg " << endl;
    uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k2 = OnlineOptions::singleton.k2_size;

    uint64_t k_max = k > k2 ? k : k2;

    Field* eval_base = new Field[k_max];
    Field* eval_base_2k = new Field[2 * k_max - 1];    

    // ===============================  First Round  ===============================
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(2 * s) / log(k2) + 2;

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
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] += masks_ss[cnt][i];
        } 
    } else {
        for(uint64_t i = 0; i < 2 * k - 1; i++) { 
            proof.p_evals_masked[cnt][i] = masks_ss[cnt][i];
        }
    }

    // sample randomness betas
    Field* betas = new Field[k];
    for(uint64_t j = 0; j < k; j++) {
        betas[j].randomize(prng);
    }

    // compute random linear combination on the first k outputs using betas
    for(uint64_t j = 0; j < k; j++) { 
        sum_ss = inner_product(betas, proof.p_evals_masked[cnt], k);
    }

    // compute out
    // sample randomness thetas
    Field* thetas = new Field[s];
    for(uint64_t j = 0; j < s; j++) {
        thetas[j].randomize(prng);
    }

    // cout << "cp 1" << endl;

    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    uint64_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    uint64_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    int cur_k_blocks = 0;
    ShareTupleBlock k_share_tuple_blocks[k];

    if (prev_party) {
        for (uint64_t block_col = 0; block_col < block_cols_num; block_col ++) {
            // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, total_blocks_num - cur_k_blocks));

            for (uint64_t i = 0; i < k; i++) { 
                if (cur_k_blocks + i >= total_blocks_num) {
                    break;
                }
                long this_block_value = k_share_tuple_blocks[i].result.first ^ (k_share_tuple_blocks[i].result.first & k_share_tuple_blocks[i].input2.first) ^ k_share_tuple_blocks[i].rho.first;
                for(int l = 0; l < BLOCK_SIZE; l++) {
                    if ((this_block_value >> l) & 1) {
                        out_ss += thetas[block_col * BLOCK_SIZE + l];
                    }
                }
            }
            cur_k_blocks += k;
        }
    }
    else {
        for (uint64_t block_col = 0; block_col < block_cols_num; block_col ++) {
            // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, total_blocks_num - cur_k_blocks));

            for (uint64_t i = 0; i < k; i++) { 
                if (cur_k_blocks + i >= total_blocks_num) {
                    break;
                }
                long this_block_value = k_share_tuple_blocks[i].rho.second;
                for(int l = 0; l < BLOCK_SIZE; l++) {
                    if ((this_block_value >> l) & 1) {
                        out_ss += thetas[block_col * BLOCK_SIZE + l];
                    }
                }
            }
            cur_k_blocks += k;
        }
    }
    
    // cout << "cp 2" << endl;
    
    b_ss[cnt] = sum_ss - out_ss;
    cnt++;

    // new evaluations at random point r
    transcript_hash.append_msges(proof.p_evals_masked[cnt]);
    Field r = transcript_hash.get_challenge();
    Langrange::evaluate_bases(k, r, eval_base);

    s *= 2;
    uint64_t s0 = s;
    // use k2 as the compression parameter from the second round
    s = (s - 1) / k2 + 1;
    size_t index = 0;
 
    Field **input = new Field*[k2];

    for(uint64_t i = 0; i < k2; i++) {
        input[i] = new Field[s];
    }
    // cout << "cp 3" << endl;
    cur_k_blocks = 0;

    uint64_t table_size = 1 << k;
    Field* input_table = new Field[table_size];

    for (uint64_t i = 0; i < table_size; i++) {
        Field sum = 0;
        for (uint64_t j = 0; j < k; j++) {
            if ((i >> j) & 1)
                sum += eval_base[j];
        }
        input_table[i] = sum;
    }

    if (prev_party) {

        for (uint64_t block_col = 0; block_col < block_cols_num; block_col ++) {
            // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, total_blocks_num - cur_k_blocks));
            
            for (int l = 0; l < BLOCK_SIZE; l++) {
                int row = index / s;
                int col = index % s;
                if (index >= s0) {
                    if ((uint64_t)row == k2) {
                        break;
                    }
                    else {
                        input[row][col] = input[row][col + 1] = 0;
                    }
                } 
                else {
                    uint64_t left_id1 = 0, left_id2 = 0;

                    for (uint64_t j = 0; j < k; j++) {
                        if ((k_share_tuple_blocks[j].input1.first >> l) & 1) left_id1 ^= 1 << k;
                        if ((k_share_tuple_blocks[j].input2.first >> l) & 1) left_id2 ^= 1 << k;
                    }

                    input[row][col] = input_table[left_id1] * thetas[block_col * BLOCK_SIZE + l];
                    input[row][col + 1] = input_table[left_id2] * thetas[block_col * BLOCK_SIZE + l];
                }
                index += 2;
            }
            cur_k_blocks += k;
        }
    } 
    else {
        for (uint64_t block_col = 0; block_col < block_cols_num; block_col ++) {
            // fetch k tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(k_share_tuple_blocks, share_tuple_blocks + start_point + cur_k_blocks, sizeof(ShareTupleBlock) * min(k, total_blocks_num - cur_k_blocks));
            
            for (int l = 0; l < BLOCK_SIZE; l++) {
                int row = index / s;
                int col = index % s;
                if (index >= s0) {
                    if ((uint64_t)row == k2) {
                        break;
                    }
                    else {
                        input[row][col] = input[row][col + 1] = 0;
                    }
                } 
                else {
                    uint64_t right_id1 = 0, right_id2 = 0;

                    for (uint64_t j = 0; j < k; j++) {
                        if ((k_share_tuple_blocks[j].input2.second >> l) & 1) right_id1 ^= 1 << k;
                        if ((k_share_tuple_blocks[j].input1.second >> l) & 1) right_id1 ^= 1 << k;
                    }

                    input[row][col] = input_table[right_id1];
                    input[row][col + 1] = input_table[right_id2];
                }
                index += 2;
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
                proof.p_evals_masked[cnt][i] += masks_ss[cnt][i];
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
        out_ss = 0;
        for(uint64_t i = 0; i < 2 * k2 - 1; i++) {
            out_ss += eval_base_2k[i] * proof.p_evals_masked[cnt][i];
        }

        b_ss[cnt] = sum_ss - out_ss;

        if(s == 1) {
            r = transcript_hash.get_challenge();
            Langrange::evaluate_bases(k2, r, eval_base);
            
            for(uint64_t i = 0; i < k2; i++) {
                final_input += eval_base[i] * input[i][0];
            }
            Langrange::evaluate_bases(2 * k2 - 1, r, eval_base_2k);

            final_result_ss = inner_product(eval_base_2k, proof.p_evals_masked[cnt], (2 * k2 - 1));

            break;
        }

        Langrange::evaluate_bases(k2, r, eval_base);
        s0 = s;
        s = (s - 1) / k2 + 1;
        for(uint64_t i = 0; i < k2; i++) {
            for(uint64_t j = 0; j < s; j++) {
                index = i * s + j;
                if (index < s0) {
                    Field temp_result;
                    temp_result = 0;
                    for(uint64_t l = 0; l < k2; l++) {
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
    // cout << "cp 5" << endl;

    // delete[] eval_base;
    // delete[] eval_base_2k;

    // for(uint64_t i = 0; i < k; i++) {
    //     delete[] input[i];
    //     delete[] input[i];
    // }

    // delete[] input;
    // delete[] input;

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
    uint64_t party_ID,
    PRNG prng
) {
    // cout << "in _verify..." << endl;
    uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k2 = OnlineOptions::singleton.k2_size;
    
    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(2 * s) / log(k2) + 2;
    
    VerMsg self_vermsg = _gen_vermsg(proof, node_id, masks_ss, batch_size, sid, prover_ID, party_ID, prng);

    Field b;

    for(uint64_t i = 0; i < len; i++) {
        b = self_vermsg.b_ss[i] + other_vermsg.b_ss[i];
        
        if(!b.is_zero()) {    
            // cout << "b != 0 at index " << i << endl; 
            return false;
        }
    }
    Field res = self_vermsg.final_input * other_vermsg.final_input;
    Field p_eval_r = self_vermsg.final_result_ss + other_vermsg.final_result_ss;
    
    if(res != p_eval_r) {   
        // cout << "res != p_eval_r" << endl;
        return false;
    } 

    // cout << "out of arith_verify..." << endl;
    return true;
}

#endif
