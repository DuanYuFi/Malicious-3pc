#ifndef PROTOCOLS_BINARYCHECK_HPP_
#define PROTOCOLS_BINARYCHECK_HPP_

#include "BinaryCheck.h"

#include <cstdlib>
#include <ctime>
#include <chrono>

using namespace std;

template <class _T>
DZKProof Malicious3PCProtocol<_T>::_prove(
    int node_id,
    Field** masks,
    uint64_t batch_size, 
    Field sid
) {
    // uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k = 16;
    uint64_t k2 = OnlineOptions::singleton.k2_size;

    // cout << "in _prove" << endl;
    // cout << "batch_size: " << T << ", s: " << s << endl;

    vector<vector<Field>> p_evals_masked;
    uint64_t k_max = k > k2 ? k : k2;
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


    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    uint64_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    uint64_t two_powers = (0xFFFF - 1) * 4;

    ShareTupleBlock* cur_block = new ShareTupleBlock[1];

    uint64_t addition = ((uint64_t)1 << 31) + ((uint64_t)1 << 63);
    uint64_t delta = Mersenne::PR - ((uint64_t)1 << 31);

    for (uint64_t block_id = 0; block_id < total_blocks_num; block_id++) {
        // cout << "block_id: " << block_id << endl;
        // fetch 1 block
        memcpy(cur_block, share_tuple_blocks + start_point + block_id, sizeof(ShareTupleBlock));
        
        long a_block = cur_block[0].input1.first;
        long c_block = cur_block[0].input2.first;
        long e_block = (a_block & c_block) ^ cur_block[0].result.first ^ cur_block[0].rho.first;
                                            
        long b_block = cur_block[0].input2.second;
        long d_block = cur_block[0].input1.second;
        long f_block = cur_block[0].rho.second;

        for(uint64_t row_entry_id = 0; row_entry_id < 4; row_entry_id++) {
        
            for (uint64_t rotation = 0; rotation < 4; rotation++) {
                
                if (rotation) {
                    // rotate once
                    
                    b_block = (b_block >> 16) ^ (b_block << 48);
                    d_block = (d_block >> 16) ^ (b_block << 48);
                    e_block = (e_block >> 16) ^ (b_block << 48);
                }

                for(uint64_t col_entry_id = 4 * rotation; col_entry_id < 4 * rotation + 4; col_entry_id++) {  

                    long tmp1, tmp2, tmp3, tmp4;

                    switch(row_entry_id) {

                        case 0: {
                            switch(col_entry_id % 4) {
                                // g_1 * h_1 = -2abcd(1-2e)(1-2f) = -2abcd + 4abcde + 4abcdf - 8abcdef
                                case 0:
                                    tmp1 = a_block & b_block & c_block & d_block;
                                    break;
                                    // g_1 * h_2 = -2acd(1-2e)(1-2f) = -2acd + 4acde + 4acdf - 8acdef
                                    case 1:
                                        tmp1 = a_block & c_block & d_block;
                                        break;
                                    // g_1 * h_3 = -2abc(1-2e)(1-2f) = -2abc + 4abce + 4abcf - 8abcef
                                    case 2:
                                        tmp1 = a_block & b_block & c_block;
                                        break; 
                                    // g_1 * h_4 = -2ac(1-2e)(1-2f) = -2ac + 4ace + 4acf - 8acef
                                    case 3:
                                        tmp1 = a_block & c_block;
                                    break; 
                            }
                            tmp2 = tmp1 & e_block;
                            tmp3 = tmp1 & f_block;
                            tmp4 = tmp2 & f_block;

                            Field sum = -2 * (tmp1 & 0x0000FFFF0000FFFF) + 4 * ((tmp2 & 0x0000FFFF0000FFFF) + (tmp3 & 0x0000FFFF0000FFFF)) - 8 * (tmp4 & 0x0000FFFF0000FFFF) + addition;
                            eval_result[row_entry_id][col_entry_id] = Mersenne::modp((sum & 0xFFFFFFFF) + delta);
                            eval_result[row_entry_id + 8][(col_entry_id + 8) % 16] = Mersenne::modp((sum >> 32) + delta);

                            sum = -2 * (tmp1 & 0xFFFF0000FFFF0000) + 4 * ((tmp2 & 0xFFFF0000FFFF0000) + (tmp3 & 0xFFFF0000FFFF0000)) - 8 * (tmp4 & 0xFFFF0000FFFF0000) + addition;
                            eval_result[row_entry_id + 4][col_entry_id + 4] = Mersenne::modp((sum & 0xFFFFFFFF) + delta);
                            eval_result[row_entry_id + 12][(col_entry_id + 12) % 16] = Mersenne::modp((sum >> 32) + delta);

                            break;
                        }

                        case 1: {
                            switch(col_entry_id % 4) {
                                // g_2 * h_1 = bcd(1−2e)(1−2f) = bcd - 2bcde - 2bcdf + 4bcdef
                                case 0:
                                    tmp1 = b_block & c_block & d_block;
                                    break;
                                // g_2 * h_2 = cd(1−2e)(1−2f) = cd - 2cde - 2cdf + 4cdef
                                case 1:
                                    tmp1 = c_block & d_block;
                                    break; 
                                // g_2 * h_3 = bc(1−2e)(1−2f) = bc - 2bce - 2bcf + 4bcef
                                case 2:
                                    tmp1 = b_block & c_block;
                                    break; 
                                case 3:
                                    // g_2 * h_3 = c(1−2e)(1−2f) = c - 2ce - 2cf + 4cef
                                    tmp1 = c_block;
                                    break; 
                            }
                            tmp2 = tmp1 & e_block;
                            tmp3 = tmp1 & f_block;
                            tmp4 = tmp2 & f_block;
                            
                            Field sum = (tmp1 & 0x0000FFFF0000FFFF) - 2 * ((tmp2 & 0x0000FFFF0000FFFF) + (tmp3 & 0x0000FFFF0000FFFF)) + 4 * (tmp4 & 0x0000FFFF0000FFFF) + addition;
                            eval_result[row_entry_id][col_entry_id] = Mersenne::modp((sum & 0xFFFFFFFF) + delta);
                            eval_result[row_entry_id + 8][(col_entry_id + 8) % 16] = Mersenne::modp((sum >> 32) + delta);

                            sum = (tmp1 & 0xFFFF0000FFFF0000) - 2 * ((tmp2 & 0xFFFF0000FFFF0000) + (tmp3 & 0xFFFF0000FFFF0000)) + 4 * (tmp4 & 0xFFFF0000FFFF0000) + addition;
                            eval_result[row_entry_id + 4][col_entry_id + 4] = Mersenne::modp((sum & 0xFFFFFFFF) + delta);
                            eval_result[row_entry_id + 12][(col_entry_id + 12) % 16] = Mersenne::modp((sum >> 32) + delta);

                            break;
                        }

                        case 2: {
                            switch(col_entry_id % 4) {
                                // g_3 * h_1 = abd(1−2e)(1−2f) = abd - 2abde - 2abdf + 4abdef
                                case 0:
                                    tmp1 = a_block & b_block;
                                    break;
                                // g_3 * h_2 = ad(1−2e)(1−2f) = ad - 2ade - 2adf + 4adef
                                case 1:
                                    tmp1 = a_block & d_block;
                                    break; 
                                // g_3 * h_3 = ab(1−2e)(1−2f) = ab - 2abe - 2abf + 4abef
                                case 2:
                                    tmp1 = a_block & b_block;
                                    break; 
                                // g_3 * h_4 = a(1−2e)(1−2f) = a - 2ae - 2af + 4aef
                                case 3:
                                    tmp1 = a_block;
                                    break; 
                            }
                            tmp2 = tmp1 & e_block;
                            tmp3 = tmp1 & f_block;
                            tmp4 = tmp2 & f_block;
                            
                            Field sum = (tmp1 & 0x0000FFFF0000FFFF) - 2 * ((tmp2 & 0x0000FFFF0000FFFF) + (tmp3 & 0x0000FFFF0000FFFF)) + 4 * (tmp4 & 0x0000FFFF0000FFFF) + addition;
                            eval_result[row_entry_id][col_entry_id] = Mersenne::modp((sum & 0xFFFFFFFF) + delta);
                            eval_result[row_entry_id + 8][(col_entry_id + 8) % 16] = Mersenne::modp((sum >> 32) + delta);

                            sum = (tmp1 & 0xFFFF0000FFFF0000) - 2 * ((tmp2 & 0xFFFF0000FFFF0000) + (tmp3 & 0xFFFF0000FFFF0000)) + 4 * (tmp4 & 0xFFFF0000FFFF0000) + addition;
                            eval_result[row_entry_id + 4][col_entry_id + 4] = Mersenne::modp((sum & 0xFFFFFFFF) + delta);
                            eval_result[row_entry_id + 12][(col_entry_id + 12) % 16] = Mersenne::modp((sum >> 32) + delta);

                            break;
                        }

                        case 3: {
                            switch(col_entry_id % 4) {
                                // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (-1/2) * bd + bde + bdf - 2bdef
                                // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (bd - 2bde - 2bdf + 4bdef) * (-1/2)
                                case 0:
                                    tmp1 = b_block & d_block;
                                    break;
                                // g_4 * h_2 = d(1−2e)(1−2f) * (-1/2) = (-1/2) * d + de + df - 2def
                                case 1:
                                    tmp1 = d_block;
                                    break; 
                                // g_4 * h_3 = b(1−2e)(1−2f) * (-1/2) = (-1/2) * b + be + bf - 2bef
                                case 2:
                                    tmp1 = b_block;
                                    break; 
                                // g_4 * h_4 = (1−2e)(1−2f) * (-1/2) = (-1/2) + e + f - 2ef
                                case 3:
                                    tmp1 = 1;
                                    break; 
                            }
                            tmp2 = tmp1 & e_block;
                            tmp3 = tmp1 & f_block;
                            tmp4 = tmp2 & f_block;
                            
                            Field sum = (tmp1 & 0x0000FFFF0000FFFF) - 2 * ((tmp2 & 0x0000FFFF0000FFFF) + (tmp3 & 0x0000FFFF0000FFFF)) + 4 * (tmp4 & 0x0000FFFF0000FFFF) + addition;
                            eval_result[row_entry_id][col_entry_id] = Mersenne::mul(neg_two_inverse, Mersenne::modp((sum & 0xFFFFFFFF) + delta));
                            eval_result[row_entry_id + 8][(col_entry_id + 8) % 16] = Mersenne::mul(neg_two_inverse, Mersenne::modp((sum >> 32) + delta));

                            sum = (tmp1 & 0xFFFF0000FFFF0000) - 2 * ((tmp2 & 0xFFFF0000FFFF0000) + (tmp3 & 0xFFFF0000FFFF0000)) + 4 * (tmp4 & 0xFFFF0000FFFF0000) + addition;
                            eval_result[row_entry_id + 4][col_entry_id + 4] = Mersenne::mul(neg_two_inverse, Mersenne::modp((sum & 0xFFFFFFFF) + delta));
                            eval_result[row_entry_id + 12][(col_entry_id + 12) % 16] = Mersenne::mul(neg_two_inverse, Mersenne::modp((sum >> 32) + delta));

                            break;
                        }
                    }
                } // end col_entry_id loop
            } // end rotation loop
        } // end row_entry_id loop
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
    cout << "First round (compute p evals) uses: " << (end - start).count() / 1e6 << " ms" << endl;

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

    // new matrix: total size = s * 4 = 80w, number of rows: k2 = 8, number of cols: 80w / 8 = 10w

    // generate two lookup tables
    // uint64_t bits_num = quarter_k / 2 * 3;

    // k = 16, still 12 bits deciding g_i or h_i, eval_base turns to be of size 16

    uint64_t table_size = 1 << 12;
    Field* input_left_table = new Field[table_size]; 
    Field* input_right_table = new Field[table_size]; 
    // bool* ace_bits = new bool[bits_num];

    for (uint64_t i = 0; i < table_size; i++) { 
        // i = 000000000000, ..., 111111111111 
        uint128_t left_sum = 0, right_sum = 0, tmp;
        int id = 0;
        for (uint64_t j = 0; j < 4; j++) {
            bool ab = i & (1 << j * 3);
            bool cd = i & (1 << (j * 3 + 1));
            bool ef = i & (1 << (j + 3 + 2));

            left_sum += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id]): 0;
            right_sum += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;
            id++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;
            left_sum += tmp;
            right_sum += tmp;
            id++;

            tmp = ab ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;
            left_sum += tmp;
            right_sum += tmp;
            id++;

            left_sum += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id];
            right_sum += ef ? Mersenne::neg(eval_base[id]) : eval_base[id];
            id++;
        }
        input_left_table[i] = Mersenne::modp_128(left_sum);
        input_right_table[i] = Mersenne::modp_128(right_sum);
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    // Asuming k = 16

    long* mask_table = new long[16];
    for (int i = 0; i < 16; i++) {
        long sum = 0;
        sum ^= (long)1 << i;
        sum ^= (long)1 << (i + 16);
        sum ^= (long)1 << (i + 32);
        sum ^= (long)1 << (i + 48);
        mask_table[i] = sum;
    }

    for (uint64_t block_id = 0; block_id < total_blocks_num; block_id++) {
        // cout << "block_id: " << block_id << endl;
        // fetch 1 block, containing BLOCKSIZE bit tuples
        memcpy(cur_block, share_tuple_blocks + start_point + block_id, sizeof(ShareTupleBlock));
        
        long a_block = cur_block[0].input1.first;
        long c_block = cur_block[0].input2.first;
        long e_block = (a_block & c_block) ^ cur_block[0].result.first ^ cur_block[0].rho.first;
                                            
        long b_block = cur_block[0].input2.second;
        long d_block = cur_block[0].input1.second;
        long f_block = cur_block[0].rho.second;

        for (int l = 0; l < 16; l++) {
            int row = index / s;
            int col = index % s;
            if (index >= s0) {
                // cout << "cp 4" << endl;
                if ((uint64_t)row == k2) 
                    break;
                else 
                    input_left[row][col] = input_right[row][col] = 0;
            }
            else {
                uint64_t left_id = 0, right_id = 0;

                long a_col = a_block & mask_table[l];
                long c_col = c_block & mask_table[l];
                long e_col = e_block & mask_table[l];

                long b_col = b_block & mask_table[l];
                long d_col = d_block & mask_table[l];
                long f_col = f_block & mask_table[l];

                if (l == 0) 
                    left_id = (a_col ^ (c_col << 1) ^ (e_col << 2)) % ((1 << 13) - 1); 
                else if (l == 1) 
                    left_id = ((a_col >> 1) ^ c_col ^ (e_col << 1)) % ((1 << 13) - 1);
                else 
                    left_id = ((a_col >> l) ^ (c_col >> (l - 1)) ^ (e_col >> (l - 2))) % ((1 << 13) - 1); 

                if (l == 0) 
                    right_id = (b_col ^ (d_col << 1) ^ (f_col << 2)) % ((1 << 13) - 1); 
                else if (l == 1) 
                    right_id = ((b_col >> 1) ^ d_col ^ (f_col << 1)) % ((1 << 13) - 1);
                else
                    right_id = ((b_col >> l) ^ (d_col >> (l - 1)) ^ (f_col >> (l - 2))) % ((1 << 13) - 1); 

                // cout << "l: " << l << endl;
                // cout << "left_id: " << left_id << endl;
                // cout << "right_id: " << right_id << endl;
                
                input_left[row][col] = Mersenne::mul(input_left_table[left_id], two_powers);
                input_right[row][col] = Mersenne::mul(input_right_table[right_id], two_powers);
            }
            index++;
        }
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
    // uint64_t k = OnlineOptions::singleton.k_size;
    uint64_t k = 16;
    uint64_t k2 = OnlineOptions::singleton.k2_size;

    uint64_t k_max = k > k2 ? k : k2;

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
    uint64_t two_powers = (0xFFFF - 1) * 4;
    bool prev_party = ((int64_t)(party_ID + 1 - prover_ID)) % 3 == 0;
    if(prev_party) {
        out_ss = Mersenne::mul(neg_two_inverse, two_powers * batch_size);
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
    uint64_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;

    ShareTupleBlock* cur_block = new ShareTupleBlock[1];

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

    // generate two lookup tables
    uint64_t table_size = 1 << 12;
    Field* input_table = new Field[table_size]; 

    auto start = std::chrono::high_resolution_clock::now(), end = start;

    // uint32_t* shift_table = new uint32_t[quarter_k / 2 * 3];
    // for (int i = 0; i < quarter_k / 2 * 3; i++) {
    //     shift_table[i] = 1 << i;
    // }

    long* mask_table = new long[16];
    for (int i = 0; i < 16; i++) {
        long sum = 0;
        sum ^= (long)1 << i;
        sum ^= (long)1 << (i + 16);
        sum ^= (long)1 << (i + 32);
        sum ^= (long)1 << (i + 48);
        mask_table[i] = sum;
    }

    if (prev_party) {
        
        for (uint64_t i = 0; i < table_size; i++) { 
            uint128_t left_sum = 0;
            int id = 0;
            for (uint64_t j = 0; j < 4; j++) {
                bool ab = i & (1 << j * 3);
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j + 3 + 2));

                left_sum += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id]): 0;
                id++;

                left_sum += cd ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;
                id++;

                left_sum += ab ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;;
                id++;

                left_sum += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id];
                id++;
            }
            input_table[i] = Mersenne::modp_128(left_sum);
        }

        end = std::chrono::high_resolution_clock::now();
        cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();

        for (uint64_t block_id = 0; block_id < total_blocks_num; block_id++) {
            // cout << "block_id: " << block_id << endl;
            // fetch 1 block, containing BLOCKSIZE bit tuples
            memcpy(cur_block, share_tuple_blocks + start_point + block_id, sizeof(ShareTupleBlock));
            
            long a_block = cur_block[0].input1.first;
            long c_block = cur_block[0].input2.first;
            long e_block = (a_block & c_block) ^ cur_block[0].result.first ^ cur_block[0].rho.first;

            for (int l = 0; l < 16; l++) {
                int row = index / s;
                int col = index % s;
                if (index >= s0) {
                    // cout << "cp 4" << endl;
                    if ((uint64_t)row == k2) 
                        break;
                    else 
                        input[row][col] = 0;
                }
                else {
                    uint64_t left_id = 0;

                    long a_col = a_block & mask_table[l];
                    long c_col = c_block & mask_table[l];
                    long e_col = e_block & mask_table[l];

                    if (l == 0) 
                        left_id = (a_col ^ (c_col << 1) ^ (e_col << 2)) % ((1 << 13) - 1); 
                    else if (l == 1) 
                        left_id = ((a_col >> 1) ^ c_col ^ (e_col << 1)) % ((1 << 13) - 1);
                    else 
                        left_id = ((a_col >> l) ^ (c_col >> (l - 1)) ^ (e_col >> (l - 2))) % ((1 << 13) - 1); 

                    input[row][col] = Mersenne::mul(input_table[left_id], two_powers);
                }
                index++;
            }
        }
    }
    else {

        for (uint64_t i = 0; i < table_size; i++) { 
            uint128_t right_sum = 0;
            int id = 0;
            for (uint64_t j = 0; j < 4; j++) {
                bool ab = i & (1 << j * 3);
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j + 3 + 2));

                right_sum += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;
                id++;

                right_sum += cd ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;
                id++;

                right_sum += ab ? (ef ? Mersenne::neg(eval_base[id]) : eval_base[id]) : 0;;
                id++;

                right_sum += ef ? Mersenne::neg(eval_base[id]) : eval_base[id];
                id++;
            }
            input_table[i] = Mersenne::modp_128(right_sum);
        }

        end = std::chrono::high_resolution_clock::now();
        cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();

        for (uint64_t block_id = 0; block_id < total_blocks_num; block_id++) {
            // cout << "block_id: " << block_id << endl;
            // fetch 1 block, containing BLOCKSIZE bit tuples
            memcpy(cur_block, share_tuple_blocks + start_point + block_id, sizeof(ShareTupleBlock));
            
            long b_block = cur_block[0].input2.second;
            long d_block = cur_block[0].input1.second;
            long f_block = cur_block[0].rho.second;

            for (int l = 0; l < 16; l++) {
                int row = index / s;
                int col = index % s;
                if (index >= s0) {
                    // cout << "cp 4" << endl;
                    if ((uint64_t)row == k2) 
                        break;
                    else 
                        input[row][col] = 0;
                }
                else {
                    uint64_t right_id = 0;

                    long b_col = b_block & mask_table[l];
                    long d_col = d_block & mask_table[l];
                    long f_col = f_block & mask_table[l];

                    if (l == 0) 
                        right_id = (b_col ^ (d_col << 1) ^ (f_col << 2)) % ((1 << 13) - 1); 
                    else if (l == 1) 
                        right_id = ((b_col >> 1) ^ d_col ^ (f_col << 1)) % ((1 << 13) - 1);
                    else
                        right_id = ((b_col >> l) ^ (d_col >> (l - 1)) ^ (f_col >> (l - 2))) % ((1 << 13) - 1); 

                    input[row][col] = Mersenne::mul(input_table[right_id], two_powers);
                }
                index++;
            }
        }
        
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "First round (compute new inputs) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

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

    end = std::chrono::high_resolution_clock::now();
    cout << "Recursion uses: " << (end - start).count() / 1e6 << " ms" << endl;
    
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
