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
    uint64_t k = OnlineOptions::singleton.k_size;
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

    ShareTupleBlock quarter_k_blocks[k];
    // works for binary_batch_size % BLOCK_SIZE = 0
    size_t start_point = (node_id % (ZOOM_RATE * OnlineOptions::singleton.max_status)) * OnlineOptions::singleton.binary_batch_size / BLOCK_SIZE;
    uint64_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    int cur_quarter_k_blocks_id = 0;
    uint64_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    // assuming k % 4 = 0
    uint64_t quarter_k = k / 4;
    uint64_t two_powers = (0xFFFF - 1) * 4;
    // cout << "block_cols_num: " << block_cols_num << endl;
    // cout << "total_blocks_num: " << total_blocks_num << endl;

    for (uint64_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {
        // cout << "block_col_id: " << block_col_id << endl;
        // fetch k tuple_blocks
        memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * min(quarter_k, total_blocks_num - cur_quarter_k_blocks_id));
        for(uint64_t i = 0; i < quarter_k; i++) { 
            // cout << "i:" << i << endl;
            // i = 0, ..., 3

            ShareTupleBlock row_block = quarter_k_blocks[i];
            long a = row_block.input1.first;
            long c = row_block.input2.first;
            long e = (a & c) ^ row_block.result.first ^ row_block.rho.first;
            
            for(uint64_t j = 0; j < quarter_k; j++) {  
                // cout << "j: " << j << endl;

                // uint64_t col_group_id =  j / 4;
                // uint64_t col_entry_id = j % 4;

                if (cur_quarter_k_blocks_id + i >= total_blocks_num || cur_quarter_k_blocks_id + j >= total_blocks_num) {
                    // cout << "continue, > total_blocks_num " << j << endl;
                    continue;
                }

                ShareTupleBlock col_block = quarter_k_blocks[j];
                    
                long b = col_block.input2.second;
                long d = col_block.input1.second;
                long f = col_block.rho.second;
                
                // group_id = 0, 1, 2, 3
                for(uint64_t row_entry_id = 0; row_entry_id < 4; row_entry_id++) {
                    for(uint64_t col_entry_id = 0; col_entry_id < 4; col_entry_id++) {
                        Field sum = 0;
                        long tmp1 = 0, tmp2, tmp3, tmp4;
                        switch(row_entry_id) {
                            case 0: {
                                switch(col_entry_id) {
                                    // g_1 * h_1 = -2abcd(1-2e)(1-2f) = -2abcd + 4abcde + 4abcdf - 8abcdef
                                    case 0:
                                        tmp1 = a & b & c & d;
                                        break;
                                    // g_1 * h_2 = -2acd(1-2e)(1-2f) = -2acd + 4acde + 4acdf - 8acdef
                                    case 1:
                                        tmp1 = a & c & d;
                                        break;
                                    // g_1 * h_3 = -2abc(1-2e)(1-2f) = -2abc + 4abce + 4abcf - 8abcef
                                    case 2:
                                        tmp1 = a & b & c;
                                        break; 
                                    // g_1 * h_4 = -2ac(1-2e)(1-2f) = -2ac + 4ace + 4acf - 8acef
                                    case 3:
                                        tmp1 = a & c;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                                for (int group_id = 0; group_id < 4; group_id++) {
                                    // group_id * 16 = 0, 16, 32, 48
                                    long mask = 0xFFFF << (group_id * 16);
                                    sum += Mersenne::neg(2 * (tmp1 & mask));
                                    sum += 4 * (tmp2 & mask);
                                    sum += 4 * (tmp3 & mask);
                                    sum += Mersenne::neg(8 * (tmp4 & mask));
                                }
                                break;
                            }
                            case 1: {
                                switch(col_entry_id) {
                                    // g_2 * h_1 = bcd(1−2e)(1−2f) = bcd - 2bcde - 2bcdf + 4bcdef
                                    case 0:
                                        tmp1 = b & c & d;
                                        break;
                                    // g_2 * h_2 = cd(1−2e)(1−2f) = cd - 2cde - 2cdf + 4cdef
                                    case 1:
                                        tmp1 = c & d;
                                        break; 
                                    // g_2 * h_3 = bc(1−2e)(1−2f) = bc - 2bce - 2bcf + 4bcef
                                    case 2:
                                        tmp1 = b & c;
                                        break; 
                                    case 3:
                                        // g_2 * h_3 = c(1−2e)(1−2f) = c - 2ce - 2cf + 4cef
                                        tmp1 = c;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                                for (int group_id = 0; group_id < 4; group_id++) {
                                    long mask = 0xFFFF << (group_id * 16);
                                    sum += tmp1 & mask;
                                    sum += Mersenne::neg(2 * (tmp2 & mask));
                                    sum += Mersenne::neg(2 * (tmp3 & mask));
                                    sum += 4 * (tmp4 & mask);
                                }
                                break;
                            }
                            case 2: {
                                switch(col_entry_id) {
                                    // g_3 * h_1 = abd(1−2e)(1−2f) = abd - 2abde - 2abdf + 4abdef
                                    case 0:
                                        tmp1 = a & b;
                                        break;
                                    // g_3 * h_2 = ad(1−2e)(1−2f) = ad - 2ade - 2adf + 4adef
                                    case 1:
                                        tmp1 = a & d;
                                        break; 
                                    // g_3 * h_3 = ab(1−2e)(1−2f) = ab - 2abe - 2abf + 4abef
                                    case 2:
                                        tmp1 = a & b;
                                        break; 
                                    // g_3 * h_4 = a(1−2e)(1−2f) = a - 2ae - 2af + 4aef
                                    case 3:
                                        tmp1 = a;
                                        break; 
                                }
                                break; 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                                for (int group_id = 0; group_id < 4; group_id++) {
                                    long mask = 0xFFFF << (group_id * 16);
                                    sum = tmp1 & mask;
                                    sum += Mersenne::neg(2 * (tmp2 & mask));
                                    sum += Mersenne::neg(2 * (tmp3 & mask));
                                    sum += 4 * (tmp4 & mask);
                                }
                                break;
                            }
                                
                            case 3: {
                                switch(col_entry_id) {
                                    // g_4 * h_1 = bd(1−2e)(1−2f) * (-1/2) = (-1/2) * bd + bde + bdf - 2bdef
                                    case 0:
                                        tmp1 = a & b;
                                        break;
                                    // g_4 * h_2 = d(1−2e)(1−2f) * (-1/2) = (-1/2) * d + de + df - 2def
                                    case 1:
                                        tmp1 = d;
                                        break; 
                                    // g_4 * h_3 = b(1−2e)(1−2f) * (-1/2) = (-1/2) * b + be + bf - 2bef
                                    case 2:
                                        tmp1 = a & b;
                                        break; 
                                    // g_4 * h_4 = (1−2e)(1−2f) * (-1/2) = (-1/2) + e + f - 2ef
                                    case 3:
                                        tmp1 = 1;
                                        break; 
                                } 
                                tmp2 = tmp1 & e;
                                tmp3 = tmp1 & f;
                                tmp4 = tmp2 & f;
                                for (int group_id = 0; group_id < 4; group_id++) {
                                    // TODO: see if using array to store masks will be better
                                    long mask = 0xFFFF << (group_id * 16);
                                    sum += Mersenne::mul(neg_two_inverse, (tmp1 & mask));
                                    sum += tmp2 & mask;
                                    sum += tmp3 & mask;
                                    sum += Mersenne::neg(2 * (tmp4 & mask));
                                }
                                break; 
                            }
                        } 
                        eval_result[i * 4 + row_entry_id][j * 4 + col_entry_id] += Mersenne::modp(sum);
                        eval_result[i * 4 + row_entry_id][j * 4 + col_entry_id] += Mersenne::modp(sum);
                    }
                }
            }
        }
        cur_quarter_k_blocks_id += quarter_k;
    }

    // uint64_t two_powers = (0xFFFFFFFF - 1) * 2 * block_cols_num;
    // Field extra_addition = Mersenne::mul(neg_two_inverse, two_powers);

    // for(uint64_t i = 0; i < k; i++) {
    //     for(uint64_t j = 0; j < k; j++) {
    //         eval_result[i][j] = Mersenne::add(eval_result[i][j], extra_addition);
    //     }
    // }

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
    cur_quarter_k_blocks_id = 0;

    // new matrix: total size = s * 4 = 80w, number of rows: k2 = 8, number of cols: 80w / 8 = 10w

    // generate two lookup tables
    // uint64_t bits_num = quarter_k / 2 * 3;

    uint64_t table_size = 1 << (quarter_k / 2 * 3);
    Field* input_left_table1 = new Field[table_size]; 
    Field* input_left_table2 = new Field[table_size];
    Field* input_right_table1 = new Field[table_size]; 
    Field* input_right_table2 = new Field[table_size];
    // bool* ace_bits = new bool[bits_num];

    for (uint64_t i = 0; i < table_size; i++) { 
        // i = 0, ..., 4095, 000000000000, ..., 111111111111, each i represents a combination of the 12 bits e^(4),c^(4),a^(4), ..., e^(1),c^(1),a^(1)
        // 12 bits for e^(4),e^(3),e^(2),e^(1), ..., a^(4),a^(3),a^(2),a^(1)
        // for (uint64_t j = 0; j < bits_num; j++) {
        //     ace_bits[j] = i & (1 << j);
        // }

        uint128_t left_sum1 = 0, left_sum2 = 0, right_sum1 = 0, right_sum2 = 0, tmp;
        int id1 = 0, id2 = quarter_k / 2;
        for (uint64_t j = 0; j < quarter_k / 2; j++) {
            // j = 0, 1, 2, 3
            // (e, c, a) = (bits_num[j * 3 + 2], bits_num[j * 3 + 1], bits_num[j * 3])
            // the same for (f, d, b)
            bool ab = i & (1 << j * 3);
            bool cd = i & (1 << (j * 3 + 1));
            bool ef = i & (1 << (j + 3 + 2));

            // left_sum1 += (ab & cd) ? ((ef ? 2 : neg_two) * eval_base[left_id1++]) : 0;
            // left_sum1 += cd ? (ef ? Mersenne::neg(eval_base[left_id1++]) : eval_base[left_id1++]) : 0;
            // left_sum1 += ab ? (ef ? Mersenne::neg(eval_base[left_id1++]) : eval_base[left_id1++]) : 0;
            // left_sum1 += (ef ? two_inverse : neg_two_inverse) * eval_base[left_id1++];

            // left_sum2 += (ab & cd) ? ((e ? 2 : neg_two) * eval_base[left_id2++]) : 0;
            // left_sum2 += cd ? (ef ? Mersenne::neg(eval_base[left_id2++]) : eval_base[left_id2++]) : 0;
            // left_sum2 += ab ? (ef ? Mersenne::neg(eval_base[left_id2++]) : eval_base[left_id2++]) : 0;
            // left_sum2 += (ef ? two_inverse : neg_two_inverse) * eval_base[left_id2++];

            // right_sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[right_id1++]) : eval_base[right_id1++]) : 0;
            // right_sum1 += cd ? (ef ? Mersenne::neg(eval_base[right_id1++]) : eval_base[right_id1++]) : 0;
            // right_sum1 += ab ? (ef ? Mersenne::neg(eval_base[right_id1++]) : eval_base[right_id1++]) : 0;
            // right_sum1 += (ef ? two_inverse : neg_two_inverse) * eval_base[right_id1++];

            // right_sum2 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[right_id2++]) : eval_base[right_id2++]) : 0;
            // right_sum2 += cd ? (ef ? Mersenne::neg(eval_base[right_id2++]) : eval_base[right_id2++]) : 0;
            // right_sum2 += ab ? (ef ? Mersenne::neg(eval_base[right_id2++]) : eval_base[right_id2++]) : 0;
            // right_sum2 += ef ? Mersenne::neg(eval_base[right_id2++]) : eval_base[right_id2++];

            left_sum1 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id1]): 0;
            right_sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            id1++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            left_sum1 += tmp;
            right_sum1 += tmp;
            id1++;

            tmp = ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
            left_sum1 += tmp;
            right_sum1 += tmp;
            id1++;

            left_sum1 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id1];
            right_sum1 += ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1];
            id1++;

            left_sum2 += (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
            right_sum2 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            id2++;

            tmp = cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            left_sum2 += tmp;
            right_sum2 += tmp;
            id2++;
            
            tmp = ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
            left_sum2 += tmp;
            right_sum2 += tmp;
            id2++;

            left_sum2 += (ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id2];
            right_sum2 += ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2];
            id2++;
        }
        input_left_table1[i] = Mersenne::modp_128(left_sum1);
        input_left_table2[i] = Mersenne::modp_128(left_sum2);
        input_right_table1[i] = Mersenne::modp_128(right_sum1);
        input_right_table2[i] = Mersenne::modp_128(right_sum2);
    }

    end = std::chrono::high_resolution_clock::now();
    cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

    start = std::chrono::high_resolution_clock::now();

    // Batchsize = 640w, total_blocks_num = 640w/64 = 10w, fetching k/4 = 8 blocks per time, needs 12500 times
    // k = 32, s = 640w/32 = 20w, block_cols_num = 20w/64 = 3125, totally 3125 cols of blocks, 3125 * 4  =  12500

    for (uint64_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {
        // cout << "block_col_id: " << block_col_id << endl;

        // fetch k/4 tuple_blocks, containing k * BLOCKSIZE bit tuples
        memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * min(quarter_k, total_blocks_num - cur_quarter_k_blocks_id));

        for (uint64_t i = 0; i < quarter_k / 2; i++) {
            // i = 0, 1, 2, 3; i + quarter_k / 2 = 4, 5, 6, 7
            // cout << "index: " << index << ", row: " << row << ", col: " << col << endl;                

            uint64_t left_id1 = 0, left_id2 = 0, right_id1 = 0, right_id2 = 0;
            ShareTupleBlock cur_block1 = quarter_k_blocks[i];
            ShareTupleBlock cur_block2 = quarter_k_blocks[i + quarter_k / 2];

            long a_block1 = cur_block1.input1.first;
            long c_block1 = cur_block1.input2.first;
            long e_block1 = (a_block1 & c_block1) ^ cur_block1.result.first ^ cur_block1.rho.first;
                                        
            long b_block1 = cur_block1.input2.second;
            long d_block1 = cur_block1.input1.second;
            long f_block1 = cur_block1.rho.second;

            long a_block2 = cur_block2.input1.first;
            long c_block2 = cur_block2.input2.first;
            long e_block2 = (a_block2 & c_block2) ^ cur_block2.result.first ^ cur_block2.rho.first;
                                        
            long b_block2 = cur_block2.input2.second;
            long d_block2 = cur_block2.input1.second;
            long f_block2 = cur_block2.rho.second;

            for (int l = 0; l < BLOCK_SIZE / 4; l++) {
                // l = 0, ..., 15
                for (int group_id = 0; group_id < 4; group_id++) {
                    // group_id = 0, 1, 2, 3

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
                        // group_id * 16  = 0, 16, 32, 48
                        // group_id * 16 + l  = 0 - 15, 16 - 31, 32 - 47, 48 - 63
                        bool a1 = a_block1 & (1 << (group_id * 16 + l));
                        bool c1 = c_block1 & (1 << (group_id * 16 + l));
                        bool e1 = e_block1 & (1 << (group_id * 16 + l));

                        bool b1 = b_block1 & (1 << (group_id * 16 + l));
                        bool d1 = d_block1 & (1 << (group_id * 16 + l));
                        bool f1 = f_block1 & (1 << (group_id * 16 + l));

                        if (a1) left_id1 ^= 1 << (i * 3);
                        if (c1) left_id1 ^= 1 << (i * 3 + 1);
                        if (e1) left_id1 ^= 1 << (i * 3 + 2);

                        if (b1) right_id1 ^= 1 << (i * 3);
                        if (d1) right_id1 ^= 1 << (i * 3 + 1);
                        if (f1) right_id1 ^= 1 << (i * 3 + 2);
                        
                        bool a2 = a_block2 & (1 << (group_id * 16 + l));
                        bool c2 = c_block2 & (1 << (group_id * 16 + l));
                        bool e2 = e_block2 & (1 << (group_id * 16 + l));

                        bool b2 = b_block2 & (1 << (group_id * 16 + l));
                        bool d2 = d_block2 & (1 << (group_id * 16 + l));
                        bool f2 = f_block2 & (1 << (group_id * 16 + l));

                        if (a2) left_id2 ^= 1 << (i * 3);
                        if (c2) left_id2 ^= 1 << (i * 3 + 1);
                        if (e2) left_id2 ^= 1 << (i * 3 + 2);

                        if (b2) right_id2 ^= 1 << (i * 3);
                        if (d2) right_id2 ^= 1 << (i * 3 + 1);
                        if (f2) right_id2 ^= 1 << (i * 3 + 2);

                        input_left[row][col] = Mersenne::mul(Mersenne::add(input_left_table1[left_id1], input_left_table2[left_id2]), two_powers);
                        input_right[row][col] = Mersenne::mul(Mersenne::add(input_right_table1[right_id1], input_right_table2[right_id2]), two_powers);
                    }
                    index++;
                }
            }
        }
        cur_quarter_k_blocks_id += quarter_k;
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

    uint64_t k_max = k > k2 ? k : k2;

    Field* eval_base = new Field[k_max];
    Field* eval_base_2k = new Field[2 * k_max - 1];    

    // ===============================  First Round  ===============================

    uint64_t T = ((batch_size - 1) / k + 1) * k;
    uint64_t s = (T - 1) / k + 1;
    uint64_t len = log(4 * s) / log(k2) + 2;
    uint64_t quarter_k = k / 4;

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
    uint64_t block_cols_num = (s - 1) / BLOCK_SIZE + 1;
    uint64_t total_blocks_num = (batch_size - 1) / BLOCK_SIZE + 1;
    int cur_quarter_k_blocks_id = 0;
    ShareTupleBlock quarter_k_blocks[k];

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

    cur_quarter_k_blocks_id = 0;

    // generate two lookup tables
    uint64_t table_size = 1 << (quarter_k / 2 * 3);
    Field* input_table1 = new Field[table_size]; 
    Field* input_table2 = new Field[table_size];

    auto start = std::chrono::high_resolution_clock::now(), end = start;

    // uint32_t* shift_table = new uint32_t[quarter_k / 2 * 3];
    // for (int i = 0; i < quarter_k / 2 * 3; i++) {
    //     shift_table[i] = 1 << i;
    // }

    if (prev_party) {
        for (uint64_t i = 0; i < table_size; i++) { 
            uint128_t sum1 = 0, sum2 = 0;
            int id1 = 0, id2 = quarter_k / 2;
            for (uint64_t j = 0; j < quarter_k / 2; j++) {
                bool ab = i & (1 << (j * 3));
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j * 3 + 2));

                sum1 = (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id1]) : 0;
                id1++;
                sum1 += cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;

                sum2 = (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
                id2++;
                sum2 += cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id1]) : 0;
                id2++;
                sum2 += ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1];
                id2++;
            }
            input_table1[i] = Mersenne::modp_128(sum1);
            input_table2[i] = Mersenne::modp_128(sum2);
        }

        end = std::chrono::high_resolution_clock::now();
        cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();

        for (uint64_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {
        // cout << "block_col_id: " << block_col_id << endl;

        // fetch k/4 tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * min(quarter_k, total_blocks_num - cur_quarter_k_blocks_id));

            for (uint64_t i = 0; i < quarter_k / 2; i++) {
                // i = 0, 1, 2, 3; i + quarter_k / 2 = 4, 5, 6, 7
                // cout << "index: " << index << ", row: " << row << ", col: " << col << endl;                

                uint64_t left_id1 = 0, left_id2 = 0;
                ShareTupleBlock cur_block1 = quarter_k_blocks[i];
                ShareTupleBlock cur_block2 = quarter_k_blocks[i + quarter_k / 2];

                long a_block1 = cur_block1.input1.first;
                long c_block1 = cur_block1.input2.first;
                long e_block1 = (a_block1 & c_block1) ^ cur_block1.result.first ^ cur_block1.rho.first;

                long a_block2 = cur_block2.input1.first;
                long c_block2 = cur_block2.input2.first;
                long e_block2 = (a_block2 & c_block2) ^ cur_block2.result.first ^ cur_block2.rho.first;

                for (int l = 0; l < BLOCK_SIZE / 4; l++) {
                    // l = 0, ..., 15
                    for (int group_id = 0; group_id < 4; group_id++) {
                        // group_id = 0, 1, 2, 3

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
                            // group_id * 16  = 0, 16, 32, 48
                            // group_id * 16 + l  = 0 - 15, 16 - 31, 32 - 47, 48 - 63
                            bool a1 = a_block1 & (1 << (group_id * 16 + l));
                            bool c1 = c_block1 & (1 << (group_id * 16 + l));
                            bool e1 = e_block1 & (1 << (group_id * 16 + l));

                            if (a1) left_id1 ^= 1 << (i * 3);
                            if (c1) left_id1 ^= 1 << (i * 3 + 1);
                            if (e1) left_id1 ^= 1 << (i * 3 + 2);
                            
                            bool a2 = a_block2 & (1 << (group_id * 16 + l));
                            bool c2 = c_block2 & (1 << (group_id * 16 + l));
                            bool e2 = e_block2 & (1 << (group_id * 16 + l));

                            if (a2) left_id2 ^= 1 << (i * 3);
                            if (c2) left_id2 ^= 1 << (i * 3 + 1);
                            if (e2) left_id2 ^= 1 << (i * 3 + 2);

                            input[row][col] = Mersenne::mul(Mersenne::add(input_table1[left_id1], input_table2[left_id2]), two_powers);
                        }
                        index++;
                    }
                }
            }
            cur_quarter_k_blocks_id += quarter_k;
        }
    }
    else {
        for (uint64_t i = 0; i < table_size; i++) { 
            Field sum1 = 0, sum2 = 0;
            int id1 = 0, id2 = quarter_k / 2;
            for (uint64_t j = 0; j < quarter_k / 2; j++) {
                bool ab = i & (1 << (j * 3));
                bool cd = i & (1 << (j * 3 + 1));
                bool ef = i & (1 << (j * 3 + 2));

                sum1 = (ab & cd) ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += cd ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += ab ? (ef ? Mersenne::neg(eval_base[id1]) : eval_base[id1]) : 0;
                id1++;
                sum1 += (ab & cd) ? ((ef ? (uint128_t)two_inverse : (uint128_t)neg_two_inverse) * eval_base[id1]) : 0;
                id1++;

                sum2 = (ab & cd) ? ((ef ? 2 : (uint128_t)neg_two) * eval_base[id2]) : 0;
                id2++;
                sum2 += cd ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2]) : 0;
                id2++;
                sum2 += ab ? (ef ? Mersenne::neg(eval_base[id2]) : eval_base[id1]) : 0;
                id2++;
                sum2 += ef ? Mersenne::neg(eval_base[id2]) : eval_base[id2];
                id2++;
            }
            input_table1[i] = Mersenne::modp_128(sum1);
            input_table2[i] = Mersenne::modp_128(sum2);
        }

        end = std::chrono::high_resolution_clock::now();
        cout << "First round (generate lookup tables) uses: " << (end - start).count() / 1e6 << " ms" << endl;

        start = std::chrono::high_resolution_clock::now();

        for (uint64_t block_col_id = 0; block_col_id < block_cols_num * 4; block_col_id ++) {
            // cout << "block_col_id: " << block_col_id << endl;

            // fetch k/4 tuple_blocks, containing k * BLOCKSIZE bit tuples
            memcpy(quarter_k_blocks, share_tuple_blocks + start_point + cur_quarter_k_blocks_id, sizeof(ShareTupleBlock) * min(quarter_k, total_blocks_num - cur_quarter_k_blocks_id));

            for (uint64_t i = 0; i < quarter_k / 2; i++) {
                // i = 0, 1, 2, 3; i + quarter_k / 2 = 4, 5, 6, 7
                // cout << "index: " << index << ", row: " << row << ", col: " << col << endl;                

                uint64_t right_id1 = 0, right_id2 = 0;
                ShareTupleBlock cur_block1 = quarter_k_blocks[i];
                ShareTupleBlock cur_block2 = quarter_k_blocks[i + quarter_k / 2];
                            
                long b_block1 = cur_block1.input2.second;
                long d_block1 = cur_block1.input1.second;
                long f_block1 = cur_block1.rho.second;
                             
                long b_block2 = cur_block2.input2.second;
                long d_block2 = cur_block2.input1.second;
                long f_block2 = cur_block2.rho.second;

                for (int l = 0; l < BLOCK_SIZE / 4; l++) {
                    // l = 0, ..., 15
                    for (int group_id = 0; group_id < 4; group_id++) {
                        // group_id = 0, 1, 2, 3

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
                            // group_id * 16  = 0, 16, 32, 48
                            // group_id * 16 + l  = 0 - 15, 16 - 31, 32 - 47, 48 - 63
                        
                            bool b1 = b_block1 & (1 << (group_id * 16 + l));
                            bool d1 = d_block1 & (1 << (group_id * 16 + l));
                            bool f1 = f_block1 & (1 << (group_id * 16 + l));

                            if (b1) right_id1 ^= 1 << (i * 3);
                            if (d1) right_id1 ^= 1 << (i * 3 + 1);
                            if (f1) right_id1 ^= 1 << (i * 3 + 2);
                            
                            bool b2 = b_block2 & (1 << (group_id * 16 + l));
                            bool d2 = d_block2 & (1 << (group_id * 16 + l));
                            bool f2 = f_block2 & (1 << (group_id * 16 + l));

                            if (b2) right_id2 ^= 1 << (i * 3);
                            if (d2) right_id2 ^= 1 << (i * 3 + 1);
                            if (f2) right_id2 ^= 1 << (i * 3 + 2);

                            input[row][col] = Mersenne::mul(Mersenne::add(input_table1[right_id1], input_table2[right_id2]), two_powers);
                        }
                        index++;
                    }
                }
            }
            cur_quarter_k_blocks_id += quarter_k;
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
