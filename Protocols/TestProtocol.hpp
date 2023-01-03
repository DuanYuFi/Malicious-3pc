
#ifndef PROTOCOLS_TESTPROTOCOL_HPP_
#define PROTOCOLS_TESTPROTOCOL_HPP_

#include "TestProtocol.h"
#include "Replicated.hpp"

#include "Tools/benchmarking.h"
#include "Tools/Bundle.h"

#include "global_debug.hpp"
#include <ctime>
#include <chrono>

template <class T>
TestProtocol<T>::TestProtocol(Player &P) : ReplicatedBase(P)
{
	assert(T::vector_length == 2);

    pointer = 0;
    pointer_answer = 0;
    iter = 0;

    batch_size = OnlineOptions::singleton.batch_size;
    ms = OnlineOptions::singleton.max_status;
    k = OnlineOptions::singleton.k_size;
    new_batch_size = batch_size * 2;
    
    X_prover = new VerifyRing[new_batch_size * ms * 2];     // only works when batch_size % k == 0, otherwise it need to be (new_batch_size + k) * ms
    Y_prover = new VerifyRing[new_batch_size * ms * 2];
    Y_right = new VerifyRing[new_batch_size * ms * 2];
    X_left = new VerifyRing[new_batch_size * ms * 2];
    _Z_left = new VerifyRing[batch_size * ms * 2];
    _Z_right = new VerifyRing[batch_size * ms * 2];
    E = new VerifyRing[batch_size * ms];                // uint64_t also works

    thread_buffer = new VerifyRing[new_batch_size * ms * 2];

    choices_left = new bool*[KAPPA];
    choices_right = new bool*[KAPPA];
    choices_prover = new bool*[KAPPA];

    for (int i = 0; i < KAPPA; i++) {
        choices_left[i] = new bool[batch_size];
        choices_right[i] = new bool[batch_size];
        choices_prover[i] = new bool[batch_size];
    }

    random_coef_left = new VerifyRing[KAPPA];
    random_coef_right = new VerifyRing[KAPPA];
    random_coef_prover = new VerifyRing[KAPPA];

    counter_prover = new VerifyRing[batch_size];
    counter_left = new VerifyRing[batch_size];
    counter_right = new VerifyRing[batch_size];

    Z_left = new VerifyRing[ms * 2];
    Z_right = new VerifyRing[ms * 2];

    coeffsX_prover = new VerifyRing[k * 2];
    coeffsY_prover = new VerifyRing[k * 2];
    coeffsX_left = new VerifyRing[k * 2];
    coeffsY_left = new VerifyRing[k * 2];
    coeffsX_right = new VerifyRing[k * 2];
    coeffsY_right = new VerifyRing[k * 2];

    local_left = new VerifyRing**[ms];
    local_right = new VerifyRing**[ms];

    for (int i = 0; i < ms; i ++) {
        local_left[i] = new VerifyRing*[k * 2];
        local_right[i] = new VerifyRing*[k * 2];
        for (int j = 0; j < 2 * k; j ++) {
            local_left[i][j] = new VerifyRing[k * 2];
            local_right[i][j] = new VerifyRing[k * 2];
        }
    }

    XY_mask_left = new VerifyRing[ms * 2 * 2];
    XY_mask_right = new VerifyRing[ms * 2 * 2];    
    XY_mask_prover = new VerifyRing[ms * 2 * 2];
    XY_mask_thread_buffer = new VerifyRing[ms * 2 * 2];

    Z_masks_left = new VerifyRing[ms * (2 * k + 1) * 2];
    Z_masks_right = new VerifyRing[ms * (2 * k + 1) * 2];
    Z_masks_prover = new VerifyRing[ms * (2 * k + 1) * 2];
    Z_masks_thread_buffer = new VerifyRing[ms * (2 * k + 1) * 2];

    // offset_data_xy = new_batch_size * ms;
    // offset_data_z = batch_size * ms;
    // offset_mono = ms;
    // offset_z_shares = ms * k * k;
    // offset_z_masks = ms * (2 * k + 1);

    cout << "Adding threads" << endl;

    // chatGPT taught me to do this. Brilliant
    for (int i = 0; i < OnlineOptions::singleton.thread_number; i++) {
        std::shared_ptr<std::thread> _thread(new std::thread(&TestProtocol<T>::verify_thread_handler, this));
        verify_threads.push_back(_thread);
    }

    cout << "Thread size: " << verify_threads.size() << endl;

    octetStream os;

    if (P.my_real_num() == 0) {
        global_prng.ReSeed();
        os.append(global_prng.get_seed(), SEED_SIZE);
        P.send_all(os);
    }
    else {
        P.receive_player(0, os);
        global_prng.SetSeed(os.get_data());
    }

    local_prng.ReSeed();

}


template<class T>
void TestProtocol<T>::init_mul() {

	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();

    verify_api();
}

template <class T>
void TestProtocol<T>::verify_part1(int batch_id) {

    for (int _ = 0; _ < KAPPA; _ ++) {

        VerifyRing e = 0;

        for (int i = 0; i < batch_size; i ++) {
            e += E[batch_id * batch_size + i] * choices_prover[_][i];
        }

        e = e >> 64;
        thread_buffer[batch_id * KAPPA + _] = e - thread_buffer[batch_id * KAPPA + _];
    }

    ++ ws;

}

template <class T>
void TestProtocol<T>::verify_part2(int batch_id) {

    VerifyRing *_Z = new VerifyRing[KAPPA];
    memset(_Z, 0, sizeof(VerifyRing) * KAPPA);

    for (int t = 0; t < KAPPA; t ++) {
        Z_right[batch_id] += (thread_buffer[batch_id * KAPPA + t] << 64) * random_coef_right[t];
    }

    for (int i = 0; i < batch_size; i ++) {
        Z_right[batch_id] += _Z_right[batch_id * batch_size + i] * counter_right[i];
    }

    ++ ws;
}

template <class T>
void TestProtocol<T>::verify_part3(int batch_id) {

    VerifyRing *_Z = new VerifyRing[KAPPA];
    memset(_Z, 0, sizeof(VerifyRing) * KAPPA);

    // Compute the RHS of poly in verifier left.
    for (int t = 0; t < KAPPA; t ++) {
        Z_left[batch_id] += (thread_buffer[batch_id * KAPPA + t] << 64) * random_coef_left[t];
    }

    for (int i = 0; i < batch_size; i ++) {
        Z_left[batch_id] += _Z_left[batch_id * batch_size + i] * counter_left[i];
    }

    // Compute the real items of the merged poly. We multiply the coefs into left. 
    for (int i = 0; i < batch_size; i ++) {
        X_prover[batch_id * new_batch_size + i * 2] *= counter_prover[i];
        X_prover[batch_id * new_batch_size + i * 2 + 1] *= counter_prover[i];
    
        X_left[batch_id * new_batch_size + i * 2] *= counter_left[i];
        X_left[batch_id * new_batch_size + i * 2 + 1] *= counter_left[i];
    }

    ++ ws;
}

template <class T>
void TestProtocol<T>::verify_part4(int batch_id) {

    // cout << "in verify_part4" << endl;

    for (int i = 0; i < k; i ++) {
        for (int j = 0; j < k; j ++) {
            if (i == 0 && j == 0) {
                continue;
            }
            thread_buffer[batch_id * k * k + i * k + j] = 
                inner_product(X_prover + batch_id * new_batch_size + i * vec_len, 
                              Y_prover + batch_id * new_batch_size + j * vec_len, 
                              vec_len)
                - thread_buffer[batch_id * k * k + i * k + j];

            thread_buffer[offset_z_shares + batch_id * k * k + i * k + j] = 
                    inner_product(X_prover + offset_data_xy + batch_id * new_batch_size + i * vec_len, 
                                Y_prover + offset_data_xy + batch_id * new_batch_size + j * vec_len, 
                                vec_len)
                    - thread_buffer[offset_z_shares + batch_id * k * k + i * k + j];
        }
    }

    if (vec_len == k) {
        XY_mask_prover[2 * batch_id] = local_prng.getDoubleWord();
        XY_mask_prover[2 * batch_id + 1] = local_prng.getDoubleWord();
        XY_mask_thread_buffer[2 * batch_id] = XY_mask_prover[2 * batch_id] - XY_mask_thread_buffer[2 * batch_id];
        XY_mask_thread_buffer[2 * batch_id + 1] = XY_mask_prover[2 * batch_id] - XY_mask_thread_buffer[2 * batch_id + 1];

        XY_mask_prover[offset_mono * 2 + 2 * batch_id] = local_prng.getDoubleWord();
        XY_mask_prover[offset_mono * 2 + 2 * batch_id + 1] = local_prng.getDoubleWord();
        XY_mask_thread_buffer[offset_mono * 2 + 2 * batch_id] = XY_mask_prover[offset_mono * 2 + 2 * batch_id] - XY_mask_thread_buffer[offset_mono * 2 + 2 * batch_id];
        XY_mask_thread_buffer[offset_mono * 2 + 2 * batch_id + 1] = XY_mask_prover[offset_mono * 2 + 2 * batch_id] - XY_mask_thread_buffer[offset_mono * 2 + 2 * batch_id + 1];

        int cur_offset_z_masks = batch_id * (2 * k + 1);
        int cur_offset_xy = batch_id * new_batch_size;
        // x_0 * y_0
        Z_masks_thread_buffer[cur_offset_z_masks] = XY_mask_prover[batch_id * 2] * XY_mask_prover[batch_id * 2 + 1] - Z_masks_thread_buffer[cur_offset_z_masks];
        Z_masks_thread_buffer[cur_offset_z_masks + offset_z_masks] = XY_mask_prover[offset_mono * 2 + batch_id * 2] * XY_mask_prover[offset_mono * 2 + batch_id * 2 + 1] - Z_masks_thread_buffer[cur_offset_z_masks];

        // x_0 * y_i, i = 1, ... k
        for (int i = 0; i < k; i++) {
            Z_masks_thread_buffer[cur_offset_z_masks + 1 + i] = XY_mask_prover[batch_id * 2] * X_prover[cur_offset_xy + i] - Z_masks_thread_buffer[cur_offset_z_masks + 1 + i];
            Z_masks_thread_buffer[cur_offset_z_masks + 1 + k + i] = XY_mask_prover[batch_id * 2 + 1] * Y_prover[cur_offset_xy + i] - Z_masks_thread_buffer[cur_offset_z_masks + 1 + k + i];
            Z_masks_thread_buffer[cur_offset_z_masks + offset_z_masks + 1 + i] = XY_mask_prover[offset_mono * 2 + batch_id * 2] * X_prover[cur_offset_xy + offset_data_xy + i] - Z_masks_thread_buffer[cur_offset_z_masks + offset_z_masks + 1 + i];
            Z_masks_thread_buffer[cur_offset_z_masks + offset_z_masks + 1 + k + i] = XY_mask_prover[offset_mono * 2 + batch_id * 2 + 1] * Y_prover[cur_offset_xy + offset_data_xy + i] - Z_masks_thread_buffer[cur_offset_z_masks + offset_z_masks + 1 + k + i];
        }
    }

    ++ ws;
}

template <class T>
void TestProtocol<T>::verify_part5(int batch_id) {

    // cout << "in verify_part5" << endl;

    VerifyRing res_left[k * 2], res_right[k * 2];
    int cur_offset_xy = batch_id * new_batch_size;
    int cur_offset_xy_2 = batch_id * new_batch_size + offset_data_xy;

    local_left[batch_id][0][0] = Z_left[batch_id];
    local_right[batch_id][0][0] = Z_right[batch_id];

    local_left[batch_id][k][k] = Z_left[offset_mono + batch_id];
    local_right[batch_id][k][k] = Z_right[offset_mono + batch_id];

    for (int i = 1; i < k; i ++) {
        local_left[batch_id][0][0] -= local_left[batch_id][i][i];
        local_right[batch_id][0][0] -= local_right[batch_id][i][i];

        local_left[batch_id][k][k] -= local_left[batch_id][k + i][k + i];
        local_right[batch_id][k][k] -= local_right[batch_id][k + i][k + i];
    }

    for (int j = 0; j < vec_len; j ++) {
        X_prover[cur_offset_xy + j] *= coeffsX_prover[0];
        Y_prover[cur_offset_xy + j] *= coeffsY_prover[0];
        X_left[cur_offset_xy + j] *= coeffsX_left[0];
        Y_right[cur_offset_xy + j] *= coeffsY_right[0];

        X_prover[cur_offset_xy_2 + j] *= coeffsX_prover[k];
        Y_prover[cur_offset_xy_2 + j] *= coeffsY_prover[k];
        X_left[cur_offset_xy_2 + j] *= coeffsX_left[k];
        Y_right[cur_offset_xy_2 + j] *= coeffsY_right[k];

    }

    for (int i = 1; i < k; i ++) {
        for (int j = 0; j < vec_len; j ++) {
            X_prover[cur_offset_xy + j] += X_prover[cur_offset_xy + j + i * vec_len] * coeffsX_prover[i];
            Y_prover[cur_offset_xy + j] += Y_prover[cur_offset_xy + j + i * vec_len] * coeffsY_prover[i];

            X_left[cur_offset_xy + j] += X_left[cur_offset_xy + j + i * vec_len] * coeffsX_left[i];
            Y_right[cur_offset_xy + j] += Y_right[cur_offset_xy + j + i * vec_len] * coeffsY_right[i];

            X_prover[cur_offset_xy_2 + j] += X_prover[cur_offset_xy_2 + j + i * vec_len] * coeffsX_prover[k + i];
            Y_prover[cur_offset_xy_2 + j] += Y_prover[cur_offset_xy_2 + j + i * vec_len] * coeffsY_prover[k + i];

            X_left[cur_offset_xy_2 + j] += X_left[cur_offset_xy_2 + j + i * vec_len] * coeffsX_left[k + i];
            Y_right[cur_offset_xy_2 + j] += Y_right[cur_offset_xy_2 + j + i * vec_len] * coeffsY_right[k + i];
        }
    }

    for (int i = 0; i < k; i ++) {
        X_prover[cur_offset_xy + vec_len + i] = 0;
        Y_prover[cur_offset_xy + vec_len + i] = 0;
        X_left[cur_offset_xy + vec_len + i] = 0;
        Y_right[cur_offset_xy + vec_len + i] = 0;

        X_prover[cur_offset_xy_2 + vec_len + i] = 0;
        Y_prover[cur_offset_xy_2 + vec_len + i] = 0;
        X_left[cur_offset_xy_2 + vec_len + i] = 0;
        Y_right[cur_offset_xy_2 + vec_len + i] = 0;
    }

    for (int i = 0; i < k; i ++) {
        res_left[i] = 0;
        res_right[i] = 0;

        res_left[k + i] = 0;
        res_right[k + i] = 0;

        for (int j = 0; j < k; j ++) {
            res_left[i] += coeffsY_left[j] * local_left[batch_id][i][j];
            res_right[i] += coeffsY_right[j] * local_right[batch_id][i][j];

            res_left[k + i] += coeffsY_left[k + j] * local_left[batch_id][k + i][k + j];
            res_right[k + i] += coeffsY_right[k + j] * local_right[batch_id][k + i][k + j];
        }
    }

    Z_left[batch_id] = Z_right[batch_id] = 0;
    Z_left[offset_mono + batch_id] = Z_right[offset_mono + batch_id] = 0;

    for (int i = 0; i < k; i ++) {
        Z_left[batch_id] += res_left[i] * coeffsX_left[i];
        Z_right[batch_id] += res_right[i] * coeffsX_right[i];

        Z_left[offset_mono + batch_id] += res_left[k + i] * coeffsX_left[k + i];
        Z_right[offset_mono + batch_id] += res_right[k + i] * coeffsX_right[k + i];
    }

    if (vec_len == 1) {
        X_left[cur_offset_xy] += XY_mask_left[2 * batch_id];
        Y_right[cur_offset_xy] += XY_mask_right[2 * batch_id + 1];
     
        X_left[cur_offset_xy_2] += XY_mask_left[offset_mono * 2 + 2 * batch_id];
        Y_right[cur_offset_xy_2] += XY_mask_right[offset_mono * 2 + 2 * batch_id + 1];
        

        for (int i = 0; i < 2 * k + 1; i++) {
            Z_left[batch_id] += Z_masks_left[batch_id * (2 * k + 1) + i];
            Z_left[offset_mono + batch_id] += Z_masks_left[offset_z_masks + batch_id * (2 * k + 1) + i];
        }
    }

    ++ ws;
}

// This solution is similar to Protocols/Malicious3PCProtocol.hpp, verify_thread_handler, verify_part1, verify_part2.
template<class T>
void TestProtocol<T>::verify_thread_handler() {

    MyPair<int, int> data;

    while (true) { 
        if (!cv.pop_dont_stop(data)) {
            continue;
        }

        // data = cv.pop();

#define PART(x)\
    case x: \
    verify_part ## x(data.second); \
    break

        switch (data.first) {
        PART(1);
        PART(2);
        PART(3);
        PART(4);
        PART(5);

        default:
            return ;
        }
    }
}

/*
 * TODO: parallel verify multiple batches.
 * 
 * There are four pass_arounds to do:
 *      1. pass around the random seed for random choices
 *      2. pass around the share_right
 *      3. in chop: inner_product and coefficients
 *      4. co-verify
 * 
 * According to our previous work, if we want to use multi-thread, we have to seperate the online and offline phase, 
 * because message cannot interact in multi-thread.
 * 
 */
template <class T>
void TestProtocol<T>::verify() {

    
    // Initialize
    Nbatches = (pointer_answer - 1) / batch_size + 1;
    ws.set_target(Nbatches);

    cout << "Nbatches: " << Nbatches << endl;

    offset_data_xy = new_batch_size * Nbatches;
    offset_data_z = batch_size * Nbatches;
    offset_mono = Nbatches;
    offset_z_shares = k * k * Nbatches;
    offset_z_masks = (2 * k + 1) * Nbatches;

    octet seed_left[SEED_SIZE], seed_right[SEED_SIZE], seed_prover[SEED_SIZE];

    // Prepare for the random seed and send to prover, which will be used to generate the random choices.
    // The random seed is sent from the left verifier. The right verifier will generate the same random seed.
    // Note: shared_prngs[1] is shared with the previous party. shared_prngs[0] is shared with the next party.
    //       The index is not the offset of the party.

    shared_prngs[1].get_octets(seed_left, SEED_SIZE);       // as Verifier left
    shared_prngs[0].get_octets(seed_right, SEED_SIZE);      // as Verifier right

    for (auto& o : os)
        o.reset_write_head();
    
    os[0].append(seed_left, SEED_SIZE);                     // send to Prover from Verifier left
    P.pass_around(os[0], os[1], 1);                         // offset is 1. At the same time, 'I' also plays the role of Prover to get 
                                                            // the random seed from Verifier left.

    os[1].consume(seed_prover, SEED_SIZE);

    PRNG choices_prng_left, choices_prng_right, choices_prng_prover;
    choices_prng_left.SetSeed(seed_left);
    choices_prng_right.SetSeed(seed_right);
    choices_prng_prover.SetSeed(seed_prover);

    // auto start = std::chrono::high_resolution_clock::now();
    // for (int i = 0; i < KAPPA; i++) {
    //     for (int j = 0; j < batch_size; j ++) {
    //         choices_left[i][j] = choices_prng_left.get_bit();           // low efficiency
    //         choices_right[i][j] = choices_prng_right.get_bit();
    //         choices_prover[i][j] = choices_prng_prover.get_bit();
    //     }
    // }
    // auto end = std::chrono::high_resolution_clock::now();
    // cout << "get_bit time: " << (end - start).count() / 1e6 << " ms" << endl;
    
    // start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < KAPPA; i++) {
        choices_prng_left.get_octets((octet*)choices_left[i], batch_size);
        choices_prng_right.get_octets((octet*)choices_right[i], batch_size);
        choices_prng_prover.get_octets((octet*)choices_prover[i], batch_size);
        for (int j = 0; j < batch_size; j++) {
            choices_left[i][j] &= 1;
        }
    }    
    // end = std::chrono::high_resolution_clock::now();
    // cout << "get_octets time: " << (end - start).count() / 1e6 << " ms" << endl;

    for (auto &o : os)
        o.reset_write_head();

    memset(counter_prover, 0, sizeof(VerifyRing) * batch_size);
    memset(counter_left, 0, sizeof(VerifyRing) * batch_size);
    memset(counter_right, 0, sizeof(VerifyRing) * batch_size);

    memset(Z_left, 0, sizeof(VerifyRing) * ms * 2);
    memset(Z_right, 0, sizeof(VerifyRing) * ms * 2);

    // seed for the random coefs.
    shared_prngs[1].get_octets(seed_left, SEED_SIZE);       // as Verifier left
    shared_prngs[0].get_octets(seed_right, SEED_SIZE);      // as Verifier right
    
    os[0].append(seed_left, SEED_SIZE); // should store the seed after passing around share of `e`

    // generate share_left because we cannot call random function in multi-thread.
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        for (int i = 0; i < KAPPA; i ++) {
            thread_buffer[batch_id * KAPPA + i] = shared_prngs[1].getDoubleWord();
        }
    }

    ws.reset();

    // part 1: compute share_right and send to verifier right. 
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        cv.push(MyPair<int, int>(1, batch_id));
    }
    
    ws.wait();

    // we cannot store the share_right to octetstream in multi-thread, so we store it to thread_buffer.
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        for (int i = 0; i < KAPPA; i ++) {
            os[0].store(thread_buffer[batch_id * KAPPA + i]);
        }
    }
 
    P.pass_around(os[0], os[1], 1);

    os[1].consume(seed_prover, SEED_SIZE);

    choices_prng_left.SetSeed(seed_left);
    choices_prng_right.SetSeed(seed_right);
    choices_prng_prover.SetSeed(seed_prover);

    // Now, thread_buffer stored the share_right. 
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        for (int i = 0; i < KAPPA; i ++) {
            os[1].get(thread_buffer[batch_id * KAPPA + i]);
        }
    }

    // The random_coefs can be used in every batch_id. 
    for (int i = 0; i < KAPPA; i ++) {
        random_coef_left[i] = choices_prng_left.getDoubleWord();
        random_coef_right[i] = choices_prng_right.getDoubleWord();
        random_coef_prover[i] = choices_prng_prover.getDoubleWord();
    }

    // Compute the real coefficient. Also they can be used in every batch_id.
    for (int i = 0; i < KAPPA; i ++) {
        for (int j = 0; j < batch_size; j ++) {
            counter_prover[j] += choices_prover[i][j] * random_coef_prover[i];
            counter_left[j] += choices_left[i][j] * random_coef_left[i];
            counter_right[j] += choices_right[i][j] * random_coef_right[i];
        }
    }


    ws.reset();
    
    // part 2: remember, the thread_buffer stored the share_right. So we firstly deal with verifier right.
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        cv.push(MyPair<int, int>(2, batch_id));
    }

    ws.wait();

    // Now, we deal with verifier left. Same as above, we have to generate the randoms outside the multi-thread.
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        for (int i = 0; i < KAPPA; i ++) {
            thread_buffer[batch_id * KAPPA + i] = shared_prngs[0].getDoubleWord();
        }
    }

    ws.reset();

    // part 3: deal with verifier left.
    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        cv.push(MyPair<int, int>(3, batch_id));
    }

    ws.wait();


    // preparation before chop
    s = new_batch_size;
    vec_len = (s - 1) / k + 1;

    // chop

    memcpy(X_prover + offset_data_xy, X_prover, sizeof(VerifyRing) * offset_data_xy);
    memcpy(Y_prover + offset_data_xy, Y_prover, sizeof(VerifyRing) * offset_data_xy);
    memcpy(Y_right + offset_data_xy, Y_right, sizeof(VerifyRing) * offset_data_xy);
    memcpy(X_left + offset_data_xy, X_left, sizeof(VerifyRing) * offset_data_xy);
    memcpy(_Z_left + offset_data_z, _Z_left, sizeof(VerifyRing) * offset_data_z);
    memcpy(_Z_right + offset_data_z, _Z_right, sizeof(VerifyRing) * offset_data_z);

    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) { 
        Z_left[offset_mono + batch_id] = Z_left[batch_id];
        Z_right[offset_mono + batch_id] = Z_right[batch_id];
    }

    while (true) {
 
        for (auto &o : os)
            o.reset_write_head();

        // thread_buffer stores random numbers with left.
        for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
            for (int i = 0; i < k; i ++) {
                for (int j = 0; j < k; j ++) {
                    if (i == 0 && j == 0) {  
                        continue;
                    }
                    thread_buffer[batch_id * k * k + i * k + j] = shared_prngs[1].getDoubleWord();
                    local_left[batch_id][i][j] = shared_prngs[0].getDoubleWord();

                    thread_buffer[offset_z_shares + batch_id * k * k + i * k + j] = shared_prngs[1].getDoubleWord();
                    local_left[batch_id][k + i][k + j] = shared_prngs[0].getDoubleWord();
                }
            }
        }

        if (vec_len == k) {
            for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
                XY_mask_thread_buffer[2 * batch_id] = shared_prngs[1].getDoubleWord();
                XY_mask_thread_buffer[2 * batch_id + 1] = shared_prngs[1].getDoubleWord();
                XY_mask_left[2 * batch_id] = shared_prngs[0].getDoubleWord();
                XY_mask_left[2 * batch_id + 1] = shared_prngs[0].getDoubleWord();

                XY_mask_thread_buffer[offset_mono * 2 + 2 * batch_id] = shared_prngs[1].getDoubleWord();
                XY_mask_thread_buffer[offset_mono * 2 + 2 * batch_id + 1] = shared_prngs[1].getDoubleWord();
                XY_mask_left[offset_mono * 2 + 2 * batch_id] = shared_prngs[0].getDoubleWord();
                XY_mask_left[offset_mono * 2 + 2 * batch_id + 1] = shared_prngs[0].getDoubleWord();

                for (int i = 0; i < 2 * k + 1; i++) {
                    Z_masks_thread_buffer[batch_id * (2 * k + 1) + i] = shared_prngs[1].getDoubleWord();
                    Z_masks_left[batch_id * (2 * k + 1) + i] = shared_prngs[0].getDoubleWord();

                    Z_masks_thread_buffer[offset_z_masks + batch_id * (2 * k + 1) + i] = shared_prngs[1].getDoubleWord();
                    Z_masks_left[offset_z_masks + batch_id * (2 * k + 1) + i] = shared_prngs[0].getDoubleWord();
                }
            }
        }

        ws.reset();
        for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
            cv.push(MyPair<int, int>(4, batch_id));
        }
        ws.wait();

        for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
            for (int i = 0; i < k; i ++) {
                for (int j = 0; j < k; j ++) {
                    if (i == 0 && j == 0) {
                        continue;
                    }
                    os[0].store(thread_buffer[batch_id * k * k + i * k + j]);
                    os[0].store(thread_buffer[offset_z_shares + batch_id * k * k + i * k + j]);
                }
            }
        }

        if (vec_len == k) {
            for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
                os[0].store(XY_mask_thread_buffer[batch_id * 2]);
                os[0].store(XY_mask_thread_buffer[batch_id * 2 + 1]);

                os[0].store(XY_mask_thread_buffer[offset_mono * 2 + batch_id * 2]);
                os[0].store(XY_mask_thread_buffer[offset_mono * 2 + batch_id * 2 + 1]);

                for (int i = 0; i < 2 * k + 1; i++) {
                    os[0].store(Z_masks_thread_buffer[batch_id * (2 * k + 1) + i]);
                    os[0].store(Z_masks_thread_buffer[offset_z_masks + batch_id * (2 * k + 1) + i]);
                }
            }
        }

        P.pass_around(os[0], os[1], 1);

        for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
            for (int i = 0; i < k; i ++) {
                for (int j = 0; j < k; j ++) {
                    if (i == 0 && j == 0) {
                        continue;
                    }
                    os[1].get(local_right[batch_id][i][j]);
                    os[1].get(local_right[batch_id][k + i][k + j]);
                }
            }
        }

        if (vec_len == k) {
            for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
                os[1].get(XY_mask_right[batch_id * 2]);
                os[1].get(XY_mask_right[batch_id * 2 + 1]);

                os[1].get(XY_mask_right[offset_mono * 2 + batch_id * 2]);
                os[1].get(XY_mask_right[offset_mono * 2 + batch_id * 2 + 1]);

                for (int i = 0; i < 2 * k + 1; i++) {
                    os[1].get(Z_masks_right[batch_id * (2 * k + 1) + i]);
                    os[1].get(Z_masks_right[offset_z_masks + batch_id * (2 * k + 1) + i]);
                }
            }
        }

        for (auto &o : os)
            o.reset_write_head();

        // should store the seed after passing around share of inner products. 
        for (int i = 0; i < k; i ++) {
            coeffsX_left[i] = shared_prngs[1].getDoubleWord();
            coeffsY_left[i] = shared_prngs[1].getDoubleWord();
            coeffsX_right[i] = shared_prngs[0].getDoubleWord();
            coeffsY_right[i] = shared_prngs[0].getDoubleWord();
            
            coeffsX_left[k + i] = shared_prngs[1].getDoubleWord();
            coeffsY_left[k + i] = shared_prngs[1].getDoubleWord();
            coeffsX_right[k + i] = shared_prngs[0].getDoubleWord();
            coeffsY_right[k + i] = shared_prngs[0].getDoubleWord();
            
            os[0].store(coeffsX_left[i]);
            os[0].store(coeffsY_left[i]);
            os[0].store(coeffsX_left[k + i]);
            os[0].store(coeffsY_left[k + i]);
        }

        P.pass_around(os[0], os[1], 1);

        for (int i = 0; i < k; i ++) {
            os[1].get(coeffsX_prover[i]);
            os[1].get(coeffsY_prover[i]);

            os[1].get(coeffsX_prover[k + i]);
            os[1].get(coeffsY_prover[k + i]);
        }

        ws.reset();
        for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
            cv.push(MyPair<int, int>(5, batch_id));
        }
        ws.wait();

        if (vec_len == 1) {
            break;
        }

        s = vec_len;
        vec_len = (s - 1) / k + 1;
        iter++;
    }

    for (auto &o : os)
        o.reset_write_head();

    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        os[0].store(XY_mask_right[2 * batch_id]);
        os[0].store(Y_right[new_batch_size * batch_id] + XY_mask_right[2 * batch_id + 1]);
        os[0].store(Z_right[batch_id]);

        os[0].store(XY_mask_right[offset_mono * 2 + 2 * batch_id]);
        os[0].store(Y_right[offset_data_xy + new_batch_size * batch_id] + XY_mask_right[offset_mono * 2 + 2 * batch_id + 1]);
        os[0].store(Z_right[offset_mono + batch_id]);
    }

    P.pass_around(os[0], os[1], 1);

    for (int batch_id = 0; batch_id < Nbatches; batch_id ++) {
        VerifyRing x, y, z, x2, y2, z2;
        os[1].get(x);
        os[1].get(y);
        os[1].get(z);
        os[1].get(x2);
        os[1].get(y2);
        os[1].get(z2);

        x += X_left[new_batch_size * batch_id];
        y += XY_mask_right[2 * batch_id + 1];
        z += Z_left[batch_id];

        x2 += X_left[offset_data_xy + new_batch_size * batch_id];
        y2 += XY_mask_right[offset_mono * 2 + 2 * batch_id + 1];
        z2 += Z_left[offset_mono + batch_id];

        if (x * y != z || x2 * y2 != z2) {
            throw mac_fail("ZKP check failed");
            // cout << "ZKP check failed" << endl;
        }
    }
}

template <class T>
void TestProtocol<T>::prepare_mul(const T& x, const T& y, int n) {
	
	typename T::value_type share = x.local_mul(y);

    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++)
        tmp[i].randomize(shared_prngs[i], n);
    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
    add_shares.push_back(tmp[0] + x[0] * y[0]);

    X_prover[pointer * 2] = (uint128_t) y[1].debug();
    X_prover[pointer * 2 + 1] = (uint128_t) x[1].debug();
    Y_prover[pointer * 2] = (uint128_t) x[0].debug();
    Y_prover[pointer * 2 + 1] = (uint128_t) y[0].debug();

    E[pointer] = X_prover[pointer * 2] * Y_prover[pointer * 2];
    E[pointer] += X_prover[pointer * 2 + 1] * Y_prover[pointer * 2 + 1];
    E[pointer] -= (uint128_t) (tmp[1].debug());

    Y_right[pointer * 2] = x[1].debug();
    Y_right[pointer * 2 + 1] = y[1].debug();
    _Z_right[pointer] = - x[1].debug() * y[1].debug() - tmp[1].debug();

    X_left[pointer * 2] = y[0].debug();
    X_left[pointer * 2 + 1] = x[0].debug();
    _Z_left[pointer] = tmp[0].debug();

    pointer ++;

}

template <class T>
void TestProtocol<T>::exchange() {

	if (os[0].get_length() > 0) {
        this->exchange_comm += os[0].get_length();
        P.pass_around(os[0], os[1], 1);
    }
        
    this->rounds++;
    
}

template <class T>
inline T TestProtocol<T>::finalize_mul(int n) {

    this->counter++;
    this->bit_counter += (n == -1 ? T::clear::length() : n);
    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);             // received from player i-1 and set it in index 1
                                            // so index 1 is shared with previous and index 0 is shared with next
                                            // which is the same as shared_prngs
    
    auto tmp0 = add_shares.next();

    E[pointer_answer] -= (uint128_t) (result[0].debug() - tmp0.debug());

    _Z_right[pointer_answer] = (uint64_t) result[1].debug() + (uint64_t) _Z_right[pointer_answer];

    pointer_answer++;

    return result;
}


template<class T>
inline void TestProtocol<T>::init_dotprod()
{
	init_mul();
    dotprod_share.assign_zero();

	
}

template<class T>
inline void TestProtocol<T>::prepare_dotprod(const T& x, const T& y)
{

	dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void TestProtocol<T>::next_dotprod()
{

	dotprod_share.normalize();
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++)
        tmp[i].randomize(shared_prngs[i], -1);
    auto add_share = dotprod_share + tmp[0] - tmp[1];
    add_share.pack(os[0], -1);
    add_shares.push_back(add_share);
    dotprod_share.assign_zero();
}

template<class T>
inline T TestProtocol<T>::finalize_dotprod(int length)
{
	(void) length;
    this->dot_counter++;
    return finalize_mul();
}

template<class T>
T TestProtocol<T>::get_random() {
	T res;
	for (int i = 0; i < 2; i++) {
		res[i].randomize(shared_prngs[i]);
	}
	return res;
}

template<class T>
template<class U>
void TestProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        false_type)
{
    assert(regs.size() % 4 == 0);
    assert(proc.P.num_players() == 3);
    assert(proc.Proc != 0);
    typedef typename T::clear value_type;
    int gen_player = 2;
    int comp_player = 1;
    bool generate = P.my_num() == gen_player;
    bool compute = P.my_num() == comp_player;
    ArgList<TruncPrTupleWithGap<value_type>> infos(regs);
    auto& S = proc.get_S();

    octetStream cs;
    ReplicatedInput<T> input(P);

    if (generate)
    {
        SeededPRNG G;
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto r = G.get<value_type>();
                input.add_mine(info.upper(r));
                if (info.small_gap())
                    input.add_mine(info.msb(r));
                (r + S[info.source_base + i][0]).pack(cs);
            }
        P.send_to(comp_player, cs);
    }
    else
        input.add_other(gen_player);

    if (compute)
    {
        P.receive_player(gen_player, cs);
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto c = cs.get<value_type>() + S[info.source_base + i].sum();
                input.add_mine(info.upper(c));
                if (info.small_gap())
                    input.add_mine(info.msb(c));
            }
    }

    input.add_other(comp_player);
    input.exchange();
    init_mul();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
        {
            this->trunc_pr_counter++;
            auto c_prime = input.finalize(comp_player);
            auto r_prime = input.finalize(gen_player);
            S[info.dest_base + i] = c_prime - r_prime;

            if (info.small_gap())
            {
                auto c_dprime = input.finalize(comp_player);
                auto r_msb = input.finalize(gen_player);
                S[info.dest_base + i] += ((r_msb + c_dprime)
                        << (info.k - info.m));
                prepare_mul(r_msb, c_dprime);
            }
        }

    exchange();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
            if (info.small_gap())
                S[info.dest_base + i] -= finalize_mul()
                        << (info.k - info.m + 1);
}

template<class T>
template<class U>
void TestProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void TestProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{

	if (TRUNC_LOG_LEVEL & TRUNC_PROCESS) {
		cout << "In trunc_pr()" << endl;
	}
	if (TRUNC_LOG_LEVEL & TRUNC_DETAIL) {
		cout << "regs: ";
		for (auto i : regs) {
			cout << i << " ";
		}
		cout << endl << size << endl;
	}

    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

#endif