
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

    batch_size = OnlineOptions::singleton.batch_size;
    ms = OnlineOptions::singleton.max_status;
    k = OnlineOptions::singleton.k_size;
    new_batch_size = batch_size * 2;

    X_prover = new VerifyRing[new_batch_size * ms];
    Y_prover = new VerifyRing[new_batch_size * ms];
    Y_right = new VerifyRing[new_batch_size * ms];
    X_left = new VerifyRing[new_batch_size * ms];
    _Z_left = new VerifyRing[batch_size * ms];
    _Z_right = new VerifyRing[batch_size * ms];
    E = new VerifyRing[batch_size * ms];

    X_prover_bak = new VerifyRing[new_batch_size * ms];
    Y_prover_bak = new VerifyRing[new_batch_size * ms];
    Y_right_bak = new VerifyRing[new_batch_size * ms];
    X_left_bak = new VerifyRing[new_batch_size * ms];
    _Z_left_bak = new VerifyRing[batch_size * ms];
    _Z_right_bak = new VerifyRing[batch_size * ms];
    E_bak = new VerifyRing[batch_size * ms];

    thread_buffer = new VerifyRing[new_batch_size * ms];

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

    Z_left = new VerifyRing[ms];
    Z_right = new VerifyRing[ms];

    coeffsX_prover = new VerifyRing[k];
    coeffsY_prover = new VerifyRing[k];
    coeffsX_left = new VerifyRing[k];
    coeffsY_left = new VerifyRing[k];
    coeffsX_right = new VerifyRing[k];
    coeffsY_right = new VerifyRing[k];

    local_left = new VerifyRing**[ms];
    local_right = new VerifyRing**[ms];

    for (int i = 0; i < ms; i ++) {
        local_left[i] = new VerifyRing*[k];
        local_right[i] = new VerifyRing*[k];
        for (int j = 0; j < k; j ++) {
            local_left[i][j] = new VerifyRing[k];
            local_right[i][j] = new VerifyRing[k];
        }
    }

    // chatGPT taught me to do this. Brilliant
    for (int i = 0; i < OnlineOptions::singleton.thread_number; i++) {
        std::shared_ptr<std::thread> _thread(new std::thread(&TestProtocol<T>::verify_thread_handler, this));
        verify_threads.push_back(_thread);
    }

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

    for (int _ = 0; _ < KAPPA; _ ++) {        
        for (int i = 0; i < batch_size; i ++) {
            _Z[_] += _Z_right[batch_id * batch_size + i] * choices_right[_][i];
        }

        _Z[_] += thread_buffer[batch_id * KAPPA + _] << 64;
    }

    for (int i = 0; i < KAPPA; i ++) {
        Z_right[batch_id] += _Z[i] * random_coef_right[i];
    }

    ++ ws;
}

template <class T>
void TestProtocol<T>::verify_part3(int batch_id) {

    VerifyRing *_Z = new VerifyRing[KAPPA];
    memset(_Z, 0, sizeof(VerifyRing) * KAPPA);

    // Compute the RHS of poly in verifier left.
    for (int _ = 0; _ < KAPPA; _ ++) {
        
        for (int i = 0; i < batch_size; i ++) {
            _Z[_] += _Z_left[batch_id * batch_size + i] * choices_left[_][i];
        }

        _Z[_] += thread_buffer[batch_id * KAPPA + _] << 64;

    }

    for (int i = 0; i < KAPPA; i ++) {
        Z_left[batch_id] += _Z[i] * random_coef_left[i];
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

    for (int i = 0; i < k; i ++) {
        for (int j = 0; j < k; j ++) {
            if (i == 0 && j == 0) {
                continue;
            }
            thread_buffer[batch_id * k * k + i * k + j] = 
                inner_product(X_prover + batch_id * new_batch_size + i * vector_length, 
                              Y_prover + batch_id * new_batch_size + j * vector_length, 
                              vector_length)
                - thread_buffer[batch_id * k * k + i * k + j];
        }
    }

    ++ ws;
}

template <class T>
void TestProtocol<T>::verify_part5(int batch_id) {

    VerifyRing res_left[k], res_right[k];
    int offset = batch_id * new_batch_size;

    local_left[batch_id][0][0] = Z_left[batch_id];
    local_right[batch_id][0][0] = Z_right[batch_id];

    for (int i = 1; i < k; i ++) {
        local_left[batch_id][0][0] -= local_left[batch_id][i][i];
        local_right[batch_id][0][0] -= local_right[batch_id][i][i];
    }

    for (int j = 0; j < vector_length; j ++) {
        X_prover[offset + j] *= coeffsX_prover[0];
        Y_prover[offset + j] *= coeffsY_prover[0];
        X_left[offset + j] *= coeffsX_left[0];
        Y_right[offset + j] *= coeffsY_right[0];
    }

    for (int i = 1; i < k; i ++) {
        for (int j = 0; j < vector_length; j ++) {
            X_prover[offset + j] += X_prover[offset + j + i * vector_length] * coeffsX_prover[i];
            Y_prover[offset + j] += Y_prover[offset + j + i * vector_length] * coeffsY_prover[i];

            X_left[offset + j] += X_left[offset + j + i * vector_length] * coeffsX_left[i];
            Y_right[offset + j] += Y_right[offset + j + i * vector_length] * coeffsY_right[i];
        }
    }

    for (int i = 0; i < vector_length; i ++) {
        X_prover[offset + vector_length + i] = 0;
        Y_prover[offset + vector_length + i] = 0;
        X_left[offset + vector_length + i] = 0;
        Y_right[offset + vector_length + i] = 0;
    }

    for (int i = 0; i < k; i ++) {
        res_left[i] = 0;
        res_right[i] = 0;
        for (int j = 0; j < k; j ++) {
            res_left[i] += coeffsY_left[j] * local_left[batch_id][i][j];
            res_right[i] += coeffsY_right[j] * local_right[batch_id][i][j];
        }
    }

    Z_left[batch_id] = Z_right[batch_id] = 0;
    for (int i = 0; i < k; i ++) {
        Z_left[batch_id] += res_left[i] * coeffsX_left[i];
        Z_right[batch_id] += res_right[i] * coeffsX_right[i];
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
    int Nbatches = (pointer_answer - 1) / batch_size + 1;
    ws.set_target(Nbatches);

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

    for (int i = 0; i < KAPPA; i++) {
        for (int j = 0; j < batch_size; j ++) {
            choices_left[i][j] = choices_prng_left.get_bit();           // low efficiency
            choices_right[i][j] = choices_prng_right.get_bit();
            choices_prover[i][j] = choices_prng_prover.get_bit();
        }
    }

    for (auto &o : os)
        o.reset_write_head();

    memset(counter_prover, 0, sizeof(VerifyRing) * batch_size);
    memset(counter_left, 0, sizeof(VerifyRing) * batch_size);
    memset(counter_right, 0, sizeof(VerifyRing) * batch_size);

    memset(Z_left, 0, sizeof(VerifyRing) * ms);
    memset(Z_right, 0, sizeof(VerifyRing) * ms);

    // seed for the random coefs.
    shared_prngs[1].get_octets(seed_left, SEED_SIZE);       // as Verifier left
    shared_prngs[0].get_octets(seed_right, SEED_SIZE);      // as Verifier right
    os[0].append(seed_left, SEED_SIZE);

    // generate share_left because we cannot call random function in multi-thread.
    for (int batch = 0; batch < Nbatches; batch ++) {
        for (int i = 0; i < KAPPA; i ++) {
            thread_buffer[batch * KAPPA + i] = shared_prngs[1].getDoubleWord();
        }
    }

    ws.reset();

    // part 1: compute share_right and send to verifier right. 
    for (int batch = 0; batch < Nbatches; batch ++) {
        cv.push(MyPair<int, int>(1, batch));
    }
    
    ws.wait();

    // we cannot store the share_right to octetstream in multi-thread, so we store it to thread_buffer.
    for (int batch = 0; batch < Nbatches; batch ++) {
        for (int i = 0; i < KAPPA; i ++) {
            os[0].store(thread_buffer[batch * KAPPA + i]);
        }
    }
 
    P.pass_around(os[0], os[1], 1);

    os[1].consume(seed_prover, SEED_SIZE);

    choices_prng_left.SetSeed(seed_left);
    choices_prng_right.SetSeed(seed_right);
    choices_prng_prover.SetSeed(seed_prover);

    // Now, thread_buffer stored the share_right. 
    for (int batch = 0; batch < Nbatches; batch ++) {
        for (int i = 0; i < KAPPA; i ++) {
            os[1].get(thread_buffer[batch * KAPPA + i]);
        }
    }

    // The random_coefs can be used in every batch. 
    for (int i = 0; i < KAPPA; i ++) {
        random_coef_left[i] = choices_prng_left.getDoubleWord();
        random_coef_right[i] = choices_prng_right.getDoubleWord();
        random_coef_prover[i] = choices_prng_prover.getDoubleWord();
    }

    // Compute the real coefficient. Also they can be used in every batch.
    for (int i = 0; i < KAPPA; i ++) {
        for (int j = 0; j < batch_size; j ++) {
            counter_prover[j] += choices_prover[i][j] * random_coef_prover[i];
            counter_left[j] += choices_left[i][j] * random_coef_left[i];
            counter_right[j] += choices_right[i][j] * random_coef_right[i];
        }
    }


    ws.reset();
    
    // part 2: remember, the thread_buffer stored the share_right. So we firstly deal with verifier right.
    for (int batch = 0; batch < Nbatches; batch ++) {
        cv.push(MyPair<int, int>(2, batch));
    }

    ws.wait();

    // Now, we deal with verifier left. Same as above, we have to generate the randoms outside the multi-thread.
    for (int batch = 0; batch < Nbatches; batch ++) {
        for (int i = 0; i < KAPPA; i ++) {
            thread_buffer[batch * KAPPA + i] = shared_prngs[0].getDoubleWord();
        }
    }

    ws.reset();

    // part 3: deal with verifier left.
    for (int batch = 0; batch < Nbatches; batch ++) {
        cv.push(MyPair<int, int>(3, batch));
    }

    ws.wait();


    // preparation before chop
    s = new_batch_size;
    vector_length = (s - 1) / k + 1;

    // chop
    while (true) {
 
        for (auto &o : os)
            o.reset_write_head();

        // thread_buffer stores random numbers with left.
        for (int batch = 0; batch < Nbatches; batch ++) {
            for (int i = 0; i < k; i ++) {
                for (int j = 0; j < k; j ++) {
                    if (i == 0 && j == 0) {  
                        continue;
                    }
                    thread_buffer[batch * k * k + i * k + j] = shared_prngs[1].getDoubleWord();
                    local_left[batch][i][j] = shared_prngs[0].getDoubleWord();
                }
            }
        }

        ws.reset();
        for (int batch = 0; batch < Nbatches; batch ++) {
            cv.push(MyPair<int, int>(4, batch));
        }
        ws.wait();

        for (int batch = 0; batch < Nbatches; batch ++) {
            for (int i = 0; i < k; i ++) {
                for (int j = 0; j < k; j ++) {
                    if (i == 0 && j == 0) {
                        continue;
                    }
                    os[0].store(thread_buffer[batch * k * k + i * k + j]);
                }
            }
        }

        for (int i = 0; i < k; i ++) {
            coeffsX_left[i] = shared_prngs[1].getDoubleWord();
            coeffsY_left[i] = shared_prngs[1].getDoubleWord();
            coeffsX_right[i] = shared_prngs[0].getDoubleWord();
            coeffsY_right[i] = shared_prngs[0].getDoubleWord();
            os[0].store(coeffsX_left[i]);
            os[0].store(coeffsY_left[i]);
        }

        P.pass_around(os[0], os[1], 1);

        for (int batch = 0; batch < Nbatches; batch ++) {
            for (int i = 0; i < k; i ++) {
                for (int j = 0; j < k; j ++) {
                    if (i == 0 && j == 0) {
                        continue;
                    }
                    os[1].get(local_right[batch][i][j]);
                }
            }
        }

        for (int i = 0; i < k; i ++) {
            os[1].get(coeffsX_prover[i]);
            os[1].get(coeffsY_prover[i]);
        }

        ws.reset();
        for (int batch = 0; batch < Nbatches; batch ++) {
            cv.push(MyPair<int, int>(5, batch));
        }
        ws.wait();

        if (vector_length == 1) {
            break;
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }

    for (auto &o : os)
        o.reset_write_head();

    for (int batch = 0; batch < Nbatches; batch ++) {
        os[0].store(Y_right[new_batch_size * batch]);
        os[0].store(Z_right[batch]);
    }
    

    P.pass_around(os[0], os[1], 1);

    for (int batch = 0; batch < Nbatches; batch ++) {
        VerifyRing y = 0, z = 0, x = X_left[new_batch_size * batch];
        os[1].get(y);
        os[1].get(z);
        z += Z_left[batch];
        if (x * y != z) {
            throw mac_fail("ZKP check failed");
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

    X_prover[pointer * 2] = X_prover_bak[pointer * 2] = (uint128_t) y[1].debug();
    X_prover[pointer * 2 + 1] = X_prover_bak[pointer * 2 + 1] = (uint128_t) x[1].debug();
    Y_prover[pointer * 2] = Y_prover_bak[pointer * 2] = (uint128_t) x[0].debug();
    Y_prover[pointer * 2 + 1] = Y_prover_bak[pointer * 2 + 1] = (uint128_t) y[0].debug();

    E[pointer] = X_prover[pointer * 2] * Y_prover[pointer * 2];
    E[pointer] += X_prover[pointer * 2 + 1] * Y_prover[pointer * 2 + 1];
    E[pointer] -= (uint128_t) (tmp[1].debug());

    Y_right[pointer * 2] = Y_right_bak[pointer * 2] = x[1].debug();
    Y_right[pointer * 2 + 1] = Y_right_bak[pointer * 2 + 1] = y[1].debug();
    _Z_right[pointer] = - x[1].debug() * y[1].debug() - tmp[1].debug();

    X_left[pointer * 2] = X_left_bak[pointer * 2] = y[0].debug();
    X_left[pointer * 2 + 1] = X_left_bak[pointer * 2 + 1] = x[0].debug();
    _Z_left[pointer] = _Z_left_bak[pointer] = tmp[0].debug();

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
    E_bak[pointer_answer] = E[pointer_answer];

    _Z_right[pointer_answer] = (uint64_t) result[1].debug() + (uint64_t) _Z_right[pointer_answer];
    _Z_right_bak[pointer_answer] = _Z_right[pointer_answer];

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