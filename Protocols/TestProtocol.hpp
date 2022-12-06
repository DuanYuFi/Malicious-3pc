
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
    verify_shares = new MultiShare[64000000];

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

    while (pointer >= 640000) {
        verify();
        verify();
        pointer -= 640000;
        pointer_answer -= 640000;
    }
}


template <class T>
void TestProtocol<T>::verify() {
    
    // Initialize

    int k = OnlineOptions::singleton.k_size;
    int batch_size = OnlineOptions::singleton.batch_size;

    bool **choices_left = new bool*[KAPPA];
    bool **choices_right = new bool*[KAPPA];
    bool **choices_prover = new bool*[KAPPA];

    VerifyRing *share_right_prover = new VerifyRing[KAPPA];
    VerifyRing *share_right_verifier = new VerifyRing[KAPPA];


    VerifyRing *random_coef_left = new VerifyRing[KAPPA];
    VerifyRing *random_coef_right = new VerifyRing[KAPPA];
    VerifyRing *random_coef_prover = new VerifyRing[KAPPA];

    VerifyRing Z_left = 0, Z_right = 0;

    for (int i = 0; i < KAPPA; i++) {
        choices_left[i] = new bool[batch_size];
        choices_right[i] = new bool[batch_size];
        choices_prover[i] = new bool[batch_size];
    }

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

        random_coef_left[i] = choices_prng_left.getDoubleWord();        // These should not be here. But the first thing to do 
                                                                        // is to make it work.
        random_coef_right[i] = choices_prng_right.getDoubleWord();
        random_coef_prover[i] = choices_prng_prover.getDoubleWord();
    }


    for (auto &o : os)
        o.reset_write_head();

    size_t new_batch_size = batch_size * 2;


    VerifyRing *X_prover, *Y_prover, *Y_right, *X_left, *_Z_left, *_Z_right, *_Z;
    X_prover = new VerifyRing[new_batch_size + k];
    Y_prover = new VerifyRing[new_batch_size + k];
    Y_right = new VerifyRing[new_batch_size + k];
    X_left = new VerifyRing[new_batch_size + k];
    _Z_left = new VerifyRing[new_batch_size + k];
    _Z_right = new VerifyRing[new_batch_size + k];
    _Z = new VerifyRing[KAPPA];
    
    VerifyRing *E;
    E = new VerifyRing[batch_size];

    // Unpack the data
    for (int i = 0; i < batch_size; i ++) {

        auto share = verify_shares[i];
        VerifyRing z1 = share.z[0] - share.rho[0], z2 = - share.x[0] * share.y[0] + share.rho[1];   // Play a role as Prover
        X_prover[i * 2] = (uint128_t) share.y[1];
        X_prover[i * 2 + 1] = (uint128_t) share.x[1];
        Y_prover[i * 2] = (uint128_t) share.x[0];
        Y_prover[i * 2 + 1] = (uint128_t) share.y[0];

        E[i] = X_prover[i * 2] * Y_prover[i * 2];
        E[i] += X_prover[i * 2 + 1] * Y_prover[i * 2 + 1];
        E[i] -= (z1 + z2);

        Y_right[i * 2] = share.x[1];                            // Play a role as Verifier right
        Y_right[i * 2 + 1] = share.y[1];
        _Z_right[i] = share.z[1] - share.x[1] * share.y[1] - share.rho[1];

        X_left[i * 2] = share.y[0];                             // Play a role as Verifier left
        X_left[i * 2 + 1] = share.x[0];
        _Z_left[i] = share.rho[0];
    }
   
    VerifyRing *counter_prover = new VerifyRing[batch_size];
    VerifyRing *counter_left = new VerifyRing[batch_size];
    VerifyRing *counter_right = new VerifyRing[batch_size];

    memset(counter_prover, 0, sizeof(int) * batch_size);
    memset(counter_left, 0, sizeof(int) * batch_size);
    memset(counter_right, 0, sizeof(int) * batch_size);

    // Prover compute e's share, communications only happen with verifier_right. 
    for (int _ = 0; _ < KAPPA; _ ++) {

        VerifyRing e = 0;

        for (int i = 0; i < batch_size; i ++) {
            e += E[i] * choices_prover[_][i];
        }

        e = e >> 64;
        
        VerifyRing share_left = shared_prngs[1].getDoubleWord();
        share_right_prover[_] = e - share_left;

        os[0].store(share_right_prover[_]);
    }
 
    P.pass_around(os[0], os[1], 1);

    for (int _ = 0; _ < KAPPA; _ ++) {
        os[1].get(share_right_verifier[_]);
    }

    // Compute the real coefficient, in three roles played.
    for (int i = 0; i < KAPPA; i ++) {
        for (int j = 0; j < batch_size; j ++) {
            counter_prover[j] += choices_prover[i][j] * random_coef_prover[i];
            counter_left[j] += choices_left[i][j] * random_coef_left[i];
            counter_right[j] += choices_right[i][j] * random_coef_right[i];
        }
    }

    memset(_Z, 0, sizeof(VerifyRing) * KAPPA);

    // Compute the RHS of poly in verifier left.
    for (int _ = 0; _ < KAPPA; _ ++) {
        
        for (int i = 0; i < batch_size; i ++) {
            _Z[_] += _Z_left[i] * choices_left[_][i];
        }

        VerifyRing share_left = shared_prngs[0].getDoubleWord();
        _Z[_] += share_left << 64;

    }

    for (int i = 0; i < KAPPA; i ++) {
        Z_left += _Z[i] * random_coef_left[i];
    }

    // Compute the real items of the merged poly. We multiply the coefs into left. 
    for (int i = 0; i < batch_size; i ++) {
        X_prover[i * 2] *= counter_prover[i];
        X_prover[i * 2 + 1] *= counter_prover[i];
    
        X_left[i * 2] *= counter_left[i];
        X_left[i * 2 + 1] *= counter_left[i];
    }

    memset(_Z, 0, sizeof(VerifyRing) * KAPPA);

    // Compute the RHS of poly in verifier right.
    for (int _ = 0; _ < KAPPA; _ ++) {        
        for (int i = 0; i < batch_size; i ++) {
            _Z[_] += _Z_right[i] * choices_right[_][i];
        }

        _Z[_] += share_right_verifier[_] << 64;
    }

    for (int i = 0; i < KAPPA; i ++) {
        Z_right += _Z[i] * random_coef_right[i];
    }

    // show_uint128(Z_left);
    // show_uint128(Z_right);

    // preparation before chop
    int s = new_batch_size;
    int vector_length = (s - 1) / k + 1;
    VerifyRing coeffsX_prover[k], coeffsY_prover[k];
    VerifyRing coeffsX_left[k], coeffsY_left[k];
    VerifyRing coeffsX_right[k], coeffsY_right[k];
    VerifyRing res_left[k], res_right[k];

    // chop
    while (true) {

        VerifyRing local_right[k][k], local_left[k][k], local_prover;

        for (auto &o : os)
            o.reset_write_head();

        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                if (i == 0 && j == 0) {
                    continue;
                }
                VerifyRing r = shared_prngs[1].getDoubleWord();
                local_left[i][j] = shared_prngs[0].getDoubleWord();
                local_prover = inner_product(X_prover + i * vector_length, Y_prover + j * vector_length, vector_length) - r;
                os[0].store(local_prover);
            }
        }

        P.pass_around(os[0], os[1], 1);
        for (int i = 0; i < k; i ++) {
            for (int j = 0; j < k; j ++) {
                if (i == 0 && j == 0) {
                    continue;
                }
                os[1].get(local_right[i][j]);
            }
        }

        local_left[0][0] = Z_left;
        local_right[0][0] = Z_right;

        for (int i = 1; i < k; i ++) {
            local_left[0][0] -= local_left[i][i];
            local_right[0][0] -= local_right[i][i];
        }

        for (auto &o : os)
            o.reset_write_head();

        for (int i = 0; i < k; i ++) {
            coeffsX_left[i] = shared_prngs[1].getDoubleWord();
            coeffsY_left[i] = shared_prngs[1].getDoubleWord();
            coeffsX_right[i] = shared_prngs[0].getDoubleWord();
            coeffsY_right[i] = shared_prngs[0].getDoubleWord();

            os[0].store(coeffsX_left[i]);
            os[0].store(coeffsY_left[i]);
        }

        P.pass_around(os[0], os[1], 1);

        for (int i = 0; i < k; i ++) {
            os[1].get(coeffsX_prover[i]);
            os[1].get(coeffsY_prover[i]);
        }

        for (int j = 0; j < vector_length; j ++) {
            X_prover[j] *= coeffsX_prover[0];
            Y_prover[j] *= coeffsY_prover[0];
            X_left[j] *= coeffsX_left[0];
            Y_right[j] *= coeffsY_right[0];
        }

        for (int i = 1; i < k; i ++) {
            for (int j = 0; j < vector_length; j ++) {
                X_prover[j] += X_prover[j + i * vector_length] * coeffsX_prover[i];
                Y_prover[j] += Y_prover[j + i * vector_length] * coeffsY_prover[i];

                X_left[j] += X_left[j + i * vector_length] * coeffsX_left[i];
                Y_right[j] += Y_right[j + i * vector_length] * coeffsY_right[i];
            }
        }

        for (int i = 0; i < vector_length; i ++) {
            X_prover[vector_length + i] = 0;
            Y_prover[vector_length + i] = 0;
            X_left[vector_length + i] = 0;
            Y_right[vector_length + i] = 0;
        }

        for (int i = 0; i < k; i ++) {
            res_left[i] = 0;
            res_right[i] = 0;
            for (int j = 0; j < k; j ++) {
                res_left[i] += coeffsY_left[j] * local_left[i][j];
                res_right[i] += coeffsY_right[j] * local_right[i][j];
            }
        }

        Z_left = Z_right = 0;
        for (int i = 0; i < k; i ++) {
            Z_left += res_left[i] * coeffsX_left[i];
            Z_right += res_right[i] * coeffsX_right[i];
        }

        
        if (vector_length == 1) {
            break;
        }

        s = vector_length;
        vector_length = (s - 1) / k + 1;
    }

    for (auto &o : os)
        o.reset_write_head();

    os[0].store(Y_right[0]);
    os[0].store(Z_right);

    P.pass_around(os[0], os[1], 1);

    VerifyRing y = 0, z = 0, x = X_left[0];
    os[1].get(y);
    os[1].get(z);

    z += Z_left;

    if (x * y != z) {
        throw mac_fail("ZKP check failed");
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

    verify_shares[pointer].x[0] = x[0].debug();
    verify_shares[pointer].x[1] = x[1].debug();
    verify_shares[pointer].y[0] = y[0].debug();
    verify_shares[pointer].y[1] = y[1].debug();
    verify_shares[pointer].rho[0] = tmp[0].debug();
    verify_shares[pointer].rho[1] = tmp[1].debug();

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

    verify_shares[pointer_answer].z[0] = result[0].debug();
    verify_shares[pointer_answer].z[1] = result[1].debug();
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