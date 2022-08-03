#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_

#include "Malicious3PCProtocol.h"
#include "BinaryCheck.hpp"

#include "Replicated.h"
#include "Tools/octetStream.h"

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P) : P(P) {
    assert(P.num_players() == 3);
	if (not P.is_encrypted())
		insecure("unencrypted communication");

	shared_prngs[0].ReSeed();
	octetStream os;
	os.append(shared_prngs[0].get_seed(), SEED_SIZE);
	P.send_relative(1, os);
	P.receive_relative(-1, os);
	shared_prngs[1].SetSeed(os.get_data());

    os.reset_write_head();
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

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs) :
        P(P)
{
    for (int i = 0; i < 2; i++)
        shared_prngs[i].SetSeed(prngs[i]);
}

template <class T>
void Malicious3PCProtocol<T>::maybe_check() {

    // cout << results.size() << endl;

    if ((int) results.size() >= BATCH_SIZE)
        Check();
}

template <class T>
void Malicious3PCProtocol<T>::init_mul()
{

    maybe_check();

	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template <class T>
void Malicious3PCProtocol<T>::Check() {
    for (auto& o : os)
        o.clear();

    int k = 8, cols = (BATCH_SIZE - 1) / k + 1;
    int my_number = P.my_real_num();

    uint64_t **input_left, **input_right, **input_result_up, **input_result_down, **input_mono_up, **input_mono_down;

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_result_up = new uint64_t*[k];
    input_result_down = new uint64_t*[k];
    input_mono_up = new uint64_t*[k];
    input_mono_down = new uint64_t*[k];

    // int size = results.size();
    for (int i = 0; i < k; i ++) {
        input_left[i] = new uint64_t[cols * 2];
        input_right[i] = new uint64_t[cols * 2];
        input_result_up[i] = new uint64_t[cols * 2];
        input_result_down[i] = new uint64_t[cols * 2];
        input_mono_up[i] = new uint64_t[cols];
        input_mono_down[i] = new uint64_t[cols];

        for (int j = 0; j < cols; j ++) {
            auto x = input1.front();    input1.pop();
            auto y = input2.front();    input2.pop();
            auto z = results.front();   results.pop();
            array<typename T::value_type, 2> rho = rhos.front();    rhos.pop();

            // x[0]: x_i, x[1]: x_{i-1}
            // y[0]: y_i, y[1]: y_{i-1}
            // z[0]: z_i, z[1]: z_{i-1}
            assert(z[0] == x[0] * y[0] + x[1] * y[0] + x[0] * y[1] + rho[0] + rho[1]);
            
            uint64_t ti = (z[0] + x[0] * y[0] + rho[0]).get();
            // shared vars between P_i and P_{i-1}
            uint64_t v0 = y[1].get();
            // shared vars between P_i and P_{i+1}
            uint64_t v1 = Mersenne::sub(x[0].get(), 2 * ti * x[0].get());
            uint64_t v11 = x[0].get() - 2 * ti * x[0].get();
            // shared vars between P_i and P_{i-1}
            uint64_t v2 = Mersenne::sub(x[1].get(), 2 * rho[1].get() * x[1].get());
            uint64_t v22 = x[1].get() - 2 * rho[1].get() * x[1].get();
            // shared vars between P_i and P_{i+1}
            uint64_t v3 = y[0].get();
            uint64_t v4 = rho[1].get() - ti;
            assert(v0 * v11 + v22 * v3 == v4);

            
            input_left[i][j * 2] = v0;
            input_left[i][j * 2 + 1] = v2;
            input_right[i][j * 2] = v1;
            input_right[i][j * 2 + 1] = v3;

            // shared vars between P_i and P_{i-1}
            input_result_down[i][j * 2] = v0;
            input_result_down[i][j * 2 + 1] = v2;
            // shared vars between P_i and P_{i+1}
            input_result_up[i][j * 2] = v1;
            input_result_up[i][j * 2 + 1] = v3;

            // shared vars between P_i and P_{i-1}
            input_mono_down[i][j] = rho[1].get();
            // shared vars between P_i and P_{i+1}
            input_mono_up[i][j] = Mersenne::neg(ti);

            // Check inputs
            assert(Mersenne::add(Mersenne::mul(input_left[i][j * 2], input_right[i][j * 2]), Mersenne::mul(input_left[i][j * 2 + 1], input_right[i][j * 2 + 1])) == Mersenne::add(input_mono_up[i][j], input_mono_down[i][j]));
            assert(Mersenne::add(Mersenne::mul(input_result_up[i][j * 2], input_result_down[i][j * 2]), Mersenne::mul(input_result_up[i][j * 2 + 1], input_result_down[i][j * 2 + 1])) == Mersenne::add(input_mono_up[i][j], input_mono_down[i][j]));
        }
    }

    int cnt = log(2 * BATCH_SIZE) / log(k) + 2;
    uint64_t **masks, **mask_ss_up, **mask_ss_down;
    masks = new uint64_t*[cnt];
    mask_ss_up = new uint64_t*[cnt];
    mask_ss_down = new uint64_t*[cnt];

    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2*k-1];
        mask_ss_up[i] = new uint64_t[2*k-1];
        mask_ss_down[i] = new uint64_t[2*k-1];
        for (int j = 0; j < 2 * k - 1; j ++) {
            // P_i and P_{i+1}
            mask_ss_up[i][j] = Mersenne::modp(shared_prngs[0].get_word());
            // P_i and P_{i-1}
            mask_ss_down[i][j] = Mersenne::modp(shared_prngs[1].get_word());
            masks[i][j] = Mersenne::add(mask_ss_up[i][j], mask_ss_down[i][j]);
        }
    }

    uint64_t sid[3];
    for (int i = 0; i < 3; i ++) {
        sid[i] = global_prng.get_word();
    }
    
    // return;

    DZKProof dzkproof = prove(input_left, input_right, BATCH_SIZE, k, sid[my_number], masks);
    DZKProof received_proof[2];
    // return ;
    dzkproof.pack(os[0]);

    // P_i sends proof_i to P_{i+1}, receives proof_{i-1} from P_{i-1}
    P.pass_around(os[0], os[1], 1);    
    // cout << dzkproof.p_evals_masked.size() << endl;

    // received_proof[0] is proof_{i-1}
    received_proof[0].unpack(os[1]);

    P.pass_around(os[0], os[1], -1);
    received_proof[1].unpack(os[1]);
    // return ;

    // cout << "Next: gen_vermsg" << endl;
    VerMsg vermsg = gen_vermsg(received_proof[0], input_result_down, input_mono_down, BATCH_SIZE, k, sid[(my_number - 1) % 3], mask_ss_down, (my_number - 1) % 3, my_number);

    // cout << "Next: reset_write_head" << endl;
    for (auto& o : os)
        o.reset_write_head();

    // cout << "Next: pack" << endl;
    vermsg.pack(os[0]);
    P.pass_around(os[0], os[1], 1);

    // cout << "Next: unpack" << endl;
    VerMsg received_vermsg;
    received_vermsg.unpack(os[1]);

    // cout << "Next: verify" << endl;
    bool res = verify(received_proof[1], input_result_up, input_mono_up, received_vermsg, BATCH_SIZE, k, sid[(my_number + 1) % 3], mask_ss_up, (my_number + 1) % 3, my_number);
    if (!res) {
        throw mac_fail("ZKP check failed");
    }

    cout << "Check passed" << endl;
}


template<class T>
void Malicious3PCProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    // cout << typeid(typename T::value_type).name() << endl;
    typename T::value_type add_share = x.local_mul(y);
    input1.push(x);
    input2.push(y);
    prepare_reshare(add_share, n);

}

template<class T>
void Malicious3PCProtocol<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++)
        tmp[i].randomize(shared_prngs[i], n);
    
    array<typename T::value_type, 2> rho;
    rho[0] = tmp[0];
    rho[1] = tmp[1];
    rhos.push(rho);

    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Malicious3PCProtocol<T>::exchange()
{

    cout << "In Malicious3PCProtocol::exchange()" << endl;

    if (os[0].get_length() > 0)
        P.pass_around(os[0], os[1], 1);
    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::start_exchange()
{
    P.send_relative(1, os[0]);
    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::stop_exchange()
{
    P.receive_relative(-1, os[1]);
}

template<class T>
inline T Malicious3PCProtocol<T>::finalize_mul(int n)
{

    this->counter++;
    this->bit_counter += n;
    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    results.push(result);
    return result;
}

template<class T>
inline void Malicious3PCProtocol<T>::init_dotprod()
{
    init_mul();
    dotprod_share.assign_zero();
}

template<class T>
inline void Malicious3PCProtocol<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void Malicious3PCProtocol<T>::next_dotprod()
{
    dotprod_share.normalize();
    prepare_reshare(dotprod_share);
    dotprod_share.assign_zero();
}

template<class T>
inline T Malicious3PCProtocol<T>::finalize_dotprod(int length)
{

    (void) length;
    this->dot_counter++;
    return finalize_mul();
}

template<class T>
T Malicious3PCProtocol<T>::get_random()
{
    T res;
    for (int i = 0; i < 2; i++)
        res[i].randomize(shared_prngs[i]);
    return res;
}

template<class T>
void Malicious3PCProtocol<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize_part(shared_prngs[i], n_bits);
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
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
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{
    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

#endif
