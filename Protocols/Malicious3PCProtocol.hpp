#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_

#include "Malicious3PCProtocol.h"


#include "Replicated.h"
#include "Tools/octetStream.h"

#include <chrono>

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P) : P(P) {
    assert(P.num_players() == 3);

    // cout << typeid(typename T::value_type).name() << endl;

    set_returned(true);
    total_and_gates = 0;
    exchange_comm = 0;
    check_comm = 0;

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
void Malicious3PCProtocol<T>::check() {

    // return ;
    
    if ((int) results.size() < OnlineOptions::singleton.binary_batch_size)
        return;

    #ifdef USE_THREAD

    if (!get_returned()) {
        // cout << "Thread already running" << endl;
        return ;
    }

    set_returned(false);
    
    if (check_thread.joinable()) {
        // cout << "Join last thread" << endl;
        check_thread.join();
    }

    // cout << "Create new thread" << endl;
    check_thread = std::thread(&Malicious3PCProtocol<T>::thread_handler, this);
    #else
    thread_handler();
    #endif
    
}

template <class T>
void Malicious3PCProtocol<T>::init_mul()
{

    check();
    // cout << "In initmul" << endl;

	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template <class T>
void Malicious3PCProtocol<T>::finalize_check() {

    // return ;
    // cout << "In finalize_check" << endl;

    #ifdef USE_THREAD
    if (!get_returned()) {
        check_thread.join();
    }
    #endif

    while ((int) results.size() >= OnlineOptions::singleton.binary_batch_size)
        Check_one();
    Check_one();

    final_verify();
}

template <class T>
void Malicious3PCProtocol<T>::thread_handler() {
    while ((int) results.size() >= OnlineOptions::singleton.binary_batch_size)
        Check_one();
    set_returned(true);
    // cout << "Returned from thread handler" << endl;
}

template <class T>
void Malicious3PCProtocol<T>::final_verify() {

    // cout << "In final_ver" << endl;

    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    array<octetStream, 2> proof_os, vermsg_os;

    for (auto& o : proof_os)
        o.reset_write_head();
    
    for (auto& o : vermsg_os)
        o.reset_write_head();
    
    for (auto data: status_queue) {
        DZKProof proof = data.proof;
        proof.pack(proof_os[0]);
    }

    // cout << proof_os[0].get_length() << endl;

    check_comm += proof_os[0].get_length();
    P.pass_around(proof_os[0], proof_os[1], 1);

    for (auto data: status_queue) {
        DZKProof proof;
        uint64_t **input_result_prev = data.input_result_prev;
        uint64_t **input_mono_prev = data.input_mono_prev;
        uint64_t **mask_ss_prev = data.mask_ss_prev;
        uint64_t *sid = data.sid;
        int sz = data.sz;
        int k = OnlineOptions::singleton.k_size;

        proof.unpack(proof_os[1]);
        VerMsg vermsg = gen_vermsg(proof, input_result_prev, input_mono_prev, sz, k, sid[prev_number], mask_ss_prev, prev_number, my_number);
        vermsg.pack(vermsg_os[0]);

        // for (int i = 0; i < k; i ++) {
        //     delete[] input_result_prev[i];
        //     delete[] input_mono_prev[i];
        //     delete[] mask_ss_prev[i];
        // }
        // delete[] input_result_prev;
        // delete[] input_mono_prev;
        // delete[] mask_ss_prev;
    }

    // proof_os[0].reset_read_head();
    proof_os[1].reset_write_head();

    P.pass_around(proof_os[0], proof_os[1], -1);
    P.pass_around(vermsg_os[0], vermsg_os[1], 1);

    check_comm += proof_os[0].get_length();
    check_comm += vermsg_os[0].get_length();

    for (auto data: status_queue) {

        uint64_t **input_result_next = data.input_result_next;
        uint64_t **input_mono_next = data.input_mono_next;
        uint64_t **mask_ss_next = data.mask_ss_next;
        uint64_t *sid = data.sid;

        int sz = data.sz;
        int k = OnlineOptions::singleton.k_size;

        VerMsg received_vermsg;
        received_vermsg.unpack(vermsg_os[1]);

        DZKProof proof;
        proof.unpack(proof_os[1]);

        // cout << "Next: verify" << endl;
        bool res = verify(proof, input_result_next, input_mono_next, received_vermsg, sz, k, sid[next_number], mask_ss_next, next_number, my_number);
            
        if (!res) {
            // throw mac_fail("ZKP check failed");
            // cout << "ZKP check failed" << endl;
        }
        else {
            // cout << "Check passed" << endl;
        }

        // for (int i = 0; i < k; i ++) {
        //     delete[] input_result_next[i];
        //     delete[] input_mono_next[i];
        //     delete[] mask_ss_next[i];
        // }
        // delete[] input_result_next;
        // delete[] input_mono_next;
        // delete[] mask_ss_next;
        // delete[] sid;
    }

    status_queue.clear();
}

template <class T>
void Malicious3PCProtocol<T>::Check_one() {
    
    int sz = min((int) results.size(), OnlineOptions::singleton.binary_batch_size);
    // cout << "size = " << sz << endl;
    if (sz == 0) {
        return;
    }

    int k = OnlineOptions::singleton.k_size, cols = (sz - 1) / k + 1;
    int my_number = P.my_real_num();

    uint64_t **input_left, **input_right, **input_result_next, **input_result_prev, **input_mono_next, **input_mono_prev;

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_result_next = new uint64_t*[k];
    input_result_prev = new uint64_t*[k];
    input_mono_next = new uint64_t*[k];
    input_mono_prev = new uint64_t*[k];

    int cnt_non_zeros = 0;
    // int size = results.size();
    for (int i = 0; i < k; i ++) {
        input_left[i] = new uint64_t[cols * 2];
        input_right[i] = new uint64_t[cols * 2];
        input_result_next[i] = new uint64_t[cols * 2];
        input_result_prev[i] = new uint64_t[cols * 2];
        input_mono_next[i] = new uint64_t[cols];
        input_mono_prev[i] = new uint64_t[cols];

        for (int j = 0; j < cols; j ++) {

            if (i * cols + j >= sz) {
                break;
            }

            auto x = input1.pop();
            auto y = input2.pop();
            auto z = results.pop();
            array<typename T::value_type, 2> rho = rhos.pop();

            // x[0]: x_i, x[1]: x_{i-1}
            // y[0]: y_i, y[1]: y_{i-1}
            // z[0]: z_i, z[1]: z_{i-1}
            if (z[0] != x[0] * y[0] + x[1] * y[0] + x[0] * y[1] + rho[0] + rho[1]) {
                cout << "x: " << x[0] << " " << x[1] << endl;
                cout << "y: " << y[0] << " " << y[1] << endl;
                cout << "z: " << z[0] << " " << z[1] << endl;
                cout << "rho: " << rho[0] << " " << rho[1] << endl;

                cout << "sz = " << sz << ", k = " << k << ", cols = " << cols << endl;
                cout << "i = " << i << ", j = " << j << endl;
            }
            assert(z[0] == x[0] * y[0] + x[1] * y[0] + x[0] * y[1] + rho[0] + rho[1]);
            
            uint64_t ti = (z[0] - x[0] * y[0] - rho[0]).get();
            // shared vars between P_i and P_{i-1}
            uint64_t v0 = y[1].get();
            // shared vars between P_i and P_{i+1}
            uint64_t v1 = Mersenne::sub(x[0].get(), 2 * ti * x[0].get());
            // uint64_t v11 = x[0].get() - 2 * ti * x[0].get();
            // shared vars between P_i and P_{i-1}
            uint64_t v2 = Mersenne::sub(2 * rho[1].get() * x[1].get(), x[1].get());
            // uint64_t v22 = x[1].get() - 2 * rho[1].get() * x[1].get();
            // shared vars between P_i and P_{i+1}
            uint64_t v3 = y[0].get();
            // uint64_t v4 = Mersenne::sub(rho[1].get(), ti);
            // uint64_t v44 = rho[1].get() - ti;

            // assert(Mersenne::add(Mersenne::mul(v0, v1), Mersenne::mul(v2, v3)) == v4);
            // assert(v0 * v11 - v22 * v3 == v44);
            if(ti != 0) {
                cnt_non_zeros++;
            }

            input_left[i][j * 2] = v0;
            input_left[i][j * 2 + 1] = v2;
            input_right[i][j * 2] = v1;
            input_right[i][j * 2 + 1] = v3;

            // shared vars between P_i and P_{i-1}
            input_result_prev[i][j * 2] = v0;
            input_result_prev[i][j * 2 + 1] = v2;
            // shared vars between P_i and P_{i+1}
            input_result_next[i][j * 2] = v1;
            input_result_next[i][j * 2 + 1] = v3;


            // cout << "v0: " << v0 << endl;
            // cout << "v1: " << v1 << endl;
            // cout << "v2: " << v2 << endl;
            // cout << "v3: " << v3 << endl;

            uint64_t tii = (z[1] - x[1] * y[1] - rho[1]).get();

            // shared vars between P_i and P_{i-1}
            input_mono_prev[i][j] = Mersenne::neg(tii);
            // shared vars between P_i and P_{i+1}
            input_mono_next[i][j] = rho[0].get();

            // cout << "rho: " << input_mono_prev[i][j] << endl;
            // cout << "-ti: " << input_mono_next[i][j] << endl;

            // // Check inputs
            // cout << "left: " << Mersenne::add(Mersenne::mul(input_left[i][j * 2], input_right[i][j * 2]), Mersenne::mul(input_left[i][j * 2 + 1], input_right[i][j * 2 + 1])) << endl;
            // cout << "right: " << Mersenne::add(input_mono_next[i][j], input_mono_prev[i][j]) << endl;
            // assert(Mersenne::add(Mersenne::mul(input_left[i][j * 2], input_right[i][j * 2]), Mersenne::mul(input_left[i][j * 2 + 1], input_right[i][j * 2 + 1])) == Mersenne::add(input_mono_next[i][j], input_mono_prev[i][j]));
            // assert(Mersenne::add(Mersenne::mul(input_result_next[i][j * 2], input_result_prev[i][j * 2]), Mersenne::mul(input_result_next[i][j * 2 + 1], input_result_prev[i][j * 2 + 1])) == Mersenne::add(input_mono_next[i][j], input_mono_prev[i][j]));
        }
    }

    cout << "prover's non-zeros: " << cnt_non_zeros << endl;

    int cnt = log(2 * sz) / log(k) + 2;
    uint64_t **masks, **mask_ss_next, **mask_ss_prev;
    masks = new uint64_t*[cnt];
    mask_ss_next = new uint64_t*[cnt];
    mask_ss_prev = new uint64_t*[cnt];

    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2*k-1];
        mask_ss_next[i] = new uint64_t[2*k-1];
        mask_ss_prev[i] = new uint64_t[2*k-1];
        for (int j = 0; j < 2 * k - 1; j ++) {
            // P_i and P_{i+1}
            // mask_ss_next[i][j] = shared_prngs[0].get_word() && Mersenne::PR;
            // mask_ss_next[i][j] = Mersenne::modp(shared_prngs[0].get_word());
            mask_ss_next[i][j] = 0;
            // P_i and P_{i-1}
            // mask_ss_prev[i][j] = shared_prngs[1].get_word() && Mersenne::PR;
            // mask_ss_prev[i][j] = Mersenne::modp(shared_prngs[1].get_word());
            mask_ss_prev[i][j] = 0;
            masks[i][j] = 0;
            // masks[i][j] = Mersenne::add(mask_ss_next[i][j], mask_ss_prev[i][j]);
        }
    }

    uint64_t *sid = new uint64_t[3];
    for (int i = 0; i < 3; i ++) {
        sid[i] = global_prng.get_word();
    }
    
    // return;
    DZKProof dzkproof = prove(input_left, input_right, sz, k, sid[my_number], masks);

    status_queue.push_back(StatusData(dzkproof,
                                    input_result_next, 
                                    input_result_prev, 
                                    input_mono_next,
                                    input_mono_prev,
                                    mask_ss_next,
                                    mask_ss_prev,
                                    sid,
                                    sz));

    for (int i = 0; i < k; i ++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for (int i = 0; i < cnt; i ++) {
        delete[] masks[i];
    }

    delete[] masks;

    // cout << "Returned from Check_one()" << endl;
}


template<class T>
void Malicious3PCProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
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

    // cout << "In Malicious3PCProtocol::exchange()" << endl;

    if (os[0].get_length() > 0) {
        exchange_comm += os[0].get_length();
        P.pass_around(os[0], os[1], 1);
    }

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

template <class T>
inline T Malicious3PCProtocol<T>::dotprod_finalize_mul(int n) {
    this->counter++;
    this->bit_counter += n;
    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

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
    return dotprod_finalize_mul();
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
