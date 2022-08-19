#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_

#include "Malicious3PCProtocol.h"


#include "Replicated.h"
#include "Tools/octetStream.h"

#include <chrono>
#include <string.h>

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P) : P(P) {
    assert(P.num_players() == 3);

    // cout<< typeid(typename T::value_type).name() << endl;

    // set_returned(true);

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

    check_prngs[0].ReSeed();
    os.clear();
    os.append(check_prngs[0].get_seed(), SEED_SIZE);
    P.send_relative(1, os);
    P.receive_relative(-1, os);
    check_prngs[1].SetSeed(os.get_data());

    check_thread = std::thread(&Malicious3PCProtocol<T>::thread_handler, this);
    local_counter = 0;
}

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs) :
        P(P)
{
    for (int i = 0; i < 2; i++) {
        shared_prngs[i].SetSeed(prngs[i]);
        check_prngs[i].SetSeed(prngs[i]);
    }
}

template <class T>
void Malicious3PCProtocol<T>::check() {
    if ((int) results.size() < OnlineOptions::singleton.binary_batch_size)
        return;
}

template <class T>
void Malicious3PCProtocol<T>::init_mul()
{
	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template <class T>
void Malicious3PCProtocol<T>::finalize_check() {

    cv.push(false);
    check_thread.join();
    final_verify();
}

template <class T>
void Malicious3PCProtocol<T>::thread_handler() {
    bool _;
    while (cv.pop(_)) {
        Check_one();
        if (_ == false) {
            break;
        }
    }
}

template <class T>
void Malicious3PCProtocol<T>::final_verify() {

    if (status_queue.empty()) {
        return ;
    }

    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    array<octetStream, 2> proof_os, vermsg_os;

    vector<StatusData> local_status_datas;
    int size = min((int) MAX_STATUS, (int) status_queue.size());
    
    for (int i = 0; i < size; i++) {
        local_status_datas.push_back(status_queue.pop_back());
        DZKProof proof = local_status_datas[i].proof;
        proof.pack(proof_os[0]);
    }

    this->check_comm += proof_os[0].get_length();
    P.pass_around(proof_os[0], proof_os[1], 1);

    for (auto data: local_status_datas) {
        DZKProof proof;
        uint64_t **input_shared_next = data.input_shared_next;
        uint64_t **mask_ss_prev = data.mask_ss_prev;
        int sz = data.sz;
        int k = OnlineOptions::singleton.k_size;

        int cnt = log(4 * sz) / log(k) + 1;

        proof.unpack(proof_os[1]);
        VerMsg vermsg = gen_vermsg(proof, input_shared_next, sz, k, mask_ss_prev, prev_number, my_number);
        vermsg.pack(vermsg_os[0]);

        for (int i = 0; i < k; i ++) {
            delete[] input_shared_next[i];
        }
        delete[] input_shared_next;

        for (int i = 0; i < cnt; i ++) {
            delete[] mask_ss_prev[i];
        }
        delete[] mask_ss_prev;

    }

    proof_os[1].reset_write_head();

    P.pass_around(proof_os[0], proof_os[1], -1);
    P.pass_around(vermsg_os[0], vermsg_os[1], 1);

    this->check_comm += proof_os[0].get_length();
    this->check_comm += vermsg_os[0].get_length();

    for (auto data: local_status_datas) {

        uint64_t **input_shared_prev = data.input_shared_prev;
        uint64_t **mask_ss_next = data.mask_ss_next;

        int sz = data.sz;
        int k = OnlineOptions::singleton.k_size;

        int cnt = log(4 * sz) / log(k) + 1;

        VerMsg received_vermsg;
        received_vermsg.unpack(vermsg_os[1]);

        DZKProof proof;
        proof.unpack(proof_os[1]);
        
        bool res = verify(proof, input_shared_prev, received_vermsg, sz, k, mask_ss_next, next_number, my_number);
        
        for (int i = 0; i < k; i ++) {
            delete[] input_shared_prev[i];
        }
        delete[] input_shared_prev;

        for (int i = 0; i < cnt; i ++) {
            delete[] mask_ss_next[i];
        }
        delete[] mask_ss_next;

        if (!res) {
            throw mac_fail("ZKP check failed");
        }
    }
}

template <class T>
void Malicious3PCProtocol<T>::Check_one() {
    
    int sz = min((int) results.size(), OnlineOptions::singleton.binary_batch_size);

    // cout << "size = " << sz << endl;

    if (sz == 0) {
        return;
    }

    int k = OnlineOptions::singleton.k_size, cols = (sz - 1) / k + 1;
    
    uint64_t **input_left, **input_right, **input_shared_next, **input_shared_prev;

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_shared_next = new uint64_t*[k];
    input_shared_prev = new uint64_t*[k];

    for (int i = 0; i < k; i ++) {
        input_left[i] = new uint64_t[cols * 4];
        input_right[i] = new uint64_t[cols * 4];
        input_shared_next[i] = new uint64_t[cols * 4];
        input_shared_prev[i] = new uint64_t[cols * 4];
    
        memset(input_left[i], 0, sizeof(uint64_t) * cols * 4);
        memset(input_right[i], 0, sizeof(uint64_t) * cols * 4);
        memset(input_shared_next[i], 0, sizeof(uint64_t) * cols * 4);
        memset(input_shared_prev[i], 0, sizeof(uint64_t) * cols * 4);
        
        for (int j = 0; j < cols; j++) {

            if (i * cols + j >= sz) {
                break;
            }

            auto x = input1.pop();
            auto y = input2.pop();
            auto z = results.pop();
            auto rho = rhos.pop();

            assert(z.first == ((x.first & y.first) ^ (x.second & y.first) ^ (x.first & y.second) ^ rho.first ^ rho.second));
            
            uint64_t a = x.first;
            uint64_t c = y.first;
            uint64_t e = (z.first ^ (x.first & y.first) ^ rho.first);

            uint64_t b = y.second;
            uint64_t d = x.second;
            uint64_t f = rho.second;

            uint64_t t1 = Mersenne::sub(1, 2 * e);
            uint64_t t2 = Mersenne::sub(1, 2 * f);
   
            input_left[i][j * 4] = Mersenne::neg(Mersenne::mul(2 * a * c, t1));
            input_left[i][j * 4 + 1] = c * t1;
            input_left[i][j * 4 + 2] = a * t1;
            input_left[i][j * 4 + 3] = Mersenne::neg(Mersenne::mul(t1, two_inverse));
            input_right[i][j * 4] = Mersenne::mul(b * d, t2);
            input_right[i][j * 4 + 1] = Mersenne::mul(d, t2);
            input_right[i][j * 4 + 2] = Mersenne::mul(b, t2);
            input_right[i][j * 4 + 3] = t2;

            uint64_t sum = 0;
            for (int l = 0; l < 4; l++) {
                sum = Mersenne::add(sum, Mersenne::mul(input_left[i][j + l], input_right[i][j + l]));
            }
            assert(sum = Mersenne::neg(two_inverse));

            a = x.second;
            c = y.second;
            e = (z.second ^ (x.second & y.second) ^ rho.second);

            b = y.first;
            d = x.first;
            f = rho.first;

            t1 = Mersenne::sub(1, 2 * e);
            t2 = Mersenne::sub(1, 2 * f);

            input_shared_prev[i][j * 4] = Mersenne::neg(Mersenne::mul(2 * a * c, t1));
            input_shared_prev[i][j * 4 + 1] = c * t1;
            input_shared_prev[i][j * 4 + 2] = a * t1;
            input_shared_prev[i][j * 4 + 3] = Mersenne::neg(Mersenne::mul(t1, two_inverse));
            input_shared_next[i][j * 4] = Mersenne::mul(b * d, t2);
            input_shared_next[i][j * 4 + 1] = Mersenne::mul(d, t2);
            input_shared_next[i][j * 4 + 2] = Mersenne::mul(b, t2);
            input_shared_next[i][j * 4 + 3] = t2;

        }
    }

    int cnt = log(4 * sz) / log(k) + 1;

    uint64_t **masks, **mask_ss_next, **mask_ss_prev;

    masks = new uint64_t*[cnt];
    mask_ss_next = new uint64_t*[cnt];
    mask_ss_prev = new uint64_t*[cnt];

    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2 * k - 1];
        mask_ss_next[i] = new uint64_t[2 * k - 1];
        mask_ss_prev[i] = new uint64_t[2 * k - 1];

        for (int j = 0; j < 2 * k - 1; j ++) {
            mask_ss_next[i][j] = check_prngs[1].get_word() & Mersenne::PR;
            mask_ss_prev[i][j] = check_prngs[0].get_word() & Mersenne::PR;
            masks[i][j] = Mersenne::add(mask_ss_next[i][j], mask_ss_prev[i][j]);
        }
    }
   
    DZKProof dzkproof = prove(input_left, input_right, sz, k, masks);

    status_queue.push_back(StatusData(dzkproof,
                                    input_shared_next, 
                                    input_shared_prev, 
                                    mask_ss_next,
                                    mask_ss_prev,
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

}


template<class T>
void Malicious3PCProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    // cout<< typeid(typename T::value_type).name() << endl;
    typename T::value_type add_share = x.local_mul(y);

    int this_size = (n == -1 ? T::value_type::length() : n);

    register long x0 = x[0].get(), x1 = x[1].get();
    register long y0 = y[0].get(), y1 = y[1].get();

    for (register short i = 0; i < this_size; i ++) {
        input1.push(ShareType((x0 >> i) & 1, (x1 >> i & 1)));
        input2.push(ShareType((y0 >> i) & 1, (y1 >> i & 1)));
    }

    prepare_reshare(add_share, n);

}

template<class T>
void Malicious3PCProtocol<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++) 
        tmp[i].randomize(shared_prngs[i], n);
    
    int this_size = (n == -1 ? T::value_type::length() : n);
    register long rho0 = tmp[0].get(), rho1 = tmp[1].get();

    for (register short i = 0; i < this_size; i ++) {
        rhos.push(ShareType((rho0 >> i) & 1, (rho1 >> i & 1)));
    }

    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Malicious3PCProtocol<T>::exchange()
{

    // cout<< "In Malicious3PCProtocol::exchange()" << endl;

    if (os[0].get_length() > 0) {
        this->exchange_comm += os[0].get_length();
        P.pass_around(os[0], os[1], 1);
    }

    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::start_exchange()
{
    P.send_relative(1, os[0]);
    this->exchange_comm += os[0].get_length();
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
    this->bit_counter += (n == -1 ? T::value_type::length() : n);

    // cout<< "this n = " << n << endl;

    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    int this_size = (n == -1 ? T::value_type::length() : n);
    register long z0 = result[0].get(), z1 = result[1].get();
    for (register short i = 0; i < this_size; i ++) {
        results.push(ShareType((z0 >> i) & 1, (z1 >> i & 1)));
    }
    
    local_counter += this_size;
    while (local_counter >= (size_t) OnlineOptions::singleton.batch_size) {
        local_counter -= OnlineOptions::singleton.batch_size;
        cv.push(true);
        if (status_queue.size() >= MAX_STATUS) {
            final_verify();
        }
    }


    return result;
}

template <class T>
inline T Malicious3PCProtocol<T>::dotprod_finalize_mul(int n) {
    this->counter++;
    // this->bit_counter += n;
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