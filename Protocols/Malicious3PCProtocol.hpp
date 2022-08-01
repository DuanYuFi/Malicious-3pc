#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_

#include "Malicious3PCProtocol.h"
#include "BinaryCheck.hpp"

#include "Replicated.h"
#include "Tools/octetStream.h"

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P) : prep(0), MC(0), P(P) {
    assert(P.num_players() == 3);
	if (not P.is_encrypted())
		insecure("unencrypted communication");

	shared_prngs[0].ReSeed();
	octetStream os;
	os.append(shared_prngs[0].get_seed(), SEED_SIZE);
	P.send_relative(1, os);
	P.receive_relative(-1, os);
	shared_prngs[1].SetSeed(os.get_data());

    os.clear();
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
    if ((int) results.size() >= BATCH_SIZE)
        check();
}

template <class T>
void Malicious3PCProtocol<T>::init_mul()
{
	assert(this->prep);
	assert(this->MC);

    maybe_check();

	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template <class T>
void Malicious3PCProtocol<T>::init(Preprocessing<T>& prep, typename T::MAC_Check& MC) {
	this->prep = &prep;
	this->MC = &MC;
}

template <class T>
typename T::Protocol Malicious3PCProtocol<T>::branch() {
	typename T::Protocol res(P);
	res.prep = prep;
	res.MC = MC;
	res.shared_prngs = shared_prngs;
	res.init_mul();
	return res;
}

template <class T>
void Malicious3PCProtocol<T>::check() {
	assert(MC);
    for (auto& o : os)
        o.reset_write_head();

    int k = 8, cols = BATCH_SIZE / k;
    int my_number = P.my_real_num();

    uint64_t **input_left, **input_right, **input_result1, **input_result2, **input_mono1, **input_mono2;

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_result1 = new uint64_t*[k];
    input_result2 = new uint64_t*[k];
    input_mono1 = new uint64_t*[k];
    input_mono2 = new uint64_t*[k];

    // int size = results.size();
    for (int i = 0; i < k; i ++) {
        input_left[i] = new uint64_t[cols * 2];
        input_right[i] = new uint64_t[cols * 2];
        input_result1[i] = new uint64_t[cols * 2];
        input_result2[i] = new uint64_t[cols * 2];
        input_mono1[i] = new uint64_t[cols];
        input_mono2[i] = new uint64_t[cols];

        for (int j = 0; j < cols; j ++) {
            auto x = input1.front();    input1.pop();
            auto y = input2.front();    input2.pop();
            auto z = results.front();   results.pop();
            array<typename T::value_type, 2> rho = rhos.front();    rhos.pop();

            uint64_t ti = (z[1] + x[1] * y[1] + rho[1]).get();
            uint64_t v0 = y[0].get();
            uint64_t v1 = x[1].get() - 2 * ti * x[1].get();
            uint64_t v2 = y[1].get();
            uint64_t v3 = x[0].get() - 2 * rho[0].get() * x[0].get();
            // uint64_t v4 = (rho[0]).get() - ti;

            input_left[i][j * 2] = v0;
            input_left[i][j * 2 + 1] = v2;
            input_right[i][j * 2] = v1;
            input_right[i][j * 2 + 1] = v3;

            input_result1[i][j * 2] = v1;
            input_result1[i][j * 2 + 1] = v2;
            input_result2[i][j * 2] = v0;
            input_result2[i][j * 2 + 1] = v3;

            input_mono1[i][j] = ti;
            input_mono2[i][j] = rho[0].get();
        }
    }

    int cnt = log(BATCH_SIZE) / log(k) + 1;
    uint64_t **masks, **mask_ss1, **mask_ss2;
    masks = new uint64_t*[cnt];
    mask_ss1 = new uint64_t*[cnt];
    mask_ss2 = new uint64_t*[cnt];

    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2*k];
        mask_ss1[i] = new uint64_t[2*k];
        mask_ss2[i] = new uint64_t[2*k];
        for (int j = 0; j < 2 * k - 1; j ++) {
            mask_ss1[i][j] = shared_prngs[0].get_word();
            mask_ss2[i][j] = shared_prngs[1].get_word();
            masks[i][j] = Mersenne::add(mask_ss1[i][j], mask_ss2[i][j]);
        }
    }

    uint64_t sid[3];
    for (int i = 0; i < 3; i ++) {
        sid[i] = global_prng.get_word();
    }
    
    DZKProof proof = prove(input_left, input_right, BATCH_SIZE, k, sid[my_number], masks);
    proof.pack(os[0]);
    P.pass_around(os[0], os[1], 1);

    DZKProof received_proof;
    received_proof.unpack(os[1]);

    VerMsg vermsg = gen_vermsg(received_proof, input_result1, input_mono1, BATCH_SIZE, k, sid[(my_number - 1) % 3], mask_ss1, (my_number - 1) % 3, my_number);

    for (auto& o : os)
        o.reset_write_head();

    vermsg.pack(os[0]);
    P.pass_around(os[0], os[1], 1);

    VerMsg received_vermsg;
    received_vermsg.unpack(os[1]);

    bool res = verify(received_proof, input_result2, input_mono2, received_vermsg, BATCH_SIZE, k, sid[(my_number + 1) % 3], mask_ss2, (my_number + 1) % 3, my_number);
    if (!res) {
        throw mac_fail("MAC check failed");
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
    
    rhos.push({});
    auto &rho = rhos.back();
    rho[0] = tmp[0];
    rho[1] = tmp[1];

    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Malicious3PCProtocol<T>::exchange()
{
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