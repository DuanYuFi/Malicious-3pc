#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_H_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_H_

#include "Replicated.h"
#include "Processor/Data_Files.h"

#include "queue"

template<class T> class SubProcessor;
template<class T> class MAC_Check_Base;
class Player;

/**
 * Three-party replicated secret sharing protocol with MAC modulo a power of two
 */
template<class T>
class Malicious3PCProtocol : public ProtocolBase<T> {
    typedef Replicated<T> super;
    typedef Malicious3PCProtocol This;

    queue<T> results, input1, input2;
    queue<array<typename T::value_type, 2>> rhos;
    vector<typename T::open_type> opened;
    Preprocessing<T>* prep;
    typename T::MAC_Check* MC;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares, uids;
    typename T::clear dotprod_share;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

    const int BATCH_SIZE = 100000;

public:

    static const bool uses_triples = false;

    array<PRNG, 2> shared_prngs;
    PRNG global_prng;

    Player& P;

    Malicious3PCProtocol(Player& P);
    Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs);
    
    // Replicated(const ReplicatedBase& other);

    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num > 0)
            share[my_num - 1] = value;

        share.is_zero_share = true;
    }

    void init_mul();
    void prepare_mul(const T& x, const T& y, int n = -1);
    void exchange();
    T finalize_mul(int n = -1);

    void prepare_reshare(const typename T::clear& share, int n = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    T get_random();
    void randoms(T& res, int n_bits);

    void start_exchange();
    void stop_exchange();
    
    void init(Preprocessing<T>& prep, typename T::MAC_Check& MC);
    typename T::Protocol branch();
    void check();
    void maybe_check();
    int get_n_relevant_players() { return P.num_players() - 1; }
};

#endif /* PROTOCOLS_MALICIOUS3PCPROTOCOL_H_ */
