#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_H_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_H_

#include "Replicated.h"
#include "BinaryCheck.h"
#include "Processor/Data_Files.h"

#include "queue"
#include "SafeQueue.h"
#include <thread>

#define USE_THREAD

#ifdef USE_THREAD
#define Queue SafeQueue
#else
#define Queue queue
#endif

template<class T> class SubProcessor;
template<class T> class MAC_Check_Base;
class Player;


struct StatusData {
    DZKProof proof;
    uint64_t **input_result_up, **input_result_down, **input_mono_up, **input_mono_down;
    uint64_t **mask_ss_up, **mask_ss_down;
    uint64_t *sid;
    int sz;

    StatusData() {}
    StatusData(DZKProof proof, uint64_t **input_result_up, uint64_t **input_result_down, uint64_t **input_mono_up, uint64_t **input_mono_down, uint64_t **mask_ss_up, uint64_t **mask_ss_down, uint64_t *sid, int sz) :
        proof(proof), input_result_up(input_result_up), input_result_down(input_result_down), input_mono_up(input_mono_up), input_mono_down(input_mono_down), mask_ss_up(mask_ss_up), mask_ss_down(mask_ss_down), sid(sid), sz(sz) {}
};


/**
 * Three-party replicated secret sharing protocol with MAC modulo a power of two
 */
template<class T>
class Malicious3PCProtocol : public ProtocolBase<T> {
    typedef Replicated<T> super;
    typedef Malicious3PCProtocol This;

    Queue<T> input1, input2, results;
    Queue<array<typename T::value_type, 2>> rhos;

    vector<StatusData> status_queue;
    // Queue<VerMsg> vermsg_queue;
    vector<typename T::open_type> opened;
    // Preprocessing<T>* prep;
    // typename T::MAC_Check* MC;
    std::thread check_thread;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares, uids;
    typename T::clear dotprod_share;

    bool returned;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

    // const static int BATCH_SIZE = OnlineOptions::singleton.batch_size;

public:

    static const bool uses_triples = false;

    int total_and_gates, exchange_comm, check_comm;

    array<PRNG, 2> shared_prngs;
    PRNG global_prng;

    Player& P;

    Malicious3PCProtocol(Player& P);
    Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs);
    ~Malicious3PCProtocol();
    
    // Replicated(const ReplicatedBase& other);

    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num < 2)
            share[my_num] = value;
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
        
    Malicious3PCProtocol branch() {
        return {P, shared_prngs};
    }

    void check();
    void finalize_check();
    void Check_one();
    void final_verify();
    // void maybe_check();
    int get_n_relevant_players() { return P.num_players() - 1; }
};

#endif /* PROTOCOLS_MALICIOUS3PCPROTOCOL_H_ */
