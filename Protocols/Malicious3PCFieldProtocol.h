#ifndef PROTOCOLS_MALICIOUS3PCFIELDPROTOCOL_H_
#define PROTOCOLS_MALICIOUS3PCFIELDPROTOCOL_H_

#include "Replicated.h"
#include "ArithmeticCheck.h"
#include "Processor/Data_Files.h"
#include "Math/mersenne.hpp"

#include <queue>
#include <thread>
#include <fstream>

#include <chrono>

#define USE_THREAD

// #ifdef USE_THREAD
// #define Queue SafeQueue
// #else
// #define Queue queue
// #endif

// #define Queue SafeQueue

template<class T> class SubProcessor;
template<class T> class MAC_Check_Base;
class Player;


struct ArithStatusData {
    ArithDZKProof proof;
    uint64_t **input_right_prev, **input_left_next;
    uint64_t **mask_ss_prev, **mask_ss_next;
    uint64_t **input_mono_prev, **input_mono_next;
    int sz;

    ArithStatusData() {}
    ArithStatusData(ArithDZKProof proof, uint64_t **_input_right_prev, uint64_t **_input_left_next, uint64_t **_input_mono_prev, uint64_t **_input_mono_next, uint64_t **_mask_ss_prev, uint64_t **_mask_ss_next, int sz) : 
        proof(proof), input_right_prev(_input_right_prev), input_left_next(_input_left_next), mask_ss_prev(_mask_ss_prev), mask_ss_next(_mask_ss_next), input_mono_prev(_input_mono_prev), input_mono_next(_input_mono_next), sz(sz) {}
    
};


// struct ShareTuple {
//     ShareType input1, input2, result, rho;
// };


// #define THREAD_NUM 5
// #define MAX_STATUS 10

/**
 * Three-party replicated secret sharing protocol with MAC modulo a power of two
 */

typedef MyPair<uint64_t, uint64_t> ArithShareType;

template<class T>
class Malicious3PCFieldProtocol : public ProtocolBase<T> {
    typedef Replicated<T> super;
    typedef Malicious3PCFieldProtocol This;

    ArithShareType *input1, *input2, *results, *rhos;
    size_t idx_input, idx_rho, idx_result;
    size_t share_tuple_size;
    const size_t ZOOM_RATE = 2;

    ArithStatusData *status_queue;
    vector<typename T::open_type> opened;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares, uids;
    typename T::clear dotprod_share;

    std::mutex check_lock;
    size_t check_id;

    WaitQueue<int> cv;

    size_t local_counter, status_counter, status_pointer;
    WaitSize wait_size;

    uint64_t two_inverse = Mersenne::inverse(2);

    // const static size_t MAX_STATUS = 100;
    // const static short THREAD_NUM = 4;

    vector<std::thread> check_threads, verify_threads;

    array<octetStream, 2> proof_os, vermsg_os;
    size_t verify_index;
    mutex verify_lock;
    ArithVerMsg *vermsgs;
    WaitQueue<u_char> verify_queue;
    WaitSize verify_tag;
    bool check_passed;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

    // const static int BATCH_SIZE = OnlineOptions::singleton.batch_size;

public:

    typedef typename T::clear value_type;
    
    static const bool uses_triples = false;

    array<PRNG, 2> shared_prngs;
    // array<PRNG, 2> *check_prngs;
    vector<array<PRNG, 2> > check_prngs;

    PRNG global_prng;
    uint64_t sid;

    Player& P;

    Malicious3PCFieldProtocol(Player& P);
    Malicious3PCFieldProtocol(Player& P, array<PRNG, 2>& prngs);
    ~Malicious3PCFieldProtocol() {

        for (int i = 0; i < OnlineOptions::singleton.thread_number; i ++) {
            // cout << "in ~Malicious3PCFieldProtocol, pushing false in cv" << endl;
            verify_queue.push(0);
        }

        cout << "Destroying threads." << endl;
        for (auto &each_thread: verify_threads) {
            each_thread.join();
        }

        cout << "Destroyed." << endl;

        this->print_debug_info("Binary Part");
        cout << "End Mal3pc at " << std::chrono::high_resolution_clock::now().time_since_epoch().count() << endl;
    }
    

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
    T dotprod_finalize_mul(int n = -1);
    T finalize_dotprod(int length);

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    T get_random();
    void randoms(T& res, int n_bits);

    void start_exchange();
    void stop_exchange();
        
    Malicious3PCFieldProtocol branch() {
        return {P, shared_prngs};
        // return {P, shared_prngs, check_prngs};
    }

    void check();
    void finalize_check();
    void Check_one(int node_id, int size = -1);
    void verify();
    void thread_handler(int tid);
    // void maybe_check();
    int get_n_relevant_players() { return P.num_players() - 1; }

    void verify_part1(int prev_number, int my_number);
    void verify_part2(int next_number, int my_number);
    void verify_thread_handler();

    ArithDZKProof arith_prove(
        // int node_id,
        uint64_t** input_left, 
        uint64_t** input_right, 
        uint64_t batch_size, 
        uint64_t k, 
        uint64_t** masks,
        uint64_t sid
    );

    ArithVerMsg arith_gen_vermsg(
        ArithDZKProof proof, 
        uint64_t** input,
        uint64_t** input_mono,
        uint64_t batch_size, 
        uint64_t k, 
        uint64_t** masks_ss,
        uint64_t prover_ID,
        uint64_t party_ID,
        uint64_t sid
    );

    bool arith_verify(
        ArithDZKProof proof, 
        uint64_t** input_right,
        uint64_t** input_mono,
        ArithVerMsg other_vermsg, 
        uint64_t batch_size, 
        uint64_t k, 
        uint64_t** masks_ss,
        uint64_t prover_ID,
        uint64_t party_ID,
        uint64_t sid
    );

};

#endif /* PROTOCOLS_MALICIOUS3PCPROTOCOL_H_ */