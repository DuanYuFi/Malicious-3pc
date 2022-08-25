#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_H_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_H_

#include "Replicated.h"
#include "BinaryCheck.h"
#include "Processor/Data_Files.h"
#include "Math/mersenne.hpp"

#include "queue"
#include "SafeQueue.h"
#include <thread>
#include <mutex>
#include <condition_variable>

#define USE_THREAD

// #ifdef USE_THREAD
// #define Queue SafeQueue
// #else
// #define Queue queue
// #endif

#define Queue SafeQueue

template<class T> class SubProcessor;
template<class T> class MAC_Check_Base;
class Player;


struct StatusData {
    DZKProof proof;
    uint64_t **input_shared_prev, **input_shared_next;
    uint64_t **mask_ss_prev, **mask_ss_next;
    int sz;

    StatusData() {}
    StatusData(DZKProof proof, uint64_t **input_shared_prev, uint64_t **input_shared_next, uint64_t **mask_ss_prev, uint64_t **mask_ss_next, int sz) :
        proof(proof), input_shared_prev(input_shared_prev), input_shared_next(input_shared_next), mask_ss_prev(mask_ss_prev), mask_ss_next(mask_ss_next), sz(sz) {}
};

class CV {
private:
    std::mutex mtk;
    condition_variable cv;
    int n_times;

public:

    CV(): n_times(0) {}

    inline void wait() {
        std::unique_lock<std::mutex> lk(this->mtk);
        if (--this->n_times < 0) {
            cv.wait(lk);
        }
    }

    inline void signal() {
        std::unique_lock<std::mutex> lk(this->mtk);
        if (++this->n_times <= 0) {
            cv.notify_one();
        }
    }
};

class SafeBool {
private:
    std::mutex lock;
    bool data;
public:
    inline void set(bool value) {
        lock.lock();
        data = value;
        lock.unlock();
    }

    inline bool get() {
        lock.lock();
        bool value = data;
        lock.unlock();
        return value;
    }
};

typedef pair<bool, bool> ShareType;


/**
 * Three-party replicated secret sharing protocol with MAC modulo a power of two
 */
template<class T>
class Malicious3PCProtocol : public ProtocolBase<T> {
    typedef Replicated<T> super;
    typedef Malicious3PCProtocol This;

    SafeQueue<ShareType> input1, input2, results, rhos;

    SafeQueue<StatusData> status_queue;
    vector<typename T::open_type> opened;
    std::thread check_thread;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares, uids;
    typename T::clear dotprod_share;

    bool returned;
    pthread_mutex_t mutex;
    std::mutex verify_lock;
    CV verify_cv;
    SafeBool isWaiting;

    WaitQueue<bool> cv;

    size_t local_counter, status_counter;

    uint64_t two_inverse = Mersenne::inverse(2);

    const static size_t MAX_STATUS = 100;

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

    // const static int BATCH_SIZE = OnlineOptions::singleton.batch_size;

public:

    static const bool uses_triples = false;

    array<PRNG, 2> shared_prngs, check_prngs;
    // array<PRNG, 2> shared_prngs;
    PRNG global_prng;

    Player& P;

    Malicious3PCProtocol(Player& P);
    Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs);
    ~Malicious3PCProtocol() {
        if (check_thread.joinable()) {
            cv.push(false);
            check_thread.join();
        }
        this->print_debug_info("Binary Part");
        pthread_mutex_destroy(&mutex);
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
        
    Malicious3PCProtocol branch() {
        return {P, shared_prngs};
        // return {P, shared_prngs, check_prngs};
    }

    void check();
    void finalize_check();
    void Check_one();
    void final_verify();
    void thread_handler();
    // void maybe_check();
    int get_n_relevant_players() { return P.num_players() - 1; }

    inline void set_returned(bool value) {
        pthread_mutex_lock(&mutex);
        returned = value;
        pthread_mutex_unlock(&mutex);
    }

    inline bool get_returned() {
        pthread_mutex_lock(&mutex);
        bool value = returned;
        pthread_mutex_unlock(&mutex);
        return value;
    }
};

#endif /* PROTOCOLS_MALICIOUS3PCPROTOCOL_H_ */