/*
 * Semi-honest ring protocol
 *
 */

#ifndef PROTOCOLS_TESTPROTOCOL_H_
#define PROTOCOLS_TESTPROTOCOL_H_

#define USE_MY_MULTIPLICATION

#include "Protocols/Replicated.h"
#include "Protocols/MAC_Check_Base.h"
#include "Processor/Input.h"
#include "Protocols/SemiMC.h"
#include "Tools/random.h"

#include <thread>
#include <mutex>
#include <condition_variable>

#include "Tools/SafeQueue.h"

typedef unsigned __int128 uint128_t;
typedef uint64_t MulRing;
typedef uint128_t VerifyRing;

const int N = 64;
const int KAPPA = 40;
const int EBITS = 64;

typedef array<uint64_t, 2> RSShare;
struct MultiShare {
    RSShare x, y;
    RSShare z;
    RSShare rho;

    MultiShare() {
        x = {0, 0};
        y = {0, 0};
        z = {0, 0};
        rho = {0, 0};
    }
    
    MultiShare(RSShare x, RSShare y, RSShare z, RSShare rho) {
        this->x = x;
        this->y = y;
        this->z = z;
        this->rho = rho;
    }
};

template<class T>
class TestProtocol : public ProtocolBase<T>, public ReplicatedBase
{

    typedef ReplicatedBase super;

    array<octetStream, 2> os;
    PointerVector<typename T::clear> add_shares;
    typename T::clear dotprod_share;

    MultiShare *verify_shares;
    size_t pointer, pointer_answer;

    PRNG global_prng, prng_left, prng_verify;
    

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, true_type);
    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc, false_type);

public:
    
    static const bool uses_triples = false;

    TestProtocol() {}
    TestProtocol(Player& P);
    TestProtocol(const ReplicatedBase &other) : 
        ReplicatedBase(other)
    {
    }

    // Init the protocol
    TestProtocol(const TestProtocol<T> &other) : super(other)
    {
        
    }

    ~TestProtocol() {
        while (pointer >= 640000) {
            verify();
            verify();
            pointer -= 640000;
            pointer_answer -= 640000;
        }
        
        // cout << typeid(typename T::clear).name() << endl;
    }


    // Public input.
    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        assert(T::vector_length == 2);
        share.assign_zero();
        if (my_num < 2)
            share[my_num] = value;
        
        share.is_zero_share = true;
    }

    // prepare next round of multiplications
    void init_mul();

    // schedule multiplication
    void prepare_mul(const T&, const T&, int = -1);

    // execute protocol
    void exchange();

    template<class U>
    void trunc_pr(const vector<int>& regs, int size, U& proc);

    // return next product
    T finalize_mul(int = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

    // void multiply(vector<T>& products, vector<pair<T, T>>& multiplicands,
    //         int begin, int end, SubProcessor<T>& proc);

    T get_random();

    void verify();

    template <typename U>
    U inner_product(U* v1, U* v2, size_t length) {
        U res = 0;
        for (size_t i = 0; i < length; i ++) {
            res += v1[i] * v2[i];
        }

        return res;
    }

};

#endif /* PROTOCOLS_SEMIRINGPROTOCOL_H_ */
