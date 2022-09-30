/*
 * Semi-honest ring protocol
 *
 */

#ifndef PROTOCOLS_DEBUGPROTOCOL_H_
#define PROTOCOLS_DEBUGPROTOCOL_H_

#define USE_MY_MULTIPLICATION

#include "Protocols/Replicated.h"
#include "Protocols/MAC_Check_Base.h"
#include "Processor/Input.h"
#include "Protocols/SemiMC.h"
#include "Tools/random.h"

// multiplication protocol
template<class T>
class DebugProtocol : public ProtocolBase<T>
{

public:
    
    static const bool uses_triples = false;

    DebugProtocol() {}
    DebugProtocol(Player& P);

    // Init the protocol
    DebugProtocol(const DebugProtocol<T> &other) : super(other)
    {
        
    }

    ~DebugProtocol() {

    }


    // Public input.
    static void assign(T& share, const typename T::clear& value, int my_num)
    {
        
    }

    // prepare next round of multiplications
    void init_mul();

    // schedule multiplication
    void prepare_mul(const T&, const T&, int = -1);

    // execute protocol
    void exchange();
    
    // return next product
    T finalize_mul(int = -1);

    void init_dotprod();
    void prepare_dotprod(const T& x, const T& y);
    void next_dotprod();
    T finalize_dotprod(int length);

};

#endif /* PROTOCOLS_SEMIRINGPROTOCOL_H_ */
