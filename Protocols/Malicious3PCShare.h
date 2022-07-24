/*
 * Malicious3PCShare.h
 *
 */

#ifndef PROTOCOLS_MALICIOUS3PCSHARE_H_
#define PROTOCOLS_MALICIOUS3PCSHARE_H_

#include "Semi3RingShare.h"
// #include "SpdzWise.h"
// #include "SpdzWiseMC.h"

template<class T> class HashMaliciousRepMC;
template<class T> class SemiRingProtocol;
template<class T> class MaliciousRepPrepWithBits;
template<class T> class MaliciousRepPO;
template<class T> class MaliciousRepPrep;
template<class T> class SpecificPrivateOutput;

namespace GC {
    class MaliciousRepSecret;
}

template <class T>
class Malicious3PCShare : public Semi3RingShare<T> {
    typedef Semi3RingShare<T> super;
    typedef Malicious3PCShare This;

public:
    typedef SemiRingProtocol<Malicious3PCShare<T>> Protocol;
    typedef HashMaliciousRepMC<Malicious3PCShare<T>> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<Malicious3PCShare<T>> Input;
    typedef MaliciousRepPO<This> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef Semi3RingShare<T> Honest;
    typedef MaliciousRepPrepWithBits<Malicious3PCShare> LivePrep;
    typedef MaliciousRepPrep<Malicious3PCShare> TriplePrep;
    typedef Malicious3PCShare prep_type;
    typedef T random_type;
    typedef This Scalar;

    typedef GC::MaliciousRepSecret bit_type;

    typedef T mac_key_type;
    

    const static bool expensive = false;
    const static bool has_trunc_pr = true;
    const static bool malicious = true;

    static string type_short() {
        return "M" + string(1, T::type_char());
    }

    Malicious3PCShare() {}
    Malicious3PCShare(const T& other, int my_num, T alphai = {}):
        super(other, my_num, alphai) {}
    
    template<class U>
    Malicious3PCShare(const U& other): super(other)
    {

    }

};

#endif