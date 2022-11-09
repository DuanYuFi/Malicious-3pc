#ifndef PROTOCOLS_MALICIOUS3PCFIELDSHARE_H_
#define PROTOCOLS_MALICIOUS3PCFIELDSHARE_H_

#include "Rep3Share.h"
#include "Math/gfp.h"
#include "Math/Z2k.h"
#include "Malicious3PCFieldProtocol.h"

namespace GC {
    class Malicious3PCSecret;
}

template<class T> class HashMaliciousRepMC;
template<class T> class Beaver;
template<class T> class MaliciousRepPrepWithBits;
template<class T> class MaliciousRepPO;
template<class T> class MaliciousRepPrep;
template<class T> class SpecificPrivateOutput;

template <class T>
class Malicious3PCFieldShare: public Rep3Share<T> {
    typedef Malicious3PCFieldShare This;
    typedef Rep3Share<T> super;

public:
    typedef T clear;

    typedef Malicious3PCFieldProtocol<Malicious3PCFieldShare<T>> Protocol;
    typedef HashMaliciousRepMC<Malicious3PCFieldShare<T>> MAC_Check;
    typedef MAC_Check Direct_MC;
    typedef ReplicatedInput<Malicious3PCFieldShare<T>> Input;
    typedef MaliciousRepPO<Malicious3PCFieldShare> PO;
    typedef SpecificPrivateOutput<This> PrivateOutput;
    typedef Rep3Share<T> Honest;
    typedef MaliciousRepPrepWithBits<Malicious3PCFieldShare> LivePrep;
    typedef MaliciousRepPrep<Malicious3PCFieldShare> TriplePrep;
    typedef Malicious3PCFieldShare prep_type;
    typedef T random_type;
    typedef This Scalar;

    typedef GC::Malicious3PCSecret bit_type;

    typedef T mac_key_type;

    const static bool expensive = true;
    static const bool has_trunc_pr = false;
    static const bool malicious = true;

    static string type_short()
    {
        return "M" + string(1, T::type_char());
    }

    Malicious3PCFieldShare()
    {
    }
    Malicious3PCFieldShare(const T& other, int my_num, T alphai = {}) :
            super(other, my_num, alphai)
    {
    }
    template<class U>
    Malicious3PCFieldShare(const U& other) : super(other)
    {
    }
};

#endif