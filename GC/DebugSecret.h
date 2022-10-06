#ifndef GC_DEBUGSECRET_H
#define GC_DEBUGSECRET_H

#include "ShareSecret.h"

namespace GC {

class DebugSecret : public ReplicatedSecret<DebugSecret>
{
    typedef ReplicatedSecret<DebugSecret> super;

public:
    typedef Memory<DebugSecret> DynamicMemory;

    typedef ReplicatedMC<DebugSecret> MC;
    typedef Replicated<DebugSecret> Protocol;
    typedef MC MAC_Check;
    typedef SemiHonestRepPrep LivePrep;
    typedef ReplicatedInput<DebugSecret> Input;

    typedef DebugSecret part_type;
    typedef SmallRepSecret small_type;
    typedef DebugSecret whole_type;

    static const bool expensive_triples = false;

    static MC* new_mc(mac_key_type) { return new MC; }

    DebugSecret() {}
    template<class T>
    DebugSecret(const T& other) : super(other) {}
};

}

#endif