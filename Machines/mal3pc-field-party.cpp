/*
 * mal3pc-field-party.cpp
 *
 */

#include "Protocols/Malicious3PCShare.h"
#include "Processor/FieldMachine.hpp"
#include "Machines/Rep.hpp"
#include "Machines/MalRep.hpp"
#include "Tools/my-utils.hpp"
#include "Math/gfp.hpp"
#include "Protocols/Malicious3PCMC.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Instruction.hpp"
#include "Processor/Machine.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"

#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/Malicious3PCShare.h"
#include "Protocols/MalRepRingPrep.h"
#include "Processor/RingOptions.h"
#include "GC/MaliciousCcdSecret.h"

#include "Protocols/ArithmeticCheck.hpp"
#include "Protocols/Replicated.hpp"
#include "Protocols/MaliciousRepMC.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/fake-stuff.hpp"

int main(int argc, const char** argv)
{
    HonestMajorityFieldMachine<Malicious3PCFieldShare>(argc, argv);
}
