/*
 * mal3pc-field-party.cpp
 *
 */

#include "Protocols/Malicious3PCShare.h"
#include "Processor/FieldMachine.hpp"
#include "Machines/Rep.hpp"
#include "Machines/MalRep.hpp"
#include "Math/gfp.hpp"

#include "Protocols/Malicious3PCProtocol.hpp"
#include "Protocols/BinaryCheck.hpp"

#include "Protocols/SpdzWiseShare.h"
#include "Protocols/MaliciousRep3Share.h"
#include "Protocols/MAC_Check.h"
#include "Protocols/SpdzWiseMC.h"
#include "Protocols/SpdzWisePrep.h"
#include "Protocols/SpdzWiseInput.h"
#include "Math/gf2n.h"
#include "Tools/ezOptionParser.h"
#include "GC/MaliciousCcdSecret.h"

#include "Protocols/Replicated.hpp"
#include "Protocols/MaliciousRepMC.hpp"
#include "Protocols/Share.hpp"
#include "Protocols/fake-stuff.hpp"
#include "Protocols/SpdzWise.hpp"
#include "Protocols/SpdzWisePrep.hpp"
#include "Protocols/SpdzWiseInput.hpp"
#include "Protocols/SpdzWiseShare.hpp"
#include "Processor/Data_Files.hpp"
#include "Processor/Instruction.hpp"
#include "Processor/Machine.hpp"
#include "GC/ShareSecret.hpp"
#include "GC/RepPrep.hpp"
#include "GC/ThreadMaster.hpp"

int main(int argc, const char** argv)
{
    Field::init_field(2305843009213693951, true);
    HonestMajorityFieldMachine<Malicious3PCFieldShare>(argc, argv);
}
