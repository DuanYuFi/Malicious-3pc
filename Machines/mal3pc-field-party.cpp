/*
 * mal3pc-field-party.cpp
 *
 */

#include "Processor/FieldMachine.hpp"
#include "Protocols/Malicious3PCShare.h"
// #include "Machines/Rep.hpp"
#include "Machines/MalRep.hpp"
// #include "Tools/my-utils.hpp"
#include "Math/gfp.hpp"

int main(int argc, const char** argv)
{
    HonestMajorityFieldMachine<Malicious3PCFieldShare>(argc, argv);
}
