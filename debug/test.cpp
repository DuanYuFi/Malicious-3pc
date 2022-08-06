// #include "Math/Z2k.hpp"
// #include "Math/gfp.hpp"
// #include "Math/bigint.hpp"
// #include "Math/BitVec.h"

#include <iostream>
#include <queue>
#include <chrono>
#include "Protocols/BinaryCheck.hpp"
#include "Tools/octetStream.cpp"

using namespace std;

const int N = 3e6;


int main() {

    DZKProof proof;
    vector <uint64_t> v;
    for (int i = 0; i < 10; i ++) {
        v.push_back(i);
    }

    vector<vector<uint64_t>> p_evals_masked;
    p_evals_masked.push_back(v);
    p_evals_masked.push_back(v);
    p_evals_masked.push_back(v);

    proof.p_evals_masked = p_evals_masked;

    octetStream os;
    proof.pack(os);

    DZKProof proof2;
    proof2.unpack(os);

    for (auto each: proof2.p_evals_masked) {
        for (auto each2: each) {
            cout << each2 << " ";
        }
        cout << endl;
    }

    return 0;
}