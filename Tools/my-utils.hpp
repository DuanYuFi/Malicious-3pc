#ifndef TOOLS_MYUTILS_H
#define TOOLS_MYUTILS_H

#include "my-utils.h"

void get_bases(uint64_t n, uint64_t** result) {
    for (uint64_t i = 0; i < n - 1; i++) {
        for(uint64_t j = 0; j < n; j++) {
            result[i][j] = 1;
            for(uint64_t l = 0; l < n; l++) {
                if (l != j) {
                    uint64_t denominator, numerator;
                    if (j > l) {
                        denominator = j - l;
                    }
                    else {
                        denominator = Mersenne::neg(l - j);
                    }
                    numerator = i + n - l;
                    result[i][j] = Mersenne::mul(result[i][j], Mersenne::mul(Mersenne::inverse(denominator), numerator));
                }
            }
        }
    }
}

void evaluate_bases(uint64_t n, uint64_t r, uint64_t* result) {

    for(uint64_t i = 0; i < n; i++) {
        result[i] = 1;
        for(uint64_t j = 0; j < n; j++) {
            if (j != i) {
                uint64_t denominator, numerator; 
                if (i > j) { 
                    denominator = i - j;
                } 
                else { 
                    denominator = Mersenne::neg(j - i);
                }
                if (r > j) { 
                    numerator = r - j; 
                } 
                else { 
                    numerator = Mersenne::neg(j - r);
                }
                result[i] = Mersenne::mul(result[i], Mersenne::mul(Mersenne::inverse(denominator), numerator));
            }
        }
    }
}

void append_one_msg(LocalHash &hash, uint64_t msg) {
    hash.update(msg);
}

void append_msges(LocalHash &hash, vector<uint64_t> msges) {
    for(uint64_t msg: msges) {
        hash.update(msg);
    }
}

#endif