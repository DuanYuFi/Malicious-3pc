#ifndef TOOLS_MYUTILS_HPP
#define TOOLS_MYUTILS_HPP

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

#include "Tools/Hash.h"
#include "Math/mersenne.hpp"
#include "SafeQueue.h"

typedef unsigned __int128 uint128_t;

class WaitSize {

private:
    size_t now;
    size_t target;
    pthread_mutex_t mutex, mutex2;
    pthread_cond_t cond;

public:
    WaitSize(): now(0) {}
    WaitSize(size_t target): now(0), target(target) {}

    void lock()
    {
        // cout << "in lock, calling pthread_mutex_lock" << endl;
        pthread_mutex_lock(&mutex2);
        // cout << "in lock, after calling pthread_mutex_lock" << endl;
    }

    void unlock()
    {
        // cout << "in unlock, calling pthread_mutex_unlock" << endl;
        pthread_mutex_unlock(&mutex2);
        // cout << "in unlock, after calling pthread_mutex_unlock" << endl;

    }

    void wait()
    {
        pthread_cond_wait(&cond, &mutex);
    }

    void signal()
    {
        pthread_cond_signal(&cond);
    }

    void set_target(size_t _target) {
        target = _target;
    }

    void operator ++() {
        // cout << "in WaitSize ++, calling lock " << endl;
        lock();
        now ++;
        // cout << "now: " << now << ", target: " << target << endl;

        if (now == target) {
            // cout << "now == target, sending signal " << endl;
            signal();
            // pthread_mutex_unlock(&mutex);
        }
        // cout << "in WaitSize ++, calling unlock " << endl;
        unlock();
    }

    void reset() {
        now = 0;
    }

};


template <typename T1, typename T2>
struct MyPair {
public:
    T1 first;
    T2 second;

    MyPair(): first(0), second(0) {}
    MyPair(T1 a, T2 b): first(a), second(b) {}
};

class LocalHash {
    octetStream buffer;
public:

    template <typename T>
    void update(T data) {
        buffer.store(data);
    }

    uint64_t final() {
        Hash hash;
        hash.reset();
        hash.update(buffer);
        uint64_t result;
        hash.final().get(result);
        return result;
    }
};

// void get_bases(uint64_t n, uint64_t** result);
// void evaluate_bases(uint64_t n, uint64_t r, uint64_t* result);
// void append_one_msg(LocalHash &hash, uint64_t msg);
// void append_msges(LocalHash &hash, vector<uint64_t> msges);

class DZKP_UTILS {

public:

    static void get_bases(uint64_t n, uint64_t** result) {
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

    static void evaluate_bases(uint64_t n, uint64_t r, uint64_t* result) {

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

    static void append_one_msg(LocalHash &hash, uint64_t msg) {
        hash.update(msg);
    }

    static void append_msges(LocalHash &hash, vector<uint64_t> msges) {
        for(uint64_t msg: msges) {
            hash.update(msg);
        }
    }
};

#endif