#include <queue>
#include "SafeQueue.h"
#include <thread>
#include <mutex>
#include <condition_variable>


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
