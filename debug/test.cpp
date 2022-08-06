// #include "Math/Z2k.hpp"
// #include "Math/gfp.hpp"
// #include "Math/bigint.hpp"
// #include "Math/BitVec.h"

#include <iostream>
#include <queue>
#include <chrono>
#include "SafeQueue.h"

using namespace std;

const int N = 3e6;

template <typename T>
int time_cost(T q) {
    auto start = chrono::high_resolution_clock::now();
    for (int i = 0; i < N; i++) {
        q.push(i);
    }
    for (int i = 0; i < N; i++) {
        q.pop();
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
    return duration.count();
}

int main() {

    queue<int> q1;
    SafeQueue<int> q2;

    cout << "queue: " << time_cost(q1) << endl;
    cout << "SafeQueue: " << time_cost(q2) << endl;

    return 0;
}