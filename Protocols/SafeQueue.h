#ifndef FFMPEGS_SAFE_QUEUE_H
#define FFMPEGS_SAFE_QUEUE_H
 
#pragma once
#include <queue>
#include <pthread.h>
 
using namespace std;
 
 
template <typename T>
class SafeQueue{
public:
    SafeQueue(){
        // 锁的初始化
        pthread_mutex_init(&mutex, 0);
        // 线程条件变量的初始化
        pthread_cond_init(&cond, 0);
 
    }
    ~SafeQueue(){
        // 锁的释放
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
    }
 
    void push(T t){
        pthread_mutex_lock(&mutex);  //加锁
        q.push(t);
        // 通知变化 notify
        // 由系统唤醒一个线程
        pthread_cond_signal(&cond);
        // 通知所有的线程
//        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&mutex);  //操作完成后解锁
 
    }
    T pop(){
        pthread_mutex_lock(&mutex);  //加锁
//        if(!q.empty()){
//            t = q.front();
//            q.pop();  //没有返回值，所以使用q.front()拿到首元素 q.back()返回最后一个元素，
//        }
        // queue为空是一直等待，直到下一次push进新的数据  java中是wait和notify
        if(q.empty()) {
            // 挂起状态，释放锁
            pthread_cond_wait(&cond, & mutex);
        }
        // 被唤醒以后
        T t = q.front();
        q.pop();
 
        pthread_mutex_unlock(&mutex);  //操作完成后解锁

        return t;
    }

    // T front() {
    //     return q.front();
    // }

    size_t size() {
        pthread_mutex_lock(&mutex);
        size_t sz = q.size();
        pthread_mutex_unlock(&mutex);
        return sz;
    }

    bool empty() {
        pthread_mutex_lock(&mutex);
        bool ep = q.empty();
        pthread_mutex_unlock(&mutex);
        return ep;
    }
private:
    // 如何保证对这个队列的操作是线程安全的？引入互斥锁
    queue<T> q;
    pthread_mutex_t mutex;
 
    // 创建条件变量
    pthread_cond_t cond;
 
};
 
template <typename T>
class SafeVector{
public:
    SafeVector(){
        // 锁的初始化
        pthread_mutex_init(&mutex, 0);
        // 线程条件变量的初始化
        pthread_cond_init(&cond, 0);
 
    }
    ~SafeVector(){
        // 锁的释放
        pthread_mutex_destroy(&mutex);
        pthread_cond_destroy(&cond);
    }
 
    void push_back(T t){
        pthread_mutex_lock(&mutex);  //加锁
        q.push_back(t);
        // 通知变化 notify
        // 由系统唤醒一个线程
        pthread_cond_signal(&cond);
        // 通知所有的线程
//        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&mutex);  //操作完成后解锁
 
    }
    T pop_back(){
        pthread_mutex_lock(&mutex);  //加锁
//        if(!q.empty()){
//            t = q.front();
//            q.pop();  //没有返回值，所以使用q.front()拿到首元素 q.back()返回最后一个元素，
//        }
        // queue为空是一直等待，直到下一次push进新的数据  java中是wait和notify
        if(q.empty()) {
            // 挂起状态，释放锁
            pthread_cond_wait(&cond, & mutex);
        }
        // 被唤醒以后
        T t = q.back();
        q.pop_back();
 
        pthread_mutex_unlock(&mutex);  //操作完成后解锁

        return t;
    }

    // T front() {
    //     return q.front();
    // }

    size_t size() {
        pthread_mutex_lock(&mutex);
        size_t sz = q.size();
        pthread_mutex_unlock(&mutex);
        return sz;
    }

    bool empty() {
        pthread_mutex_lock(&mutex);
        bool ep = q.empty();
        pthread_mutex_unlock(&mutex);
        return ep;
    }

    void clear() {
        q.clear();
    }

private:
    // 如何保证对这个队列的操作是线程安全的？引入互斥锁
    vector<T> q;
    pthread_mutex_t mutex;
 
    // 创建条件变量
    pthread_cond_t cond;
 
};

template <typename T>
class FixedQueue {
private:
    size_t _size;
    T *data;
    size_t head, tail;

public:
    FixedQueue(): _size(0), head(0), tail(0) {}
    FixedQueue(size_t sz): _size(sz), head(0), tail(0) {
        data = new T[sz];
    }

    ~FixedQueue() {
        delete[] data;
    }

    void print_log() {
        cout << tail << " -> " << head << ", size = " << size() << ", alloced size = " << _size << endl;
    }

    void init(size_t sz) {
        if (_size != 0) {
            delete[] data;
        }
        data = new T[sz];
        _size = sz;
    }

    inline void resize(size_t length) {

        if (length < _size) {
            return ;
        }

        // print_log();

        size_t sz = _size;
        T *tmp = new T[length];

        if (head > tail) {
            memcpy(tmp, data + tail, sizeof(T) * sz);
        }
        else {
            memcpy(tmp + (sz - tail), data, sizeof(T) * head);
            memcpy(tmp, data + tail, sizeof(T) * (sz - tail));
        }
        head = sz; tail = 0;
        delete[] data;
        data = tmp;
        _size = length;
    }

    inline void push(T one_data) {
        data[head++] = one_data;

        if (head >= _size)  head -= _size;

        if (head == tail) {
            // cout << "in push, resize from " << _size << " to " << _size * 2 << endl;
            resize(_size * 2);
        }
        
        else if (head >= _size) {
            head -= _size;
        }
    }

    inline void pop(size_t number_poped) {
        tail += number_poped;
        while (tail >= _size)   tail -= _size;
    }

    void pop() {
        pop(1);
    }

    inline T front() {
        return data[tail];
    }

    inline bool empty() {
        return head == tail;
    }

    inline size_t size() {
        long sz = (long) head - (long) tail;
        if (sz < 0) {
            sz += _size;
        }
        return (size_t) sz;
    }

    inline size_t alloc_size() {
        return _size;
    }

    inline T operator[] (const int a) {
        size_t idx = tail + a;
        while (idx >= _size) {
            idx -= _size;
        }
        while (idx < 0) {
            idx += _size;
        }
        return data[idx];
    }

};
 
#endif //FFMPEGS_SAFE_QUEUE_H