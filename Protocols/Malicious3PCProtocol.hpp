#ifndef PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_
#define PROTOCOLS_MALICIOUS3PCPROTOCOL_HPP_

#include "Malicious3PCProtocol.h"

#define MAX_STATUS 100

#include "Replicated.h"
#include "Tools/octetStream.h"
#include "Tools/time-func.h"

#include <chrono>
#include <string.h>
#include <fstream>

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P) : P(P) {
    assert(P.num_players() == 3);
    assert(THREAD_NUM > 0);

    // cout << "in Malicious3PCProtocol(Player& P), THREAD_NUM: " << THREAD_NUM << endl;
    // cout<< typeid(typename T::value_type).name() << endl;

    // set_returned(true);

	if (not P.is_encrypted())
		insecure("unencrypted communication");

    status_queue = new StatusData[MAX_STATUS];
    
    shared_prngs[0].ReSeed();
	octetStream os;
	os.append(shared_prngs[0].get_seed(), SEED_SIZE);
	P.send_relative(1, os);
	P.receive_relative(-1, os);
	shared_prngs[1].SetSeed(os.get_data());

    os.reset_write_head();
    if (P.my_real_num() == 0) {
        global_prng.ReSeed();
        os.append(global_prng.get_seed(), SEED_SIZE);
        P.send_all(os);
    }
    else {
        P.receive_player(0, os);
        global_prng.SetSeed(os.get_data());
    }

    // check_prngs.resize(THREAD_NUM);
    // for (auto &prng: check_prngs) {
    //     prng[0].SetSeed(shared_prngs[0]);
    //     prng[1].SetSeed(shared_prngs[1]);
    // }
    check_prngs[0].SetSeed(shared_prngs[0]);
    check_prngs[1].SetSeed(shared_prngs[1]);

    // check_prngs[0].ReSeed();
    // os.clear();
    // os.append(check_prngs[0].get_seed(), SEED_SIZE);
    // P.send_relative(1, os);
    // P.receive_relative(-1, os);
    // check_prngs[1].SetSeed(os.get_data());

    for (int i = 0; i < THREAD_NUM; i ++) {
        // check_threads.push_back(std::thread(&Malicious3PCProtocol<T>::thread_handler, this, i));
        check_threads.push_back(std::thread(&Malicious3PCProtocol<T>::thread_handler, this));
    }

    verify_threads.resize(THREAD_NUM);

    this->local_counter = 0;
    this->status_counter = 0;
    this->checking_id = 0;
    isWaiting.set(false);
    wait_size.set_target(MAX_STATUS);

    input1.init(OnlineOptions::singleton.binary_batch_size * 2);
    input2.init(OnlineOptions::singleton.binary_batch_size * 2);
    rhos.init(OnlineOptions::singleton.binary_batch_size * 2);
    results.init(OnlineOptions::singleton.binary_batch_size * 2);
}

template <class T>
Malicious3PCProtocol<T>::Malicious3PCProtocol(Player& P, array<PRNG, 2>& prngs) :
        P(P)
{
    for (int i = 0; i < 2; i++) {
        shared_prngs[i].SetSeed(prngs[i]);
    }

    // check_prngs.resize(THREAD_NUM);
    // for (auto &prng: check_prngs) {
    //     prng[0].SetSeed(shared_prngs[0]);
    //     prng[1].SetSeed(shared_prngs[1]);
    // }

    check_prngs[0].SetSeed(shared_prngs[0]);
    check_prngs[1].SetSeed(shared_prngs[1]);
}

template <class T>
void Malicious3PCProtocol<T>::check() {
    // if ((int) results.size() < OnlineOptions::singleton.binary_batch_size)
    //     return;
    // Check_one();
}

template <class T>
void Malicious3PCProtocol<T>::init_mul()
{
    // cout << "in init_mul " << endl;

    while (checking_id >= MAX_STATUS) {

        // cout << "in init_mul, calling verify " << endl;
        verify();

        // final_verify();

    }

	for (auto& o : os)
        o.reset_write_head();
    add_shares.clear();
}

template <class T>
void Malicious3PCProtocol<T>::finalize_check() {

    // cout << "in finalize_check" << endl;

    for (int i = 0; i < THREAD_NUM; i ++) {
        // cout << "in finalize_check, pushing false in cv" << endl;
        cv.push(false);
    }
    
    for (auto &each_thread: check_threads) {
        // cout << "in finalize_check, calling thread to join" << endl;
        each_thread.join();
    }

    while (checking_id > 0) {
        // cout << "in finalize_check, checking_id: " << checking_id << ", calling verify" << endl;
        verify();
    }
}

template <class T>
void Malicious3PCProtocol<T>::thread_handler() {
    // ofstream outfile;
    // outfile.open("Thread_P" + to_string(P.my_real_num()) + "_" + to_string(tid));

    // outfile << "in thread_handler, tid: " << tid << endl;
    bool _;
    while (cv.pop(_)) { // listening to the cv queue 监听cv队列，有true就开始证明
        // outfile << "bool _: " << _ << endl;

        if (_ == false) {
            // outfile << "breaking thread_handler loop... tid: " << tid << endl;
            // verify_cv.signal();
            break;
        }

        // this->locks[tid].lock();
        // outfile << "in thread_handler, calling Check_one, tid: " << tid << endl;
        Check_one();
        // if (isWaiting.get() and cv.empty()) {
        //     verify_cv.signal();
        // }
        // this->locks[tid].unlock();

        // cout << "in thread_handler, calling lock, tid: " << tid << endl;
        // this->locks[tid].lock();
        // Check_one();
        // if (isWaiting.get() and cv.empty()) {
        //     cout << "in thread_handler, calling signal, tid: " << tid << endl;
        //     verify_cv.signal();
        // }
        // cout << "in thread_handler, calling unlock, tid: " << tid << endl;
        // this->locks[tid].unlock();
    }
    // outfile << "in thread_handler, out of loop, returning..." << endl;
    return;
}

template <class T>
void Malicious3PCProtocol<T>::verify() {

    // cout << "in Malicious3PCProtocol::verify, this->bit_counter: " << this->bit_counter << endl;
    
    if (checking_id == 0) {
        return ;
    }

    // cout << "results queue: ";
    // results.print_log();

    // sort(status_queue.begin(), status_queue.end());

    // cout << "Verify" << endl;

    int my_number = P.my_real_num();
    int prev_number = my_number == 0 ? 2 : my_number - 1;
    int next_number = my_number == 2 ? 0 : my_number + 1;

    array<octetStream, 2> proof_os, vermsg_os;

    int size = checking_id;
    checking_id = 0;
    
    // cout << "size: " << size << endl;
    
    for (int i = 0; i < size; i ++) {
        DZKProof proof = status_queue[i].proof;
        // cout << proof.get_size() << ", ";
        proof.pack(proof_os[0]);
    }
    // cout << endl;

    this->check_comm += proof_os[0].get_length();
    // cout << "checkpoint 1: " << proof_os[0].get_length() << endl;
    // cout << "in verify, calling pass_around for sending/receiving proof (offset 1)" << endl;
    P.pass_around(proof_os[0], proof_os[1], 1);
    // cout << "in verify, pass_around done" << endl;


    for (int i = 0; i < size; i ++) {
        DZKProof proof;
        uint64_t **input_shared_next = status_queue[i].input_shared_next;
        uint64_t **mask_ss_prev = status_queue[i].mask_ss_prev;
        int sz = status_queue[i].sz;

        // cout << sz << endl;

        int k = OnlineOptions::singleton.k_size;

        int cnt = log(4 * sz) / log(k) + 1;

        proof.unpack(proof_os[1]);
        // cout << "generating vermsg, " << i << "-th proof: " << endl;
        // proof.print_out();

        VerMsg vermsg = gen_vermsg(proof, input_shared_next, sz, k, mask_ss_prev, prev_number, my_number);
        vermsg.pack(vermsg_os[0]);

        for (int j = 0; j < k; j ++) {
            delete[] input_shared_next[j];
        }
        delete[] input_shared_next;

        for (int j = 0; j < cnt; j ++) {
            delete[] mask_ss_prev[j];
        }
        delete[] mask_ss_prev;

    }

    proof_os[1].reset_write_head();

    this->check_comm += proof_os[0].get_length();
    this->check_comm += vermsg_os[0].get_length();
    // cout << "checkpoint 2: " << proof_os[0].get_length() + vermsg_os[0].get_length() << endl;

    // cout << "in verify, calling pass_around for sending/receiving proof (offset -1)" << endl;
    P.pass_around(proof_os[0], proof_os[1], -1);
    // cout << "in verify, pass_around done" << endl;

    // cout << "in verify, calling pass_around for sending/receiving vermsg (offset 1)" << endl;
    P.pass_around(vermsg_os[0], vermsg_os[1], 1);
    // cout << "in verify, pass_around done" << endl;


    for (int i = 0; i < size; i ++) {

        uint64_t **input_shared_prev = status_queue[i].input_shared_prev;
        uint64_t **mask_ss_next = status_queue[i].mask_ss_next;

        int sz = status_queue[i].sz;
        int k = OnlineOptions::singleton.k_size;

        int cnt = log(4 * sz) / log(k) + 1;

        VerMsg received_vermsg;
        received_vermsg.unpack(vermsg_os[1]);

        DZKProof proof;
        proof.unpack(proof_os[1]);

        // cout << "zkp verifying, " << i << "-th proof: " << endl;
        // proof.print_out();
        
        bool res = _verify(proof, input_shared_prev, received_vermsg, sz, k, mask_ss_next, next_number, my_number);
        // cout << "verify_res: " << res << endl;

        for (int j = 0; j < k; j ++) {
            delete[] input_shared_prev[j];
        }
        delete[] input_shared_prev;

        for (int j = 0; j < cnt; j ++) {
            delete[] mask_ss_next[j];
        }
        delete[] mask_ss_next;

        if (!res) {
            // cout << i << "-th proof check failed" << endl;
            throw mac_fail("ZKP check failed");
        }
    }

    status_counter = 0;

    // vector<StatusData>().swap(local_status_datas);

    // cout << "verify end" << endl;
    // status_queue.clear();
}

template <class T>
void Malicious3PCProtocol<T>::Check_one() {

    // ofstream outfile;
    // outfile.open("CheckOne_P" + to_string(P.my_real_num()) + "_" + to_string(tid), ios::app);

    // outfile << "Entering Check_one" << endl;

    int ID;
    
    // outfile << "in Check_one, calling lock" << endl;
    check_lock.lock();
    int sz = min(results.size(), (size_t) OnlineOptions::singleton.binary_batch_size);
    // results.print_log();
    // cout << "size = " << sz << endl;

    if (sz == 0) {
        // outfile << "in Check_one, sz == 0, calling unlock, Exiting Check_one" << endl;
        check_lock.unlock();
        return;
    }

    
    int k = OnlineOptions::singleton.k_size, cols = (sz - 1) / k + 1;
    int cnt = log(4 * sz) / log(k) + 1;

    uint64_t **masks, **mask_ss_next, **mask_ss_prev;

    masks = new uint64_t*[cnt];
    mask_ss_next = new uint64_t*[cnt];
    mask_ss_prev = new uint64_t*[cnt];

    ShareType *_input1, *_input2, *_results, *_rhos;
    _input1 = new ShareType[sz];
    _input2 = new ShareType[sz];
    _results = new ShareType[sz];
    _rhos = new ShareType[sz];

    for (int i = 0; i < sz; i ++) {
        _input1[i] = input1[i];
        _input2[i] = input2[i];
        _results[i] = results[i];
        _rhos[i] = rhos[i];
    }

    input1.pop(sz);
    input2.pop(sz);
    results.pop(sz);
    rhos.pop(sz);


    // for (int i = 0; i < sz; i ++) {
    //     _input1[i] = input1.pop();
    //     _input2[i] = input2.pop();
    //     _results[i] = results.pop();
    //     _rhos[i] = rhos.pop();
    // }

    // outfile << "checking_id: " << checking_id << endl;
    ID = checking_id ++;
    // outfile << "ID: " << ID << endl;
  
    for (int i = 0; i < cnt; i++) {
        masks[i] = new uint64_t[2 * k - 1];
        mask_ss_next[i] = new uint64_t[2 * k - 1];
        mask_ss_prev[i] = new uint64_t[2 * k - 1];

        for (int j = 0; j < 2 * k - 1; j ++) {
            mask_ss_next[i][j] = check_prngs[1].get_word() & Mersenne::PR;
            mask_ss_prev[i][j] = check_prngs[0].get_word() & Mersenne::PR;
            masks[i][j] = Mersenne::add(mask_ss_next[i][j], mask_ss_prev[i][j]);
        }
    }
    // outfile << "in Check_one, calling unlock" << endl;
    // results.print_log();
    check_lock.unlock();

    int temp_pointer = 0;
    uint64_t **input_left, **input_right, **input_shared_next, **input_shared_prev;

    input_left = new uint64_t*[k];
    input_right = new uint64_t*[k];
    input_shared_next = new uint64_t*[k];
    input_shared_prev = new uint64_t*[k];


    for (int i = 0; i < k; i ++) {
        input_left[i] = new uint64_t[cols * 4];
        input_right[i] = new uint64_t[cols * 4];
        input_shared_next[i] = new uint64_t[cols * 4];
        input_shared_prev[i] = new uint64_t[cols * 4];
    
        memset(input_left[i], 0, sizeof(uint64_t) * cols * 4);
        memset(input_right[i], 0, sizeof(uint64_t) * cols * 4);
        memset(input_shared_next[i], 0, sizeof(uint64_t) * cols * 4);
        memset(input_shared_prev[i], 0, sizeof(uint64_t) * cols * 4);
        
        for (int j = 0; j < cols; j++) {

            if (temp_pointer >= sz) {
                break;
            }

            auto x = _input1[temp_pointer];
            auto y = _input2[temp_pointer];
            auto z = _results[temp_pointer];
            auto rho = _rhos[temp_pointer];

            // outfile << "ID: " << ID << endl;
            // outfile << "x: " << x.first << " " << x.second << endl;
            // outfile << "y: " << y.first << " " << y.second << endl;
            // outfile << "z: " << z.first << " " << z.second << endl;
            // outfile << "rho: " << rho.first << " " << rho.second << endl;

            if (z.first != ((x.first & y.first) ^ (x.second & y.first) ^ (x.first & y.second) ^ rho.first ^ rho.second)) {
                // outfile << "Error occured in " << temp_pointer << endl;
                // outfile << "size = " << sz << endl;
                // results.print_log();
            }
            assert(z.first == ((x.first & y.first) ^ (x.second & y.first) ^ (x.first & y.second) ^ rho.first ^ rho.second));
            
            uint64_t a = x.first;
            uint64_t c = y.first;
            uint64_t e = (z.first ^ (x.first & y.first) ^ rho.first);

            uint64_t b = y.second;
            uint64_t d = x.second;
            uint64_t f = rho.second;

            uint64_t t1 = Mersenne::sub(1, 2 * e);
            uint64_t t2 = Mersenne::sub(1, 2 * f);
   
            input_left[i][j * 4] = Mersenne::neg(Mersenne::mul(2 * a * c, t1));
            input_left[i][j * 4 + 1] = c * t1;
            input_left[i][j * 4 + 2] = a * t1;
            input_left[i][j * 4 + 3] = Mersenne::neg(Mersenne::mul(t1, two_inverse));
            input_right[i][j * 4] = Mersenne::mul(b * d, t2);
            input_right[i][j * 4 + 1] = Mersenne::mul(d, t2);
            input_right[i][j * 4 + 2] = Mersenne::mul(b, t2);
            input_right[i][j * 4 + 3] = t2;

            // outfile << "input_left[" << i << "][" << 4 * j << "]: " << input_left[i][4 * j] << endl;
            // outfile << "input_left[" << i << "][" << 4 * j + 1 << "]: " << input_left[i][4 * j + 1] << endl;
            // outfile << "input_left[" << i << "][" << 4 * j + 2 << "]: " << input_left[i][4 * j + 2] << endl;
            // outfile << "input_left[" << i << "][" << 4 * j + 3 << "]: " << input_left[i][4 * j + 3] << endl;

            // outfile << "input_right[" << i << "][" << 4 * j << "]: " << input_right[i][4 * j] << endl;
            // outfile << "input_right[" << i << "][" << 4 * j + 1 << "]: " << input_right[i][4 * j + 1] << endl;
            // outfile << "input_right[" << i << "][" << 4 * j + 2 << "]: " << input_right[i][4 * j + 2] << endl;
            // outfile << "input_right[" << i << "][" << 4 * j + 3 << "]: " << input_right[i][4 * j + 3] << endl;


            uint64_t sum = 0;
            for (int l = 0; l < 4; l++) {
                sum = Mersenne::add(sum, Mersenne::mul(input_left[i][j + l], input_right[i][j + l]));
            }
            // outfile << "sum: " << sum << endl;
            // outfile << "inverse(2): " << Mersenne::neg(two_inverse) << endl;
            assert(sum == Mersenne::neg(two_inverse));

            a = x.second;
            c = y.second;
            e = (z.second ^ (x.second & y.second) ^ rho.second);

            b = y.first;
            d = x.first;
            f = rho.first;

            t1 = Mersenne::sub(1, 2 * e);
            t2 = Mersenne::sub(1, 2 * f);

            input_shared_prev[i][j * 4] = Mersenne::neg(Mersenne::mul(2 * a * c, t1));
            input_shared_prev[i][j * 4 + 1] = c * t1;
            input_shared_prev[i][j * 4 + 2] = a * t1;
            input_shared_prev[i][j * 4 + 3] = Mersenne::neg(Mersenne::mul(t1, two_inverse));
            input_shared_next[i][j * 4] = Mersenne::mul(b * d, t2);
            input_shared_next[i][j * 4 + 1] = Mersenne::mul(d, t2);
            input_shared_next[i][j * 4 + 2] = Mersenne::mul(b, t2);
            input_shared_next[i][j * 4 + 3] = t2;

            // outfile << "input_shared_prev[" << i << "][" << 4 * j << "]: " << input_shared_prev[i][4 * j] << endl;
            // outfile << "input_shared_prev[" << i << "][" << 4 * j + 1 << "]: " << input_shared_prev[i][4 * j + 1] << endl;
            // outfile << "input_shared_prev[" << i << "][" << 4 * j + 2 << "]: " << input_shared_prev[i][4 * j + 2] << endl;
            // outfile << "input_shared_prev[" << i << "][" << 4 * j + 3 << "]: " << input_shared_prev[i][4 * j + 3] << endl;

            // outfile << "input_shared_next[" << i << "][" << 4 * j << "]: " << input_shared_next[i][4 * j] << endl;
            // outfile << "input_shared_next[" << i << "][" << 4 * j + 1 << "]: " << input_shared_next[i][4 * j + 1] << endl;
            // outfile << "input_shared_next[" << i << "][" << 4 * j + 2 << "]: " << input_shared_next[i][4 * j + 2] << endl;
            // outfile << "input_shared_next[" << i << "][" << 4 * j + 3 << "]: " << input_shared_next[i][4 * j + 3] << endl;

            temp_pointer ++;
        }
    }

    // outfile << "in Check_one, calling prove" << endl;
    DZKProof dzkproof = prove(input_left, input_right, sz, k, masks);

    // dzkproof.print_out();

    // outfile << "in Check_one, pushing status_queue, ID: " << ID << endl;
    status_queue[ID] = StatusData(dzkproof,
                                 input_shared_next, 
                                 input_shared_prev, 
                                 mask_ss_next,
                                 mask_ss_prev,
                                 sz);

    // outfile << "in Check_one, ++wait_size" << endl;
    ++wait_size;
    // outfile << "in Check_one, after ++wait_size" << endl;

    for (int i = 0; i < k; i ++) {
        delete[] input_left[i];
        delete[] input_right[i];
    }

    delete[] input_left;
    delete[] input_right;

    for (int i = 0; i < cnt; i ++) {
        delete[] masks[i];
    }

    delete[] masks;

    delete[] _input1;
    delete[] _input2;
    delete[] _results;
    delete[] _rhos;

    // cout << "Finish check" << endl;
    // outfile << "Exiting Check_one" << endl;


}


template<class T>
void Malicious3PCProtocol<T>::prepare_mul(const T& x,
        const T& y, int n)
{
    // cout << "in prepare_mul" << endl;
    // cout<< typeid(typename T::value_type).name() << endl;
    typename T::value_type add_share = x.local_mul(y);

    int this_size = (n == -1 ? T::value_type::length() : n);

    register long x0 = x[0].get(), x1 = x[1].get();
    register long y0 = y[0].get(), y1 = y[1].get();

    check_lock.lock();
    for (register short i = 0; i < this_size; i ++) {
        input1.push(ShareType((x0 >> i) & 1, (x1 >> i & 1)));
        input2.push(ShareType((y0 >> i) & 1, (y1 >> i & 1)));
    }
    check_lock.unlock();

    prepare_reshare(add_share, n);
    // cout << "Exiting prepare_mul" << endl;
}

template<class T>
void Malicious3PCProtocol<T>::prepare_reshare(const typename T::clear& share,
        int n)
{
    typename T::value_type tmp[2];
    for (int i = 0; i < 2; i++) 
        tmp[i].randomize(shared_prngs[i], n);
    
    int this_size = (n == -1 ? T::value_type::length() : n);
    register long rho0 = tmp[0].get(), rho1 = tmp[1].get();

    check_lock.lock();
    for (register short i = 0; i < this_size; i ++) {
        rhos.push(ShareType((rho0 >> i) & 1, (rho1 >> i & 1)));
    }
    check_lock.unlock();

    auto add_share = share + tmp[0] - tmp[1];
    add_share.pack(os[0], n);
    add_shares.push_back(add_share);
}

template<class T>
void Malicious3PCProtocol<T>::exchange()
{

    // cout<< "in exchange" << endl;

    // cout << "Send " << os[0].get_length() << endl;

    if (os[0].get_length() > 0) {
        this->exchange_comm += os[0].get_length();
        P.pass_around(os[0], os[1], 1);
    }

    // cout << "Received " << os[1].get_length() << endl;

    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::start_exchange()
{
    P.send_relative(1, os[0]);
    this->exchange_comm += os[0].get_length();
    this->rounds++;
}

template<class T>
void Malicious3PCProtocol<T>::stop_exchange()
{
    P.receive_relative(-1, os[1]);
}

template<class T>
inline T Malicious3PCProtocol<T>::finalize_mul(int n)
{
    this->counter++;
    this->bit_counter += (n == -1 ? T::value_type::length() : n);

    // cout << "Entering finalize_mul, this->counter: " << this->counter << endl;
    // cout << "in finalize_mul, this->bit_counter: " << this->bit_counter << endl;
    
    // cout<< "this n = " << n << endl;

    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    int this_size = (n == -1 ? T::value_type::length() : n);
    // cout << "in finalize_mul, this_size: " << this_size << endl;
    register long z0 = result[0].get(), z1 = result[1].get();

    // cout << "locking, pushing z0, z1" << endl;
    check_lock.lock();
    for (register short i = 0; i < this_size; i ++) {
        results.push(ShareType((z0 >> i) & 1, (z1 >> i & 1)));
    }
    check_lock.unlock();
    // cout << "unlocked" << endl;
    
    this->local_counter += this_size;
    // cout << "in finalize_mul, this->local_counter: " << this->local_counter << endl;

    while (local_counter >= (size_t) OnlineOptions::singleton.binary_batch_size) {
        local_counter -= OnlineOptions::singleton.binary_batch_size;
        // cout << "check" << endl;
        // cout << "in loop, this->local_counter >= binary_batch_size, this->local_counter: " << this->local_counter << endl;
        cv.push(true);
        status_counter ++;
        // cout << "status_counter: " << status_counter << endl;
        if (status_counter == MAX_STATUS) {

            // isWaiting.set(true);
            // verify_cv.wait();
            // isWaiting.set(false);
            // lock_all();
            // cout << "waiting" << endl;
            wait_size.wait();
            wait_size.unlock();
            // cout << "wait end, calling verify" << endl;
            verify();
            // cout << "after verify" << endl;
            wait_size.reset();
            // verify_cv.reset();
            // unlock_all();

            // cout << "setting is_waiting to true" << endl;
            // isWaiting.set(true);
            // verify_cv.wait();
            // cout << "after waiting, setting is_waiting to false" << endl;
            // isWaiting.set(false);
            // cout << "locking all" << endl;
            // lock_all();
            // cout << "after locking all, calling final_verify " << endl;
            // final_verify();
            // cout << "resetting verify_cv" << endl;
            // verify_cv.reset();
            // cout << "unlocking all" << endl;
            // unlock_all();
            // status_counter = 0;

        }
    }
    // cout << "Exiting finalize_mul" << endl;
    return result;
}

template <class T>
inline T Malicious3PCProtocol<T>::dotprod_finalize_mul(int n) {
    this->counter++;
    // this->bit_counter += n;
    T result;
    result[0] = add_shares.next();
    result[1].unpack(os[1], n);

    return result;
}

template<class T>
inline void Malicious3PCProtocol<T>::init_dotprod()
{
    init_mul();
    dotprod_share.assign_zero();
}

template<class T>
inline void Malicious3PCProtocol<T>::prepare_dotprod(const T& x, const T& y)
{
    dotprod_share = dotprod_share.lazy_add(x.local_mul(y));
}

template<class T>
inline void Malicious3PCProtocol<T>::next_dotprod()
{
    dotprod_share.normalize();
    prepare_reshare(dotprod_share);
    dotprod_share.assign_zero();
}

template<class T>
inline T Malicious3PCProtocol<T>::finalize_dotprod(int length)
{

    (void) length;
    this->dot_counter++;
    return dotprod_finalize_mul();
}

template<class T>
T Malicious3PCProtocol<T>::get_random()
{
    T res;
    for (int i = 0; i < 2; i++)
        res[i].randomize(shared_prngs[i]);
    return res;
}

template<class T>
void Malicious3PCProtocol<T>::randoms(T& res, int n_bits)
{
    for (int i = 0; i < 2; i++)
        res[i].randomize_part(shared_prngs[i], n_bits);
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        false_type)
{
    assert(regs.size() % 4 == 0);
    assert(proc.P.num_players() == 3);
    assert(proc.Proc != 0);
    typedef typename T::clear value_type;
    int gen_player = 2;
    int comp_player = 1;
    bool generate = P.my_num() == gen_player;
    bool compute = P.my_num() == comp_player;
    ArgList<TruncPrTupleWithGap<value_type>> infos(regs);
    auto& S = proc.get_S();

    octetStream cs;
    ReplicatedInput<T> input(P);

    if (generate)
    {
        SeededPRNG G;
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto r = G.get<value_type>();
                input.add_mine(info.upper(r));
                if (info.small_gap())
                    input.add_mine(info.msb(r));
                (r + S[info.source_base + i][0]).pack(cs);
            }
        P.send_to(comp_player, cs);
    }
    else
        input.add_other(gen_player);

    if (compute)
    {
        P.receive_player(gen_player, cs);
        for (auto info : infos)
            for (int i = 0; i < size; i++)
            {
                auto c = cs.get<value_type>() + S[info.source_base + i].sum();
                input.add_mine(info.upper(c));
                if (info.small_gap())
                    input.add_mine(info.msb(c));
            }
    }

    input.add_other(comp_player);
    input.exchange();
    init_mul();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
        {
            this->trunc_pr_counter++;
            auto c_prime = input.finalize(comp_player);
            auto r_prime = input.finalize(gen_player);
            S[info.dest_base + i] = c_prime - r_prime;

            if (info.small_gap())
            {
                auto c_dprime = input.finalize(comp_player);
                auto r_msb = input.finalize(gen_player);
                S[info.dest_base + i] += ((r_msb + c_dprime)
                        << (info.k - info.m));
                prepare_mul(r_msb, c_dprime);
            }
        }

    exchange();

    for (auto info : infos)
        for (int i = 0; i < size; i++)
            if (info.small_gap())
                S[info.dest_base + i] -= finalize_mul()
                        << (info.k - info.m + 1);
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size, U& proc,
        true_type)
{
    (void) regs, (void) size, (void) proc;
    throw runtime_error("trunc_pr not implemented");
}

template<class T>
template<class U>
void Malicious3PCProtocol<T>::trunc_pr(const vector<int>& regs, int size,
        U& proc)
{
    this->trunc_rounds++;
    trunc_pr(regs, size, proc, T::clear::characteristic_two);
}

#endif