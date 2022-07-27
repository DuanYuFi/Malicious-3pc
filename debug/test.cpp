#include <queue>
#include <iostream>
#include <mutex>

using namespace std;

class A {
    
    std::mutex mtx;
public:

    int a;
    void init() {
        a = 1;
    }

};

class B : public A {

    typedef A super;

public:

    int x;

    B() {}
    B(const B& b) : super() {
        a = b.a;
    }

    void init() {
        super::init();
        a += 1;
    }

};

int main() {
    B b;
    b.init();
    B c = b;
    cout << b.x << endl;
    cout << c.x << endl;
    return 0;
}