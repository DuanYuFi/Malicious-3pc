#include <queue>
#include <iostream>

using namespace std;

class A {
    

public:

    int a;
    void init() {
        a = 1;
    }

};

class B : public A {

    typedef A super;

public:

    void init() {
        super::init();
        a += 1;
    }

};

int main() {
    B b;
    b.init();
    cout << b.a << endl;
    return 0;
}