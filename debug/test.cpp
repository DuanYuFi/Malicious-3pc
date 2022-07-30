#include <queue>
#include <iostream>
#include <mutex>

using namespace std;

class A {
    
public:

    int a;
    void init() {
        a = 1;
    }

};

class B {

public:
    int a;
    void init() {
        a = 2;
    }
};

class C: public A, public B {
public:
int a;
    void init() {
        A::init();
    }
};

int main() {
    C c;
    c.init();
    cout << c.a << endl;
    return 0;
}