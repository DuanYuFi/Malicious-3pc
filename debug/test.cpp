#include <iostream>
#include <cstdio>

using namespace std;

int main() {
    unsigned long a = 2773165201, b = 3500405213;
    unsigned long a1 = a >> 32, a2 = a & 0xFFFFFFFF;
    unsigned long b1 = b >> 32, b2 = b & 0xFFFFFFFF;

    unsigned long upper = 0, lower = 0;
    unsigned long tmp = a1 * b2 + a2 * b1;

    upper = a1 * b1 + (tmp >> 32);
    lower = a2 * b2 + (tmp & 0xFFFFFFFF);

    printf("a1 = %lu, a2 = %lu\n", a1, a2);
    printf("b1 = %lu, b2 = %lu\n", b1, b2);

    cout << a << " " << b << endl;
    cout << hex << upper << " " << lower << endl;


    return 0;
}