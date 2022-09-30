
#ifndef PROTOCOLS_DEBUGPROTOCOL_HPP_
#define PROTOCOLS_DEBUGPROTOCOL_HPP_

#include "DebugProtocol.h"

#include "Tools/benchmarking.h"
#include "Tools/Bundle.h"

#include "global_debug.hpp"
#include <ctime>
#include <chrono>

template <class T>
DebugProtocol<T>::DebugProtocol(Player &P) : ProtocolBase(P)
{

}

template<class T>
void DebugProtocol<T>::init_mul() {

}


template <class T>
void DebugProtocol<T>::prepare_mul(const T& x, const T& y, int n) {

}

template <class T>
void DebugProtocol<T>::exchange() {

}

template <class T>
inline T DebugProtocol<T>::finalize_mul(int n) {

	T result = 0;
	return result;
}


template<class T>
inline void DebugProtocol<T>::init_dotprod()
{
	
}

template<class T>
inline void DebugProtocol<T>::prepare_dotprod(const T& x, const T& y)
{

}

template<class T>
inline void DebugProtocol<T>::next_dotprod()
{

}

template<class T>
inline T DebugProtocol<T>::finalize_dotprod(int length)
{

	if (DOTPROD_LOG_LEVEL & SHOW_DOTPROD_PROCESS) {
        cout << "In finalize_dotprod()" << endl;
    }

    (void) length;
    this->dot_counter++;
    return finalize_mul();
}

#endif