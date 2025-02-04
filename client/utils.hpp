#pragma once

#include <stdexcept>


template<typename... Fs>
struct overload : Fs... { using Fs::operator()...; };


template<typename T, typename R, typename... Ps>
struct method_ref {
    T& object;
    R (T::*method)(Ps...);

    R operator()(Ps... ps) { return object.*method(ps...); }
};



class KeysNotFound : std::runtime_error { using std::runtime_error::runtime_error; };
class CorruptedKeys : std::runtime_error {
public:
    CorruptedKeys() : std::runtime_error("Encryption keys are corrupted. Manually erase the key file to reset. Note: you will lose the documents.") {}
};
