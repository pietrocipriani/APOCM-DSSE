#pragma once

template<typename... Fs>
struct overload : Fs... { using Fs::operator()...; };


template<typename T, typename R, typename... Ps>
struct method_ref {
    T& object;
    R (T::*method)(Ps...);

    R operator()(Ps... ps) { return object.*method(ps...); }
};
