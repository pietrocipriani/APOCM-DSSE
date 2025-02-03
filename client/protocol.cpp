#include "protocol.hpp"
#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>

template<size_t lambda>
void Protocol<lambda>::add([[maybe_unused]] const ArgsAdd& args) {
    std::cout << "add" << std::endl;
}

template<size_t lambda>
void Protocol<lambda>::remove([[maybe_unused]] const ArgsRemove& args) {
    std::cout << "remove" << std::endl;
}

template<size_t lambda>
void Protocol<lambda>::search([[maybe_unused]] const ArgsSearch& args) {
    std::cout << "search" << std::endl;
}
