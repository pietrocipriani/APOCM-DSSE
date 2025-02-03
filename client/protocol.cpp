#include "protocol.hpp"
#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>


void Protocol::add([[maybe_unused]] const ArgsAdd& args) {
    std::cout << "add" << std::endl;
}

void Protocol::remove([[maybe_unused]] const ArgsRemove& args) {
    std::cout << "remove" << std::endl;
}

void Protocol::search([[maybe_unused]] const ArgsSearch& args) {
    std::cout << "search" << std::endl;
}
