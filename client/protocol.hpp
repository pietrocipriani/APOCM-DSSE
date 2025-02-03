#pragma once

#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdint>


template<size_t lambda>
class Protocol {
private:
    // NOTE: encrypted keys

    // Documents encryption key
    std::array<uint8_t, lambda> key_d;
    
    std::array<uint8_t, lambda> key_g, key_f, key_t;


public:

    void add(const ArgsAdd& args);

    void remove(const ArgsRemove& args);

    void search(const ArgsSearch& args);

};
