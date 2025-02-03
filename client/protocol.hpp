#pragma once

#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <cstdint>
#include <sockpp/unix_connector.h>


template<size_t lambda>
class Protocol {
private:
    // NOTE: encrypted keys

    // Documents encryption key
    std::array<uint8_t, lambda> key_d;
    
    std::array<uint8_t, lambda> key_g, key_f, key_t;

    sockpp::unix_connector sock;


public:
    
    Protocol(const sockpp::unix_address& server_addr);
    Protocol(std::string&& server_addr) : Protocol(sockpp::unix_address{server_addr}) {}

    void add(const ArgsAdd& args);

    void remove(const ArgsRemove& args);

    void search(const ArgsSearch& args);

};


template class Protocol<32>;
template class Protocol<64>;
