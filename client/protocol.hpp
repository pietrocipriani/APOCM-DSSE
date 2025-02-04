#pragma once

#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <cstdint>
#include <sockpp/unix_connector.h>
#include <Monocypher.hh>


template<size_t lambda = 32>
class Protocol {
private:
    // NOTE: encrypted keys

    // Documents encryption key
    monocypher::byte_array<lambda> key_d;
    
    monocypher::byte_array<lambda> key_g, key_f, key_t;

    sockpp::unix_connector sock;

    bool load_keys();
    void load_or_setup_keys();
    void setup();

public:
    
    Protocol(const sockpp::unix_address& server_addr);
    Protocol(std::string&& server_addr) : Protocol(sockpp::unix_address{server_addr}) {}

    void add(const ArgsAdd& args);

    void remove(const ArgsRemove& args);

    void search(const ArgsSearch& args);

};


template class Protocol<32>;
template class Protocol<64>;
