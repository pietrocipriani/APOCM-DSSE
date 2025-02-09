#pragma once

#include <Monocypher.hh>
#include "utils.hpp"

template<size_t lambda>
class Keystore {
private:
public:

    // Documents encryption key
    monocypher::secret_byte_array<lambda> key_d;
    
    monocypher::secret_byte_array<lambda> key_g, key_f, key_t;

    monocypher::byte_array<8> con = serialize(-2ULL);

    
    void load_keys();

    void create_keys();
    
    void store_keys();

    void wipe_keys();

};


template class Keystore<32>;
template class Keystore<64>;
