#pragma once

#include <Monocypher.hh>

template<size_t lambda>
class Keystore {
private:

    // NOTE: encrypted keys

    // Documents encryption key
    monocypher::secret_byte_array<lambda> key_d;
    
    monocypher::secret_byte_array<lambda> key_g, key_f, key_t;

public:
    
    void load_keys();

    template<size_t buf_size>
    void create_keys([[maybe_unused]] const std::array<char, buf_size>& password) {
        key_d.randomize();
        key_g.randomize();
        key_f.randomize();
        key_t.randomize();
    }
    
    void store_keys();

    void wipe_keys();

};


template class Keystore<32>;
template class Keystore<64>;
