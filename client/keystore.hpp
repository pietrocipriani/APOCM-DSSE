#pragma once

#include <Monocypher.hh>

template<size_t lambda>
class Keystore {
private:
public:

    // Documents encryption key
    monocypher::secret_byte_array<lambda> key_d;
    
    monocypher::secret_byte_array<lambda> key_g, key_f, key_t;

    monocypher::byte_array<8> con{0xff};

    
    void load_keys();

    template<size_t buf_size>
    void create_keys([[maybe_unused]] const std::array<char, buf_size>& password) {
        key_d.randomize();
        key_g.randomize();
        key_f.randomize();
        key_t.randomize();
        con.fill(0xff);
    }
    
    void store_keys();

    void wipe_keys();

};


template class Keystore<32>;
template class Keystore<64>;
