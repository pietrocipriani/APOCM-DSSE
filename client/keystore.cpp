#include "keystore.hpp"
#include "utils.hpp"


template<size_t lambda>
void Keystore<lambda>::load_keys() {
    // TODO: implement
    throw KeysNotFound("Cannot load keys");
    abort();
}

template<size_t lambda>
void Keystore<lambda>::store_keys() {
    // TODO: implement
}


template<size_t lambda>
void Keystore<lambda>::wipe_keys() {
    key_d.wipe();
    key_g.wipe();
    key_f.wipe();
    key_t.wipe();
}
