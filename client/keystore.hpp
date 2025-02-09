#pragma once

#include <Monocypher.hh>
#include "utils.hpp"

/// Stores the state theta of the protocol.
/// The state is loaded on-demand, but the keys are stored in clear.
/// The caller should load and wipe the keys when they are not needed.
template<size_t lambda>
class Keystore {
private:
public:

    // TODO: private but with friends.

    /// Documents encryption key
    monocypher::secret_byte_array<lambda> key_d;
    
    /// The other keys
    monocypher::secret_byte_array<lambda> key_g, key_f, key_t;

    monocypher::byte_array<8> con = serialize(-2ULL);

    /// Loads and decrypts the keys from the key-file.
    /// Decryption is performed by asking the password to the user.
    void load_keys();

    /// Creates fresh keys.
    void create_keys();
    
    /// Store the keys (and con) in the key-file.
    /// The keys are encrypted with an user-provided password.
    /// NOTE: the keystore is wiped.
    void store_keys();

    /// Wipes the keys on ram.
    void wipe_keys();

};


template class Keystore<32>;
template class Keystore<64>;
