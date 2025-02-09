#pragma once

#include <Monocypher.hh>
#include <bsd/readpassphrase.h>
#include <iostream>


using argon2id = monocypher::argon2<monocypher::Argon2id, 32, 400000, 3>;


/// Checks if the password is secure.
template<size_t buf_size>
bool is_password_secure([[maybe_unused]] const std::array<char, buf_size>& password) {
    // TODO: implement
    return true;
}

// The buffer is passed from outside to avoid possible copies that can leave
// the password uncleared.
/// Asks the password to the user in a "secure" manner.
template<size_t buf_size>
void read_password(std::array<char, buf_size>& buf, const char* prompt = "Password: ") {
    // TODO: check if there can be buffers that store the password.
    auto res = readpassphrase(prompt, buf.data(), buf_size, RPP_REQUIRE_TTY | RPP_SEVENBIT);

    if (res == nullptr) {
        monocypher::wipe(buf.data(), buf_size);
        // TODO: change exception
        throw KeysNotFound("Passoword not submitted");
        abort();
    }
}

/// Asks a secure password to the user.
template<size_t buf_size>
void obtain_secure_password(std::array<char, buf_size>& password, const char* prompt = "Password") {
    bool first_time = true;
    do {
        if (!first_time) {
            // TODO: define to the user what "secure" means.
            std::cerr << "Password must be secure" << std::endl;
        }
        read_password(password, prompt);
        first_time = false;
    } while(not is_password_secure(password));
}

// NOTE: both argon2id::salt and argon2id::hash are secret_byte_arrays and are automatically wiped.
/// Creates a salted hash for a password that is storable.
/// The password is internally cleared.
template<size_t buf_size>
std::pair<argon2id::hash, argon2id::salt> derive_key(std::array<char, buf_size>& password) {
    auto hashed_password = argon2id::create(password.data(), strlen(password.data()));
    monocypher::wipe(password.data(), buf_size);

    return hashed_password;
}


// NOTE: both argon2id::salt and argon2id::hash are secret_byte_arrays and are automatically wiped.
/// Creates a salted hash for a password that is storable.
/// The password is internally cleared.
template<size_t buf_size>
argon2id::hash obtain_key(const argon2id::salt& salt, std::array<char, buf_size>& password) {
    auto hashed_password = argon2id::create(password.data(), strlen(password.data()), salt);
    monocypher::wipe(password.data(), buf_size);

    return hashed_password;
}
