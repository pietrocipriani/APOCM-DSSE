#include "protocol.hpp"
#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
#include <format>
#include <bsd/readpassphrase.h>
#include <Monocypher.hh>

// The buffer is passed from outside to avoid possible copies that can leave
// the password uncleared.
template<size_t buf_size>
void request_password(std::array<char, buf_size>& buf, const char* prompt = "Password: ") {
    auto res = readpassphrase(prompt, buf.data(), buf_size, RPP_REQUIRE_TTY | RPP_SEVENBIT);

    if (res == nullptr) {
        monocypher::wipe(buf.data(), buf_size);
        throw KeysNotFound("Password not submitted");
        abort();
    }
}



template<size_t buf_size>
bool is_password_secure([[maybe_unused]] const std::array<char, buf_size>& password) {
    return true;
}

template<size_t lambda>
bool Protocol<lambda>::load_keys() {
    throw KeysNotFound("Cannot load keys");
    abort();
}

template<size_t lambda>
void Protocol<lambda>::load_or_setup_keys() {
    try {
        load_keys();
    } catch (const KeysNotFound& e) {
        std::cerr << "Key file not found. Setupping..." << std::endl;
        setup();
    }
}


template<size_t lambda>
void Protocol<lambda>::setup() {
    const size_t buf_size = 256;
    std::array<char, buf_size> raw_password;

    bool first_time = true;
    do {
        if (!first_time) {
            // TODO: define to the user what "secure" means.
            std::cerr << "Password must be secure" << std::endl;
        }
        request_password(raw_password);
        first_time = false;
    } while (!is_password_secure(raw_password));
    std::cout << "Leaked password: " << raw_password.data() << std::endl;

    monocypher::byte_array<raw_password.max_size()> password;
    // NOTE: raw_password is garanteed to contain the terminator, also the fill method also avoids overflows.
    password.fillWithString(raw_password.data());
    monocypher::wipe(raw_password.data(), buf_size);

}

template<size_t lambda>
void Protocol<lambda>::add([[maybe_unused]] const ArgsAdd& args) {
    std::cout << "add" << std::endl;
}

template<size_t lambda>
void Protocol<lambda>::remove([[maybe_unused]] const ArgsRemove& args) {
    std::cout << "remove" << std::endl;
}

template<size_t lambda>
void Protocol<lambda>::search([[maybe_unused]] const ArgsSearch& args) {
    std::cout << "search" << std::endl;
}

template<size_t lambda>
Protocol<lambda>::Protocol(const sockpp::unix_address& server_addr) {

    if (auto res = sock.connect(server_addr); !res) {
        auto msg = std::format("Unable to reach the server: {}", res.error_message());
        //throw std::runtime_error(std::move(msg));
    }

    // TODO: move to specific methods.
    load_or_setup_keys();
    
}
