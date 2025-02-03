#include "protocol.hpp"
#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
#include <format>

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
        throw std::runtime_error(std::move(msg));
    }

    
}
