#include "protocol.hpp"
#include "argparse.hpp"
#include "utils.hpp"
#include "password_utils.hpp"
#include <iostream>
#include <stdexcept>
#include <format>
#include <Monocypher.hh>


template<size_t lambda>
void Protocol<lambda>::load_or_setup_keys() {
    try {
        keystore.load_keys();
    } catch (const KeysNotFound& e) {
        std::cerr << "Key file not found. Setup..." << std::endl;
        setup();
    }
}


template<size_t lambda>
void Protocol<lambda>::setup() {
    const size_t buf_size = 256;
    std::array<char, buf_size> password;
    obtain_secure_password(password, "Choose password: ");

    keystore.create_keys(password);
    monocypher::wipe(password.data(), buf_size);
}

template<size_t lambda>
void Protocol<lambda>::add([[maybe_unused]] const ArgsAdd& args) {

    // NOTE: memory issues can arise.
    KTMap index;
    // TODO: fill map.
    
    
    load_or_setup_keys();

    // NOTE: this can lead to memory issues, however sending while encrypting increases the key exposure in memory.
    auto encrypted_index = process(Operation::add, index);
    auto docs = encrypt_documents(args);

    keystore.wipe();

    send(encrypted_index);
    send(docs);

    print_response();
}

template<size_t lambda>
void Protocol<lambda>::remove([[maybe_unused]] const ArgsRemove& args) {
    std::cout << "Removal is not implemented" << std::endl;
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

    // TODO: ensure the server authenticity.

}

template<size_t lambda>
Data Protocol<lambda>::process(Operation op, const KTMap& index) const {
    // Blake2b as prf and hash function.
    using prf = monocypher::hash<monocypher::Blake2b<32>>;
    using hash = monocypher::hash<monocypher::Blake2b<32>>;
    using prp = monocypher::symmetric_key;
    using value = byte_array<hash::Size + sizeof(uint64_t) + hash::Size>;

    unordered_map<hash, value> encrypted_index;

    for (auto& [keyword, docs] : index) { // TODO: find how to do this.
        auto [start, end] = index.equal_range(keyword);

        // TODO: keywords should be erased to avoid to correlate keys with hashes.
        auto kt = prf::createMAC(keyword, keystore.key_f);
        auto key = hash::create(kt | keystore.con);
        auto addr = hash::create(key | 1);

        for (auto& uuid : docs) {
            byte_array<hash::Size> rn(0);

            // If this is not the last document, then rn must be a non-zero random sequence.
            while (std::next(start) != end && rn == byte_array(0)) {
                rn.random();
            }

            auto sk = prf::createMAC(keyword | keystore.con, keystore.key_g);
            auto eid = prp::lock(uuid | op, sk);
            static_assert(dectype(eid)::Size == hash::Size);

            auto val = (hash::create(key | 0) ^ eid) | con | rn;

            encrypted_index[addr] = val;

            addr ^= rn;
        }
    }

    // TODO: convert encrypted_index to data.
}

