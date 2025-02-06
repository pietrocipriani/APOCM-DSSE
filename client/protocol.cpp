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
void Protocol<lambda>::add(const ArgsAdd& args) {

    // NOTE: memory issues can arise.
    KTMap index;
    // TODO: fill map.
    
    
    load_or_setup_keys();

    // NOTE: this can lead to memory issues, however sending while encrypting increases the key exposure in memory.
    auto encrypted_index = process(Operation::add, index);
    auto docs = encrypt_documents(args);

    keystore.wipe_keys();

    send("add-----");
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
Protocol<lambda>::Data Protocol<lambda>::process(Operation op, const KTMap& index) const {
    // Blake2b as prf (keyed) and hash (unkeyed) function.
    using prf = monocypher::hash<monocypher::Blake2b<32>>;
    using hash = monocypher::hash<monocypher::Blake2b<64>>;
    using prp = monocypher::session::encryption_key<monocypher::XChaCha20_Poly1305>;
    using key = monocypher::byte_array<hash::Size>;
    using value = monocypher::byte_array<hash::Size + decltype(Keystore<lambda>::con)::byte_count + hash::Size>;

    std::unordered_map<key, value> encrypted_index;

    for (auto& [keyword, docs] : index) {
        auto [start, end] = index.equal_range(keyword);

        auto kt = prf::createMAC(keyword.data(), keyword.length(), keystore.key_f);

        auto key = hash::create(kt | keystore.con);
        monocypher::byte_array addr = hash::create(key | one<1>);

        for (auto& uuid : docs) {
            monocypher::byte_array<hash::Size> rn(0);

            // If this is not the last document, then rn must be a non-zero random sequence.
            while (std::next(start) != end and rn == zero<hash::Size>) {
                rn.randomize();
            }

            // NOTE: like in the paper.
            // It is possible to only compute sk once, however in this case it is 
            // not possible to wipe it, so it will reside in memory longer.
            // However sk is completely obtainable from other secrets stored in memory.
            // This doesn't allow to clear the keyword, allowing to create correspondences
            // between keywords and kts in case of memory dumps.
            auto sk_plain = keyword | keystore.con;
            auto sk = prf::createMAC(sk_plain.data(), sk_plain.size(), keystore.key_g);
            monocypher::wipe(sk_plain.data(), sk_plain.size());

            // randomized nonce. It MUST NOT be reused.
            monocypher::session::nonce nonce{};
            auto op_id = std::to_underlying(op);
            auto data = uuid | monocypher::byte_array<8>(op_id);
            auto mac = prp(sk).lock(nonce, data.data(), data.size(), data.data());
            sk.wipe();
            auto eid = mac | nonce | data;

            auto val = (hash::create(key | zero<1>) ^ eid) | keystore.con | rn;

            encrypted_index[addr] = val;

            addr = addr ^ rn;
        }
    }

    Data result; result.reserve(encrypted_index.size() * (hash::Size + value::byte_count));

    for (auto& [key, value] : encrypted_index) {
        auto row = key | value;
        result.insert(result.end(), row.begin(), row.end());
    }

    return result;
}

