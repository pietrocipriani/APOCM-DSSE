#include "protocol.hpp"
#include "argparse.hpp"
#include "utils.hpp"
#include "password_utils.hpp"
#include <iostream>
#include <stdexcept>
#include <format>
#include <Monocypher.hh>
#include <filesystem>
#include <iterator>
#include <fstream>
#include <regex>


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
    keystore.create_keys();
}

template<size_t lambda>
void Protocol<lambda>::add(const ArgsAdd& args) {
    DocMap documents;

    std::clog << "[+] Reading documents." << std::endl;

    // Read documents.
    for (auto& path : args.paths) {
        if (!std::filesystem::is_regular_file(path)) {
            std::cerr << path << " doesn't exists or is not a regular file: ignored." << std::endl;
            continue;
        }

        // NOTE: duplicate files are not removed.

        DocId uuid; uuid_generate(uuid.data());

        // TODO: manage exceptions.
        std::ifstream file(path, std::ios_base::in | std::ios_base::binary);

        if (file.good()) {
            std::string content(std::istreambuf_iterator<char>(file), {});
            documents[uuid] = std::move(content);
        } else {
            std::cerr << "Error while reading file " << path << ": ignored." << std::endl;
        }
    }

    std::clog << "[+] Generating index." << std::endl;

    KTMap index;

    // Extract keywords
    std::regex exp("[a-zA-Z0-9]+");
    for (const auto& [uuid, content] : documents) {

        std::sregex_iterator begin(content.begin(), content.end(), exp);
        std::sregex_iterator end{};
        for (; begin != end; ++begin) {
            index[begin->str()].insert(uuid);
        }

    }

    std::clog << "[+] Encrypting." << std::endl;
    
    load_or_setup_keys();

    // NOTE: this can lead to memory issues, however sending while encrypting increases the key exposure in memory.
    auto encrypted_index = process(Operation::add, index);
    auto docs = encrypt_documents(documents);

    // Con has changed.
    --keystore.con;
    keystore.store_keys();
    keystore.wipe_keys();

    std::clog << "[+] Sending data." << std::endl;

    send(0); // add operation
    send(encrypted_index.size());
    send(encrypted_index);
    send(docs.size());
    send(docs);

    print_response();
}

template<size_t lambda>
void Protocol<lambda>::remove([[maybe_unused]] const ArgsRemove& args) {
    std::cout << "Removal is not implemented" << std::endl;
}

template<size_t lambda>
void Protocol<lambda>::search(const ArgsSearch& args) {
    using prf = monocypher::hash<monocypher::Blake2b<32>>;
    using hash = monocypher::hash<monocypher::Blake2b<64>>;
    using prp = monocypher::session::encryption_key<monocypher::XChaCha20_Poly1305>;

    std::clog << "[+] Sending search parameters." << std::endl;


    keystore.load_keys();

    const auto& keyword = args.keyword;
    auto t = prf::createMAC(keyword.data(), keyword.size(), keystore.key_t);
    auto kt = prf::createMAC(keyword.data(), keyword.size(), keystore.key_f);

    // Store con to send it to the server.
    auto con = keystore.con;
    keystore.wipe_keys();

    send(2);
    send(t);
    t.wipe();
    send(kt);
    kt.wipe();
    send(con);
    
    std::clog << "[+] Reading first response." << std::endl;

    auto count_1 = recv<size_t>();
    auto count_2 = recv<size_t>();

    if (count_1 % DocId::byte_count != 0) {
        throw std::runtime_error("Corrupted response");
        abort();
    }
    count_1 /= DocId::byte_count;
    
    if (count_2 % (hash::Size + decltype(keystore.con)::byte_count) != 0) {
        throw std::runtime_error("Corrupted response");
        abort();
    }
    count_2 /= hash::Size + decltype(keystore.con)::byte_count;

    using hash_t = monocypher::byte_array<hash::Size>;
    using Con = decltype(keystore.con);

    std::unordered_set<DocId> id1;
    std::unordered_set<DocId> removals;
    std::vector<std::pair<hash_t, Con>> id2; 

    for (size_t i = 0; i < count_1; ++i) {
        auto uuid = recv<DocId::byte_count>();
        id1.insert(uuid);
    }
    for (size_t i = 0; i < count_2; ++i) {
        auto eid = recv<hash::Size>();
        auto con = recv<sizeof(keystore.con)>();

        id2.emplace_back(eid, con);
    }

    std::clog << "[+] Decrypting entries." << std::endl;

    keystore.load_keys();
    for (auto& [eid, con] : id2) {
        auto sk_plain = keyword | con;
        auto sk = prf::createMAC(sk_plain.data(), sk_plain.size(), keystore.key_g);
        monocypher::wipe(sk_plain.data(), sk_plain.size());

        using Mac = monocypher::session::mac;
        using Nonce = monocypher::session::nonce;

        Mac mac(eid.template range<0, Mac::byte_count>());
        Nonce nonce(eid.template range<Mac::byte_count, Nonce::byte_count>());
        auto data = eid.template range<40, 24>();

        if (auto ok = prp(sk).unlock(nonce, mac, data, data.data()); !ok) {
            std::cerr << "[WARN] Corrupted data." << std::endl;
            continue;
        }
        auto uuid = data.template range<0, DocId::byte_count>();
        // Serialized as 8B, little endian.
        auto op = data[DocId::byte_count];

        // Without guarantees about the receiving order it is better to only remove 
        // after insertions.
        if (op == 0) {
            id1.insert(uuid);
        } else {
            removals.insert(uuid);
        }
    }
    

    keystore.wipe_keys();

    for (auto& uuid : removals) id1.erase(uuid);

    std::clog << "[+] Sending Sr." << std::endl;

    send(id1.size());
    if (id1.empty()) {
        std::cout << "No results." << std::endl;
    }
    for (auto& uuid : id1) {
        hexprint(uuid);
        send(uuid);
    }

    send(con);

    // TODO: read documents.
}

template<size_t lambda>
Protocol<lambda>::Protocol(const sockpp::unix_address& server_addr) {

    if (auto res = sock.connect(server_addr); !res) {
        auto msg = std::format("Unable to reach the server.", sock.last_error_str());
        throw std::runtime_error(std::move(msg));
    }

    // TODO: ensure the server authenticity.
    if (int pid; sock.get_option<int>(SOL_SOCKET, SO_PEERCRED, &pid)) {
        std::cerr << "Server credentials: " << pid << std::endl;
    }

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

    // Encrypt the index
    for (auto& [keyword, docs] : index) {
        auto kt = prf::createMAC(keyword.data(), keyword.length(), keystore.key_f);

        auto key = hash::create(kt | keystore.con);
        monocypher::byte_array addr = hash::create(key | one<1>);

        for (auto it = docs.begin(); it != docs.end(); ++it) {
            auto& uuid = *it;
            monocypher::byte_array<hash::Size> rn(0);

            // If this is not the last document, then rn must be a non-zero random sequence.
            while (std::next(it) != docs.end() and rn == zero<hash::Size>) {
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


template<size_t lambda>
void Protocol<lambda>::send(const Protocol<lambda>::Data& data) {
    send(data.data(), data.size());
}
template<size_t lambda>
void Protocol<lambda>::send(const char* data) {
    send(reinterpret_cast<const uint8_t*>(data), strlen(data));
}
template<size_t lambda>
void Protocol<lambda>::send(const uint8_t* data, size_t size) {
    auto res = sock.write_n(data, size);
    if (res == -1 || static_cast<size_t>(res) != size) {
        throw std::ios_base::failure("Unable to write the buffer to the socket");
        abort();
    }
}

template<size_t lambda>
void Protocol<lambda>::print_response() {
    // TODO: read server message.
    std::cerr << "[Server] dummy msg" << std::endl;
}


template<size_t lambda>
Protocol<lambda>::Data Protocol<lambda>::encrypt_documents(DocMap& args) {
    using prp = monocypher::session::encryption_key<monocypher::XChaCha20_Poly1305>;

    Data result;

    for (auto& [uuid, content] : args) {

        // NOTE: the nonce must be different for every encryption.
        // 192-bit random nonce is considered safe.
        monocypher::session::nonce nonce{};
        static_assert(monocypher::session::nonce::byte_count == 24);

        // Consider in the length also the mac and the nonce.
        auto ad = uuid | serialize(content.size() + 16 + 24);
        static_assert(decltype(ad)::byte_count == 16 + 8);
        auto mac = prp(keystore.key_d).lock(
            nonce,
            {content.data(), content.size()},
            ad,
            content.data()
        );

        result.insert(result.end(), ad.begin(), ad.end());
        result.insert(result.end(), mac.begin(), mac.end());
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), content.begin(), content.end());
    }

    return result;
}
