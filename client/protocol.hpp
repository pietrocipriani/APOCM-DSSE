#pragma once

#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <cstdint>
#include <sockpp/unix_connector.h>
#include <Monocypher.hh>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <uuid/uuid.h>
#include <filesystem>
#include <stdexcept>


#include "keystore.hpp"


template<size_t lambda = 32>
class Protocol {
private:
    enum class Operation { add, remove };

    // Type for KTMap
    using KTMap = std::unordered_map<std::string, std::unordered_set<DocId>>;
    // Map between uuids and document contents.
    using DocMap = std::unordered_map<DocId, std::string>;
    // A generic sequnce of bytes.
    using Data = std::vector<uint8_t>;

    // The state of the protocol. Contains the keys and con (theta in the paper).
    Keystore<lambda> keystore;

    // The socket handler.
    sockpp::unix_connector sock;

    /// Loads the keys or generates new one if there is no key-file.
    void load_or_setup_keys();
    /// Generates a new state.
    void setup();

    // Process method of the paper.
    Data process(Operation op, const KTMap& index) const;
    // Encrypts (AE) the documents one by one and serializes them.
    Data encrypt_documents(DocMap& args);

    // Writes to the socket.
    void send(const Data& data);
    void send(const uint8_t* data, size_t size);
    void send(const char* data);
    /// Sends the binary representation of val.
    template<typename T>
    void send(const T& val) {
        send(reinterpret_cast<const uint8_t*>(&val), sizeof(T));
    }


    // Reads from the socket.
    template<typename T>
    T recv() {
        T result;
        if (auto res = sock.read_n(&result, sizeof(T)); !res || res != sizeof(T)) {
            throw std::runtime_error("Unable to read");
        }
        return result;
    }
    template<size_t size>
    monocypher::byte_array<size> recv() {
        monocypher::byte_array<size> result;
        if (auto res = sock.read_n(result.data(), size); !res || res != size) {
            throw std::runtime_error("Unable to read");
        }
        return result;
    }

    void print_response();

public:
    
    Protocol(const sockpp::unix_address& server_addr);
    Protocol(std::string&& server_addr) : Protocol(sockpp::unix_address{server_addr}) {}

    /// Add method for updates.
    void add(const ArgsAdd& args);

    /// Remove method for updates.
    void remove(const ArgsRemove& args);

    /// Performs a search.
    void search(const ArgsSearch& args);

};


template class Protocol<32>;
//template class Protocol<64>;
