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


#include "keystore.hpp"


template<size_t lambda = 32>
class Protocol {
private:
    enum class Operation { add, remove };
    using KTMap = std::unordered_map<std::string, std::unordered_set<DocId>>;
    using DocMap = std::unordered_map<std::filesystem::path, DocId>;
    using Data = std::vector<uint8_t>;

    Keystore<lambda> keystore;

    sockpp::unix_connector sock;

    void load_or_setup_keys();
    void setup();

    Data process(Operation op, const KTMap& index) const;
    Data encrypt_documents(const DocMap& args);

    void send(const Data& data);
    void send(const uint8_t* data, size_t size);
    void send(const char* data);
    /// Sends the binary representation of val.
    template<typename T>
    void send(const T& val) {
        send(reinterpret_cast<const uint8_t*>(&val), sizeof(T));
    }

    void print_response();

public:
    
    Protocol(const sockpp::unix_address& server_addr);
    Protocol(std::string&& server_addr) : Protocol(sockpp::unix_address{server_addr}) {}

    void add(const ArgsAdd& args);

    void remove(const ArgsRemove& args);

    void search(const ArgsSearch& args);

};


template class Protocol<32>;
template class Protocol<64>;
