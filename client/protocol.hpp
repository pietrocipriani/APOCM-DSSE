#pragma once

#include "argparse.hpp"
#include "utils.hpp"
#include <iostream>
#include <cstdint>
#include <sockpp/unix_connector.h>
#include <Monocypher.hh>
#include <vector>
#include <unordered_map>
#include <uuid.h>


#include "keystore.hpp"


template<size_t lambda = 32>
class Protocol {
private:
    enum class Operation { add, remove };
    using KTMap = std::unordered_map<std::string, unordered_set<uuid_t>>;
    using Data = std::vector<uint8_t>;

    Keystore<lambda> keystore;

    sockpp::unix_connector sock;

    void load_or_setup_keys();
    void setup();

    Data process(Operation op, const KTMap& index) const;
    Data encrypt_documents(const ArgsAdd& args);

    void send(const std::vector<uint8_t>& data);

public:
    
    Protocol(const sockpp::unix_address& server_addr);
    Protocol(std::string&& server_addr) : Protocol(sockpp::unix_address{server_addr}) {}

    void add(const ArgsAdd& args);

    void remove(const ArgsRemove& args);

    void search(const ArgsSearch& args);

};


template class Protocol<32>;
template class Protocol<64>;
