#include "protocol.hpp"
#include <cstdlib>
#include <utility>
#include <functional>
#include <iostream>
#include <vector>
#include <random>
#include <cstring>

std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::generate(data.begin(), data.end(), [&rd]() { return rd() % 256; });
    return data;
}

std::vector<uint8_t> generate_uuid() {
    std::vector<uint8_t> uuid(16);
    std::random_device rd;
    std::generate(uuid.begin(), uuid.end(), [&rd]() { return rd() % 256; });
    return uuid;
}

uint64_t encode_length(uint64_t len) {
    uint64_t encoded;
    std::memcpy(&encoded, &len, sizeof(len));
    return encoded;
}

int main() {
    std::string storage_path = "storage";  // Storage directory for user data
    DSSEProtocol server(storage_path);

    // Simulated user ID
    std::string user_id = "test_user";

    // Simulated Se and Sr (encrypted indexes received from the client)
    std::vector<uint8_t> Se_data = generate_random_data(256);  // 256-byte encrypted Se
    std::vector<uint8_t> Sr_data = generate_random_data(128);  // 128-byte encrypted Sr

    std::cout << "\nInitializing Encrypted Index for User: " << user_id << "\n";
    if (!server.init_encrypted_index(user_id, Se_data, Sr_data)) {
        std::cerr << "[ERROR] Failed to initialize encrypted index.\n";
        return 1;
    }

    // Simulated Se' update
    std::vector<uint8_t> Se_update = generate_random_data(256);  // 256-byte update

    std::cout << "\nUpdating Encrypted Index for User: " << user_id << "\n";
    if (!server.update_encrypted_index(user_id, Se_update)) {
        std::cerr << "[ERROR] Failed to update encrypted index.\n";
        return 1;
    }

    // Simulated encrypted document storage (multiple documents)
    std::vector<uint8_t> doc_data;
    for (int i = 0; i < 3; ++i) {
        std::vector<uint8_t> uuid = generate_uuid();
        uint64_t doc_len = 64;  // Example document size
        std::vector<uint8_t> doc = generate_random_data(doc_len);

        doc_data.insert(doc_data.end(), uuid.begin(), uuid.end());  // Append UUID
        uint64_t encoded_len = encode_length(doc_len);
        doc_data.insert(doc_data.end(), reinterpret_cast<uint8_t*>(&encoded_len), reinterpret_cast<uint8_t*>(&encoded_len) + 8);  // Append Length
        doc_data.insert(doc_data.end(), doc.begin(), doc.end());  // Append Document
    }

    std::cout << "\nStoring Encrypted Documents for User: " << user_id << "\n";
    if (!server.store_encrypted_document(user_id, doc_data)) {
        std::cerr << "[ERROR] Failed to store encrypted document.\n";
        return 1;
    }

    std::cout << "\nAll operations completed successfully!\n";
    return 0;
}

