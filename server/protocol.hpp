#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>

namespace fs = std::filesystem;

constexpr uint64_t SYSTEM_CONSTANT = 1000;

// Custom hash function for std::vector<uint8_t> to use in std::unordered_map
struct VectorHash {
    std::size_t operator()(const std::vector<uint8_t>& vec) const {
        std::size_t hash = 0;
        for (uint8_t byte : vec) {
            hash = (hash * 31) + byte;
        }
        return hash;
    }
};

// DSSE Protocol - Handles server-side storage and updates
class DSSEProtocol {
public:
    explicit DSSEProtocol(const fs::path& base_storage_path);

    // Process Se and Sr received from the client
    bool init_encrypted_index(const std::string& user_id, 
                                 const std::vector<uint8_t>& Se_serialized,
                                 const std::vector<uint8_t>& Sr_serialized);

    // Update Se' received from the client
    bool update_encrypted_index(const std::string& user_id, 
                                 const std::vector<uint8_t>& Se_serialized);

    // Store encrypted documents
    bool store_encrypted_document(const std::string& user_id, 
                                  const std::vector<uint8_t>& document_data);
    
    // Search for a keyword in the encrypted index
    // Step 1: Process search request and return ID1 & ID2
    bool search_keyword(const std::string& user_id,
                        const std::vector<uint8_t>& tw,
                        const std::vector<uint8_t>& KTw,
                        uint64_t Con,
                        std::vector<uint8_t>& ID1,
                        std::vector<uint8_t>& ID2,
                        uint64_t& newCon);

    // Step 2: Finalize search results and update Sr
    bool search_finalize(const std::string& user_id,
                         const std::vector<uint8_t>& tw,
                         const std::vector<uint8_t>& ID1,
                         uint64_t Con);

private:
    fs::path storage_path;

    // Helpers
    bool is_valid_filename(const std::string& name);
    bool create_user_directory(const std::string& user_id);
    std::string uuid_to_hex(const std::vector<uint8_t>& uuid);
};
