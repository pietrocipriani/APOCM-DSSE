#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>

namespace fs = std::filesystem;

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

private:
    fs::path storage_path;

    // Helpers
    bool is_valid_filename(const std::string& name);
    bool create_user_directory(const std::string& user_id);
    std::string uuid_to_hex(const std::vector<uint8_t>& uuid);
};
