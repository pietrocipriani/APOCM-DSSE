#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>

// Encrypted index entry structure (each keyword maps to encrypted metadata)
struct EncryptedIndexEntry {
    std::vector<uint8_t> eid;  // Encrypted document ID (256 bits)
    uint64_t con;              // Counter (64 bits)
};

// DSSE Protocol - Handles server-side storage and updates
class DSSEProtocol {
public:
    explicit DSSEProtocol(const std::string& base_storage_path);

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
    std::string storage_path;

    // Helpers
    bool is_valid_filename(const std::string& name);
    bool create_user_directory(const std::string& user_id);
};
