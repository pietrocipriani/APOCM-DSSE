#include "protocol.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <sys/stat.h>

namespace fs = std::filesystem;

DSSEProtocol::DSSEProtocol(const fs::path& base_storage_path) 
    : storage_path(base_storage_path) {
    // Ensure base storage directory exists
    fs::create_directories(storage_path);
}

// Check if a string is a valid filename (to prevent directory traversal)
bool DSSEProtocol::is_valid_filename(const std::string& name) {
    if (name.empty() || name.size() > 255) return false;
    if (name.find("..") != std::string::npos) return false;
    if (name.find("/") != std::string::npos) return false;
    if (name.find("\\") != std::string::npos) return false;
    return true;
}

// Create user storage directory securely
bool DSSEProtocol::create_user_directory(const std::string& user_id) {
    fs::path user_dir = storage_path / user_id;

    // Ensure the user_id is safe
    if (!is_valid_filename(user_id)) {
        std::cerr << "[ERROR] Invalid user_id format.\n";
        return false;
    }

    // If directory doesn't exist, create it securely
    if (!fs::exists(user_dir)) {
        if (!fs::create_directory(user_dir)) {
            std::cerr << "[ERROR] Failed to create user directory: " << user_id << "\n";
            return false;
        }
    }
    return true;
}


// Convert UUID to hex string
std::string DSSEProtocol::uuid_to_hex(const std::vector<uint8_t>& uuid) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : uuid) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

// Process and store encrypted indexes (Se, Sr)
bool DSSEProtocol::init_encrypted_index(const std::string& user_id, 
                                           const std::vector<uint8_t>& Se_serialized, 
                                           const std::vector<uint8_t>& Sr_serialized) {
    // Ensure user directory exists
    if (!create_user_directory(user_id)) return false;

    fs::path user_dir = storage_path / user_id;
    fs::path se_path = user_dir / "Se.enc";
    fs::path sr_path = user_dir / "Sr.enc";

    constexpr size_t SE_ENTRY_SIZE = 256 + 64 + 256;  // Key(256) + Value(256+64+256)
    constexpr size_t SR_ENTRY_SIZE = 256;  // Assume 256 bytes for Sr row
    
    // Validate input sizes
    if (Se_serialized.size() % SE_ENTRY_SIZE != 0) {
        std::cerr << "[ERROR] Invalid Se size.\n";
        return false;
    }
    if (Sr_serialized.size() % SR_ENTRY_SIZE != 0) {
        std::cerr << "[ERROR] Invalid Sr size.\n";
        return false;
    }

    try {
        // Handle Se (encrypted index)
        std::ofstream se_file(se_path, std::ios::binary | std::ios::trunc);
        if (!se_file) {
            std::cerr << "[ERROR] Cannot open Se file for writing.\n";
            se_file.close();
            return false;
        }
        if (!se_file.write(reinterpret_cast<const char*>(Se_serialized.data()), Se_serialized.size())) {
            std::cerr << "[ERROR] Failed to write Se.\n";
            se_file.close();
            return false;
        }
        se_file.close();

        // Handle Sr (explicit index)
        std::ofstream sr_file(sr_path, std::ios::binary | std::ios::trunc);
        if (!sr_file) {
            std::cerr << "[ERROR] Cannot open Sr file for writing.\n";
            sr_file.close();
            return false;
        }
        if (!sr_file.write(reinterpret_cast<const char*>(Sr_serialized.data()), Sr_serialized.size())) {
            std::cerr << "[ERROR] Failed to write Sr.\n";
            sr_file.close();
            return false;
        }
        sr_file.close();

        std::cout << "[+] Successfully updated Se and Sr for user: " << user_id << "\n";
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception while processing Se/Sr: " << e.what() << "\n";
        return false;
    }
}

// Update encrypted index by appending (Se')
bool DSSEProtocol::update_encrypted_index(const std::string& user_id, 
                                             const std::vector<uint8_t>& Se_serialized) {
    // Ensure user directory exists
    if (!create_user_directory(user_id)) return false;

    fs::path se_path = storage_path / user_id / "Se.enc";

    constexpr size_t SE_ENTRY_SIZE = 256 + 64 + 256;  // Key(256) + Value(256+64+256)

    if (Se_serialized.size() % SE_ENTRY_SIZE != 0) {
        std::cerr << "[ERROR] Invalid Se' size.\n";
        return false;
    }

    try {
        std::ofstream se_file(se_path, std::ios::binary | std::ios::app);
        if (!se_file) {
            std::cerr << "[ERROR] Cannot open Se file for writing.\n";
            se_file.close();
            return false;
        }
        if (!se_file.write(reinterpret_cast<const char*>(Se_serialized.data()), Se_serialized.size())) {
            std::cerr << "[ERROR] Failed to append Se'.\n";
            se_file.close();
            return false;
        }
        se_file.close();

        std::cout << "[+] Successfully updated Se for user: " << user_id << "\n";
        return true;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception while updating Se: " << e.what() << "\n";
        return false;
    }
}

// Store an encrypted document
bool DSSEProtocol::store_encrypted_document(const std::string& user_id, 
                                            const std::vector<uint8_t>& document_data) {
    // Ensure user directory exists
    if (!create_user_directory(user_id)) return false;

    // extract UUID (128 bits) and document length (64 bits) from document_data.
    // there could be more than one document serialized this way: UIID(128) + length(64) + document(length)
    // we need to extract each document and store it separately.
    for (size_t i = 0; i < document_data.size(); ) {
        if (i + 16 + 8 > document_data.size()) {
            std::cerr << "[ERROR] Invalid document data format.\n";
            return false;
        }

        std::vector<uint8_t> uuid(document_data.begin() + i, document_data.begin() + i + 16);
        i += 16;
        uint64_t doc_len = *reinterpret_cast<const uint64_t*>(&document_data[i]);
        i += 8;

        if (i + doc_len > document_data.size()) {
            std::cerr << "[ERROR] Invalid document data format.\n";
            return false;
        }

        std::vector<uint8_t> doc(document_data.begin() + i, document_data.begin() + i + doc_len);
        i += doc_len;

        fs::path user_dir = storage_path / user_id;
        fs::path doc_path = user_dir / (uuid_to_hex(uuid) + ".enc");

        try {
            std::ofstream doc_file(doc_path, std::ios::binary | std::ios::app);
            if (!doc_file) {
                std::cerr << "[ERROR] Cannot open document file for writing.\n";
                doc_file.close();
                return false;
            }
            if (!doc_file.write(reinterpret_cast<const char*>(uuid.data()), uuid.size()) ||
                !doc_file.write(reinterpret_cast<const char*>(&doc_len), sizeof(doc_len)) ||
                !doc_file.write(reinterpret_cast<const char*>(doc.data()), doc.size())) {
                std::cerr << "[ERROR] Failed to write document.\n";
                doc_file.close();
                return false;
            }
            doc_file.close();

            std::cout << "[+] Stored encrypted document: " << uuid_to_hex(uuid) << " for user: " << user_id << "\n";

        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Exception while storing document: " << e.what() << "\n";
            return false;
        }
    }

    return true;
}

