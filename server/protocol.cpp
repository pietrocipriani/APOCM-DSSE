#include "protocol.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <sys/stat.h>

namespace fs = std::filesystem;

DSSEProtocol::DSSEProtocol(const std::string& base_storage_path) 
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
    std::string user_dir = storage_path + "/" + user_id;

    // Ensure the user_id is safe
    if (!is_valid_filename(user_id)) {
        std::cerr << "[ERROR] Invalid user_id format.\n";
        return false;
    }

    // If directory doesn't exist, create it securely
    if (!fs::exists(user_dir)) {
        if (mkdir(user_dir.c_str(), 0700) != 0) {
            std::cerr << "[ERROR] Failed to create user directory: " << user_id << "\n";
            return false;
        }
    }
    return true;
}

// Process and store encrypted indexes (Se, Sr)
bool DSSEProtocol::init_encrypted_index(const std::string& user_id, 
                                           const std::vector<uint8_t>& Se_serialized, 
                                           const std::vector<uint8_t>& Sr_serialized) {
    // Ensure user directory exists
    if (!create_user_directory(user_id)) return false;

    std::string user_dir = storage_path + "/" + user_id;
    std::string se_path = user_dir + "/Se.enc";
    std::string sr_path = user_dir + "/Sr.enc";

    try {
        // Handle Se (encrypted index)
        std::ofstream se_file(se_path, std::ios::binary | std::ios::trunc);
        if (!se_file) {
            std::cerr << "[ERROR] Cannot open Se file for writing.\n";
            return false;
        }
        se_file.write(reinterpret_cast<const char*>(Se_serialized.data()), Se_serialized.size());
        se_file.close();

        // Handle Sr (explicit index)
        std::ofstream sr_file(sr_path, std::ios::binary | std::ios::trunc);
        if (!sr_file) {
            std::cerr << "[ERROR] Cannot open Sr file for writing.\n";
            return false;
        }
        sr_file.write(reinterpret_cast<const char*>(Sr_serialized.data()), Sr_serialized.size());
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

    std::string user_dir = storage_path + "/" + user_id;
    std::string se_path = user_dir + "/Se.enc";

    try {
        std::ofstream se_file(se_path, std::ios::binary | std::ios::app);
        if (!se_file) {
            std::cerr << "[ERROR] Cannot open Se file for writing.\n";
            return false;
        }
        se_file.write(reinterpret_cast<const char*>(Se_serialized.data()), Se_serialized.size());
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
        std::vector<uint8_t> uuid(document_data.begin() + i, document_data.begin() + i + 16);
        i += 16;
        uint64_t doc_len = *reinterpret_cast<const uint64_t*>(&document_data[i]);
        i += 8;
        std::vector<uint8_t> doc(document_data.begin() + i, document_data.begin() + i + doc_len);
        i += doc_len;

        std::string user_dir = storage_path + "/" + user_id;
        std::string doc_path = user_dir + "/" + std::string(uuid.begin(), uuid.end()) + ".enc";

        try {
            std::ofstream doc_file(doc_path, std::ios::binary | std::ios::app);
            if (!doc_file) {
                std::cerr << "[ERROR] Cannot open document file for writing.\n";
                return false;
            }
            doc_file.write(reinterpret_cast<const char*>(doc.data()), doc.size());
            doc_file.close();

            std::cout << "[+] Stored encrypted document for user: " << user_id << "\n";

        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Exception while storing document: " << e.what() << "\n";
            return false;
        }
    }

    return true;
}

