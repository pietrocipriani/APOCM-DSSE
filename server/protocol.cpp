#include "protocol.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <cstring>
#include <sys/stat.h>
#include <Monocypher.hh>

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

// NOTE: Refer to the paper's search algorithm pseudocode for the steps cited below
bool DSSEProtocol::search_keyword(const std::string& user_id, 
                                  const std::vector<uint8_t>& tw,   // Transformed keyword (location in Sr)
                                  const std::vector<uint8_t>& KTw,  // Derived key used to locate encrypted entries in Se
                                  uint64_t Con,                     // Counter tracking previous search instances
                                  std::vector<uint8_t>& ID1,        // Output: Stores previous search result (explicit index Sr)
                                  std::vector<uint8_t>& ID2,        // Output: Stores newly retrived encrypted results (encrypted index Se)
                                  uint64_t& newCon) {               // Output: Updated counter for consistency across searches
    if (!create_user_directory(user_id)) return false;

    fs::path user_dir = storage_path / user_id;
    fs::path se_path = user_dir / "Se.enc";
    fs::path sr_path = user_dir / "Sr.enc";

    std::ifstream sr_file(sr_path, std::ios::binary);
    if (!sr_file) {
        std::cerr << "[ERROR] Failed to open Sr file.\n";
        sr_file.close();
        return false;
    }

    std::ifstream se_file(se_path, std::ios::binary);
    if (!se_file) {
        std::cerr << "[ERROR] Failed to open Se file.\n";
        se_file.close();
        return false;
    }

    // Step 6-10: Check if Sr[tw] exists (explicit index contains results)
    uint64_t Lcon = SYSTEM_CONSTANT;  // Default system constant
    uint64_t prev_con = 0;

    // Load Sr into memory
    std::unordered_map<std::vector<uint8_t>, std::vector<uint8_t>, VectorHash> Sr_map;
    while (!sr_file.eof()) {
        std::vector<uint8_t> key(256), value(256 + 64);
        sr_file.read(reinterpret_cast<char*>(key.data()), key.size());
        sr_file.read(reinterpret_cast<char*>(value.data()), value.size());
        if (sr_file.gcount() == 0) break;
        Sr_map[key] = value;
    }

    sr_file.close();

    // Check if Sr[tw] exists
    auto it = Sr_map.find(tw);
    if (it != Sr_map.end()) {
        ID1.insert(ID1.end(), it->second.begin(), it->second.begin() + 256);  // Eid
        std::memcpy(&prev_con, it->second.data() + 256, sizeof(prev_con));   // Con
        Lcon = prev_con; // Update Lcon with prevuious search counter
    } // otherwise proceed searching in Se

    // Step 11: Iterate over Con to Lcon
    for (uint64_t i = Con; i <= Lcon; ++i) {
        std::vector<uint8_t> Keyw(32), Addrw(32);

        // Step 12: Keyw <- H(KTw || i)
        // Hashes KTw || i to generate a unique key (Keyw) for this iteration
        monocypher::c::crypto_blake2b_ctx hash_ctx;
        monocypher::c::crypto_blake2b_init(&hash_ctx, Keyw.size());
        monocypher::c::crypto_blake2b_update(&hash_ctx, KTw.data(), KTw.size());
        monocypher::c::crypto_blake2b_update(&hash_ctx, reinterpret_cast<const uint8_t*>(&i), sizeof(i));
        monocypher::c::crypto_blake2b_final(&hash_ctx, Keyw.data());

        // Step 13: Addrw <- H(Keyw || 1)
        // Derive Addrw used as a pointer to the encrypted entry in Se
        monocypher::c::crypto_blake2b_init(&hash_ctx, Addrw.size());
        monocypher::c::crypto_blake2b_update(&hash_ctx, Keyw.data(), Keyw.size());
        uint8_t one = 1;
        monocypher::c::crypto_blake2b_update(&hash_ctx, &one, sizeof(one));
        monocypher::c::crypto_blake2b_final(&hash_ctx, Addrw.data());

        // Step 14: If Se[Addrw] != null
        std::unordered_map<std::vector<uint8_t>, std::vector<uint8_t>, VectorHash> Se_map;
        while (!se_file.eof()) {
            std::vector<uint8_t> key(32), value(256 + 64 + 256);
            se_file.read(reinterpret_cast<char*>(key.data()), key.size());
            se_file.read(reinterpret_cast<char*>(value.data()), value.size());
            if (se_file.gcount() == 0) break;
            Se_map[key] = value;
        }

        se_file.close();

        // Check if Se[Addrw] exists
        auto se_it = Se_map.find(Addrw);
        if (se_it != Se_map.end()) {
            // Step 15: (Eid || i || rn) <- Se[Addrw] ⊕ H(Keyw || 0)
            std::vector<uint8_t> Eid_i_rn(256 + 64 + 256);
            std::vector<uint8_t> mask(256 + 64 + 256);

            // Extract Se[Addrw] and decrypt it using mask H(Keyw || 0)
            monocypher::c::crypto_blake2b_init(&hash_ctx, mask.size());
            monocypher::c::crypto_blake2b_update(&hash_ctx, Keyw.data(), Keyw.size());
            uint8_t zero = 0;
            monocypher::c::crypto_blake2b_update(&hash_ctx, &zero, sizeof(zero));
            monocypher::c::crypto_blake2b_final(&hash_ctx, mask.data());

            for (size_t j = 0; j < Eid_i_rn.size(); ++j) {
                Eid_i_rn[j] = se_it->second[j] ^ mask[j];
            }

            // Step 16: ID2 <- ID2 ∪ {Eid || i}
            // Store encrypted results for the client to decrypt later.
            ID2.insert(ID2.end(), Eid_i_rn.begin(), Eid_i_rn.begin() + 256 + 64);

            // Step 17: Delete Se[Addrw]
            // Ensures forward security by removing the processed entry
            Se_map.erase(se_it);

            // Step 18-22: Follow rn chain
            std::vector<uint8_t> rn(Eid_i_rn.begin() + 256 + 64, Eid_i_rn.end());
            while (!std::all_of(rn.begin(), rn.end(), [](uint8_t b) { return b == 0; })) {  // rn != 0
                // Compute next Addrw
                monocypher::c::crypto_blake2b_init(&hash_ctx, Addrw.size());
                monocypher::c::crypto_blake2b_update(&hash_ctx, Addrw.data(), Addrw.size());
                monocypher::c::crypto_blake2b_update(&hash_ctx, rn.data(), rn.size());
                monocypher::c::crypto_blake2b_final(&hash_ctx, Addrw.data());

                // Repeat decryption and add to ID2
                se_it = Se_map.find(Addrw);
                if (se_it == Se_map.end()) break;

                for (size_t j = 0; j < Eid_i_rn.size(); ++j) {
                    Eid_i_rn[j] = se_it->second[j] ^ mask[j];
                }

                ID2.insert(ID2.end(), Eid_i_rn.begin(), Eid_i_rn.begin() + 256 + 64);
                rn.assign(Eid_i_rn.begin() + 256 + 64, Eid_i_rn.end());
                Se_map.erase(se_it);
            }
        }
    }

    newCon = Lcon + 1;
    std::cout << "[1/2] Search Step 1 completed for user: " << user_id << "\n";
    return true;
}


// NOTE: Refer to the paper's search algorithm pseudocode for the steps cited below
bool DSSEProtocol::search_finalize(const std::string& user_id,
                                   const std::vector<uint8_t>& tw,  // Transformed keyword (location in Sr)
                                   const std::vector<uint8_t>& ID1, // Final results from the client after filtering
                                   uint64_t Con) {                  // Counter tracking previous search instances
    if (!create_user_directory(user_id)) return false;

    fs::path sr_path = storage_path / user_id / "Sr.enc";

    std::unordered_map<std::vector<uint8_t>, std::vector<uint8_t>, VectorHash> Sr_map;

    std::ifstream sr_file(sr_path, std::ios::binary);
    if (!sr_file) {
        std::cerr << "[ERROR] Failed to open Sr file.\n";
        sr_file.close();
        return false;
    }

    // Load Sr into memory
    while (!sr_file.eof()) {
        std::vector<uint8_t> key(256), value(256 + 64);
        sr_file.read(reinterpret_cast<char*>(key.data()), key.size());
        sr_file.read(reinterpret_cast<char*>(value.data()), value.size());
        if (sr_file.gcount() == 0) break;
        Sr_map[key] = value;
    }

    sr_file.close();

    // Step 31: Store plaintext search results
    // Update Sr[tw] with the new values
    Sr_map[tw].clear();
    Sr_map[tw].insert(Sr_map[tw].end(), ID1.begin(), ID1.end());
    Sr_map[tw].insert(Sr_map[tw].end(), reinterpret_cast<uint8_t*>(&Con), 
                      reinterpret_cast<uint8_t*>(&Con) + sizeof(Con));

    // Overwrite Sr file
    std::ofstream sr_out(sr_path, std::ios::binary | std::ios::trunc);
    if (!sr_out) {
        std::cerr << "[ERROR] Failed to overwrite Sr.\n";
        sr_out.close();
        return false;
    }
    for (const auto& entry : Sr_map) {
        sr_out.write(reinterpret_cast<const char*>(entry.first.data()), entry.first.size());
        sr_out.write(reinterpret_cast<const char*>(entry.second.data()), entry.second.size());
    }

    sr_out.close();

    std::cout << "[✓] Search completed for user: " << user_id << "\n";
    return true;
}
