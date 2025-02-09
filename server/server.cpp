#include "server.hpp"
#include <sockpp/unix_acceptor.h>
#include <sockpp/unix_stream_socket.h>
#include <iostream>
#include <cstring>

DSSEServer::DSSEServer(const std::string& storage_path) : protocol(storage_path) {}

void DSSEServer::start() {
    std::cout << "[+] Starting DSSE Server on " << SOCK_ADDR << "\n";

    sockpp::unix_acceptor acc(sockpp::unix_address(SOCK_ADDR));
    if (!acc) {
        std::cerr << "[ERROR] Failed to create socket: " << acc.last_error_str() << "\n";
        return;
    }

    while (true) {
        sockpp::unix_stream_socket client_sock = acc.accept();
        if (!client_sock) {
            std::cerr << "[ERROR] Accept failed: " << acc.last_error_str() << "\n";
            continue;
        }

        std::cout << "[+] Client connected.\n";
        handle_client(std::move(client_sock));
    }
}

// Ensures full message reception
bool DSSEServer::receive_exact(sockpp::unix_stream_socket& sock, void* buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t r = sock.read(static_cast<uint8_t*>(buf) + received, len - received);
        if (r <= 0) return false;
        received += r;
    }
    return true;
}

// Handle client requests
void DSSEServer::handle_client(sockpp::unix_stream_socket client_sock) {
    // opcode is 4 byte:
    // 0: add
    // 1: remove
    // 2: search
    // uint8_t opcode;
    uint32_t opcode;
    if (!receive_exact(client_sock, &opcode, sizeof(opcode))) {
        std::cerr << "[ERROR] Failed to receive operation code.\n";
        return;
    }

    std::string user_id = "test_user";  // TODO: Authenticate user

    if (opcode == 0) {  // Handle Update
        std::cout << "[+] Handling UPDATE request.\n";

        // Receive encrypted index size
        uint64_t index_size;
        if (!receive_exact(client_sock, &index_size, sizeof(index_size))) {
            std::cerr << "[ERROR] Failed to receive index size.\n";
            return;
        }
        
        // Receive encrypted index update (Se)
        std::vector<uint8_t> Se_data(index_size);
        if (!receive_exact(client_sock, Se_data.data(), Se_data.size())) {
            std::cerr << "[ERROR] Failed to receive encrypted index Se.\n";
            return;
        }

        // Receive document data size
        uint64_t total_doc_size;
        if (!receive_exact(client_sock, &total_doc_size, sizeof(total_doc_size))) {
            std::cerr << "[ERROR] Failed to receive total document size.\n";
            return;
        }

        // Receive encrypted documents
        std::vector<uint8_t> doc_data(total_doc_size);
        if (!receive_exact(client_sock, doc_data.data(), doc_data.size())) {
            std::cerr << "[ERROR] Failed to receive encrypted documents.\n";
            return;
        }

        protocol.update_encrypted_index(user_id, Se_data);
        protocol.store_encrypted_document(user_id, doc_data);
        std::cout << "[✓] Update processed for user: " << user_id << "\n";

    } else if (opcode == 2) {  // Handle Search
        std::cout << "[+] Handling SEARCH request.\n";

        // Receive search query: t (256) + KT (256) + Con (64)
        std::vector<uint8_t> t(32), KT(32);
        uint64_t Con;
        if (!receive_exact(client_sock, t.data(), t.size()) ||
            !receive_exact(client_sock, KT.data(), KT.size()) ||
            !receive_exact(client_sock, &Con, sizeof(Con))) {
            std::cerr << "[ERROR] Failed to receive search parameters.\n";
            return;
        }

        std::cout << "[+] Searching.\n";

        // Step 1: Perform search and send results back
        std::vector<uint8_t> ID1, ID2;
        uint64_t newCon;
        if (!protocol.search_keyword(user_id, t, KT, Con, ID1, ID2, newCon)) {
            std::cerr << "[ERROR] Search failed.\n";
            return;
        }

        // Send response: ID1 size (8 bytes) + ID2 size (8 bytes) + ID1 + ID2 + newCon (64)
        // Send ID1 size (8 bytes) + ID2 size (8 bytes)
        size_t ID1_size = ID1.size();
        size_t ID2_size = ID2.size();
        if (!client_sock.write(&ID1_size, sizeof(ID1_size)) ||
            !client_sock.write(&ID2_size, sizeof(ID2_size))) {
            std::cerr << "[ERROR] Failed to send search response sizes.\n";
            return;
        }
        // Send ID1 and ID2
        if (client_sock.write(ID1.data(), ID1.size()) != ID1.size() ||
            client_sock.write(ID2.data(), ID2.size()) != ID2.size()) {
            std::cerr << "[ERROR] Failed to send search results.\n";
            return;
        }

        std::cout << "[✓] Search step 1 response sent. Waiting for client confirmation...\n";

        // Step 2: Receive final confirmation (ID1 + Con)
        size_t final_ID1_size;
        if (!receive_exact(client_sock, &final_ID1_size, sizeof(final_ID1_size))) {
            std::cerr << "[ERROR] Failed to receive final ID1 size.\n";
            return;
        }

        std::vector<uint8_t> final_ID1(final_ID1_size * 16);
        uint64_t final_Con;
        if (!receive_exact(client_sock, final_ID1.data(), final_ID1.size()) ||
            !receive_exact(client_sock, &final_Con, sizeof(final_Con))) {
            std::cerr << "[ERROR] Failed to receive final search results.\n";
            return;
        }

        // Finalize search
        if (!protocol.search_finalize(user_id, t, final_ID1, final_Con)) {
            std::cerr << "[ERROR] Search finalization failed.\n";
            return;
        }

        std::cout << "[✓] Search successfully finalized.\n";

    } else {
        std::cerr << "[ERROR] Invalid operation code.\n";
    }

    std::cout << "[+] Closing client connection.\n";
}

