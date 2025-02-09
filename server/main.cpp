#include "protocol.hpp"
#include "server.hpp"
#include <cstdlib>
#include <utility>
#include <functional>
#include <iostream>
#include <vector>
#include <random>
#include <cstring>

DSSEServer* server_instance = nullptr;

// Gracefully handle SIGINT (Ctrl+C) to stop the server
void handle_signal([[maybe_unused]] int signal) {
    if (server_instance) {
        std::cout << "\n[!] Shutting down DSSE Server...\n";
        delete server_instance;
        server_instance = nullptr;
        exit(0);
    }
}

int main() {
    std::string storage_path = "storage";  // Storage directory for user data

    std::cout << "[+] Initializing DSSE Server...\n";
    server_instance = new DSSEServer(storage_path);

    // Handle Ctrl+C to allow clean exit
    signal(SIGINT, handle_signal);

    // Start the server (blocking call)
    server_instance->start();

    return 0;
}

