#pragma once

#include <sockpp/unix_stream_socket.h>
#include <sockpp/unix_acceptor.h>
#include "protocol.hpp"
#include <vector>
#include <iostream>

#define SOCK_ADDR "\0dsse_apocm"  // Abstract namespace Unix socket

class DSSEServer {
public:
    explicit DSSEServer(const std::string& storage_path);
    void start();

private:
    DSSEProtocol protocol;  // Handles encrypted index & document storage
    void handle_client(sockpp::unix_stream_socket client_sock);
    bool receive_exact(sockpp::unix_stream_socket& sock, void* buf, size_t len);
};


