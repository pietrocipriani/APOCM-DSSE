#pragma once

class Socket {
private:
    
    using sfd_t = int;
    using fd_t = int;

    Socket(const string& address);

public:
    
    static ServerSocket listen();
    static ClientSocket connect();

    ~Socket();

};
