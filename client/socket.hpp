#pragma once

class Socket {
private:
    
    using sfd_t = int;
    using fd_t = int;

public:

    Socket(const string& address);

    ~Socket();



};
