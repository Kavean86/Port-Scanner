#pragma once
using namespace std;

// Determine which local IP address would be used to reach the target
string get_source_ip(const std::string& target)
{
    // Create a UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    // Check whether the socket was created successfully
    if (sock < 0) {
        perror("socket");
        return "";
    }

    // Create and initialize the destination address structure
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);

    // Convert the target IP address from string format to binary format
    if (inet_pton(AF_INET, target.c_str(), &dest.sin_addr) != 1) {
        close(sock);
        return "";
    }

    // Connect the UDP socket to the target
    // This does not establish a TCP-style connection
    if (connect(sock,
                reinterpret_cast<sockaddr*>(&dest),
                sizeof(dest)) < 0) {
        perror("connect");
        close(sock);
        return "";
    }

    // Structure used to store the local socket address
    sockaddr_in local{};
    socklen_t len = sizeof(local);

    // Get the local address selected by the operating system
    if (getsockname(sock,
                    reinterpret_cast<sockaddr*>(&local),
                    &len) < 0) {
        perror("getsockname");
        close(sock);
        return "";
    }

    // Buffer used to store the source IP address as a string
    char source_ip[INET_ADDRSTRLEN];

    // Convert the local binary IPv4 address to string format
    if (inet_ntop(AF_INET,
                  &local.sin_addr,
                  source_ip,
                  sizeof(source_ip)) == nullptr) {
        close(sock);
        return "";
    }

    // Close the socket after obtaining the source IP
    close(sock);

    // Return the selected local source IP address
    return source_ip;
}
