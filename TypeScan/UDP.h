#pragma once
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ifaddrs.h>
#include <cstring>
#include <random>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "Global_var.h"
#include "UDP.h_Checksums.h"
#include "route.h"

using namespace std;

// Perform a UDP scan against the specified destination port
void udp_connect(int dest_port, string ipaddress)
{
    // Generate a random source port for the UDP packet
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(1024, 65535);

    int source_port = dist(gen);

    // Create a raw UDP socket for crafting the packet
    int rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (rawsock < 0) {
        perror("socket");
        return;
    }

    // Tell the kernel that the IP header is being created manually
    int one = 1;

    if (setsockopt(rawsock,
                   IPPROTO_IP,
                   IP_HDRINCL,
                   &one,
                   sizeof(one)) < 0)
    {
        perror("setsockopt");
        close(rawsock);
        return;
    }

    // Determine the local source IP used to reach the target
    string source_ip = get_source_ip(ipaddress);

    if (source_ip.empty()) {
        cerr << "Could not determine source IP\n";
        close(rawsock);
        return;
    }

    // Buffer containing the IP header followed by the UDP header
    char packet[1024] = {0};

    // Point to the beginning of the IP header
    iphdr* ip = (iphdr*)packet;

    // Place the UDP header immediately after the IP header
    udphdr* udp =
        (udphdr*)(packet + sizeof(iphdr));

    // Configure the IPv4 header
    ip->version = 4;
    ip->ihl = 5;
    ip->id = htons(45896);
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;

    // Set the total length of the IP packet
    ip->tot_len =
        htons(sizeof(iphdr) + sizeof(udphdr));

    ip->frag_off = 0;

    // Set source and destination IP addresses
    ip->saddr =
        inet_addr(source_ip.c_str());

    ip->daddr =
        inet_addr(ipaddress.c_str());

    // Configure the UDP source and destination ports
    udp->source = htons(source_port);

    udp->dest = htons(dest_port);

    // Set the UDP header length
    udp->len =
        htons(sizeof(udphdr));

    // Initially clear the UDP checksum
    udp->check = 0;

    // Calculate the UDP checksum
    udp->check =
        udp_checksum(ip, udp);

    // Clear the IP checksum before calculating it
    ip->check = 0;

    // Calculate the IPv4 header checksum
    ip->check =
        UDP_checksum(
            (uint16_t*)ip,
            ip->ihl * 4
        );

    // Configure the destination address used by sendto()
    sockaddr_in dest{};

    dest.sin_family = AF_INET;

    inet_pton(
        AF_INET,
        ipaddress.c_str(),
        &dest.sin_addr
    );


    // Calculate the total packet size
    int packet_size =
        sizeof(struct iphdr) +
        sizeof(struct udphdr);

    // Create a raw socket for receiving UDP responses
    int recvsock =
        socket(AF_INET, SOCK_RAW, IPPROTO_UDP);

    if (recvsock < 0) {
        perror("socket");
        close(rawsock);
        return;
    }

    // Configure the maximum time to wait for a response
    struct timeval timeout{};

    timeout.tv_sec = 0;
    timeout.tv_usec = 200000;

    if (setsockopt(
            recvsock,
            SOL_SOCKET,
            SO_RCVTIMEO,
            &timeout,
            sizeof(timeout)) < 0)
    {
        perror("setsockopt");

        close(rawsock);
        close(recvsock);

        return;
    }

    // Send the crafted UDP packet to the target
    ssize_t sent =
        sendto(
            rawsock,
            packet,
            packet_size,
            0,
            (sockaddr*)&dest,
            sizeof(dest)
        );

    if (sent < 0) {
        perror("sendto");

        close(rawsock);
        close(recvsock);

        return;
    }

    // Buffer used to store received packets
    char buffer[1024] = {0};

    // Keep receiving packets until a matching response is found
    // or the receive operation times out
    while (true)
    {
        ssize_t received =
            recv(
                recvsock,
                buffer,
                sizeof(buffer),
                0
            );

        // Handle receive errors
        if (received < 0)
        {
            // No response was received within the timeout
            if (errno == EAGAIN ||
                errno == EWOULDBLOCK)
            {
                break;
            }

            perror("recv");

            close(rawsock);
            close(recvsock);

            return;
        }

        // Ignore packets that are too small to contain an IP header
        if (received < (ssize_t)sizeof(iphdr))
            continue;


        // Interpret the received data as an IPv4 header
        iphdr* iprecv =
            (iphdr*)buffer;


        // Ignore packets that are not UDP packets
        if (iprecv->protocol != IPPROTO_UDP)
            continue;


        // Calculate the actual IP header length
        int ip_header_len =
            iprecv->ihl * 4;


        // Ignore invalid IP headers
        if (ip_header_len < 20)
            continue;


        // Make sure the packet also contains a complete UDP header
        if (received <
            ip_header_len + (int)sizeof(udphdr))
        {
            continue;
        }


        // Locate the UDP header after the IP header
        udphdr* udprecv =
            (udphdr*)
            (buffer + ip_header_len);


        // Extract source and destination ports from the received packet
        int recv_source_port =
            ntohs(udprecv->source);

        int recv_dest_port =
            ntohs(udprecv->dest);

        // Ignore packets that appear to be related to our own
        // source-to-destination direction
        if (recv_source_port == source_port &&
            recv_dest_port == dest_port)
        {
            continue;
        }

        // Verify that the packet came from the target,
        // was sent to our local source IP,
        // and uses the expected UDP ports
        if (iprecv->saddr ==
                inet_addr(ipaddress.c_str()) &&

            iprecv->daddr ==
                inet_addr(source_ip.c_str()) &&

            recv_source_port == dest_port &&

            recv_dest_port == source_port)
        {
            // A matching UDP response was received,
            // so consider the destination port open
            openports.push_back(dest_port);

            // Store the source port used for this scan
            sourceports.push_back(source_port);

            // Stop waiting for additional packets
            break;
        }
    }

    // Clear the receive buffer
    memset(buffer, 0, sizeof(buffer));

    // Close both raw sockets
    close(rawsock);
    close(recvsock);
}
