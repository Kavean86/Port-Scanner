#pragma once
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <cstring>
#include <random>
#include <cerrno>
#include "Global_var.h"
#include "TCP_SYN.h_CheckSums.h"
#include "route.h"
using namespace std;

// Perform a TCP XMAS scan against the specified destination port
void xmas_connect(int dest_port,string ipaddress){

// Generate a random source port for the crafted TCP packet
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<int> dist(1024, 65535);
int source_port = dist(gen);

// Create a raw TCP socket for manually crafting the packet
int rawsock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
if(rawsock<0){
perror("socket");
return;
}

// Enable manual construction of the IPv4 header
int one=1;
if(setsockopt(rawsock,IPPROTO_IP,IP_HDRINCL,&one,sizeof(one))<0){
perror("setsockopt");
close(rawsock);
return;
}

// Determine the local source IP address used to reach the target
string source_ip = get_source_ip(ipaddress);
if (source_ip.empty()) {
cerr << "Could not determine source IP\n";
close(rawsock);
return;
}

// Buffer used to construct the IP and TCP headers
char packet[1024]={0};

// Point to the IP header
iphdr* ip=(iphdr*)packet;

// Place the TCP header immediately after the IP header
tcphdr* tcp=(tcphdr*)(packet+sizeof(iphdr));

// Configure the IPv4 header
ip->version=4;
ip->ihl=5;
ip->id=htons(45896);
ip->ttl=64;
ip->protocol=IPPROTO_TCP;
ip->tot_len=htons(sizeof(iphdr)+sizeof(tcphdr));
ip->frag_off=0;

// Set the source and destination IP addresses
ip->saddr=inet_addr(source_ip.c_str());
ip->daddr=inet_addr(ipaddress.c_str());

// Configure the TCP source and destination ports
tcp->source=htons(source_port);
tcp->dest=htons(dest_port);

// Set the TCP sequence number and receive window
tcp->seq=htonl(4000);
tcp->window=htons(65535);

// TCP header length
tcp->doff=5;

// XMAS scan sends a packet with FIN, PSH and URG flags enabled
tcp->syn=0;
tcp->rst=0;
tcp->fin=1;
tcp->ack=0;
tcp->urg=1;
tcp->psh=1;

// Calculate the IPv4 header checksum
ip->check=0;
ip->check=TCP_SYN_checksum((uint16_t *)ip,ip->ihl * 4);

// Calculate the TCP checksum
int tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);
tcp->check = tcp_checksum(ip, tcp, tcp_len);

// Configure the destination address for sendto()
sockaddr_in dest;
dest.sin_family=AF_INET;
inet_pton(AF_INET, ipaddress.c_str(), &dest.sin_addr);

// Calculate the total packet size
int packet_size =sizeof(struct iphdr) +sizeof(struct tcphdr);

// Create a raw socket for receiving TCP responses
int recvsock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
if (recvsock < 0) {
perror("socket");
close(rawsock);
return;
}

// Configure the initial receive timeout
struct timeval timeout;
timeout.tv_sec = 0;
timeout.tv_usec = 200000;

if(setsockopt(recvsock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0){
perror("setsockopt");
close(rawsock);
close(recvsock);
return;
}

// Send the crafted XMAS packet
ssize_t send=sendto(rawsock,packet,packet_size,0,(sockaddr*)&dest,sizeof(dest));

// Check whether sending the packet failed
if(send<0){
perror("sendto");
}

// Buffer used to store received packets
char buffer[1024]={0};

// Configure a shorter receive timeout
timeval tv{};

tv.tv_sec = 0;
tv.tv_usec = 100;

if (setsockopt(recvsock, SOL_SOCKET, SO_RCVTIMEO,&tv, sizeof(tv)) < 0) {
perror("setsockopt");
}

// Try to receive responses
for(int i=0;i<=1;i++){

    // Receive a TCP packet from the raw socket
    ssize_t received = recv(recvsock,buffer,sizeof(buffer),0);

    // Handle receive errors and timeout
    if(received < 0){

        // No response within the timeout
        // XMAS scans generally interpret this as open or filtered
        if(errno == EAGAIN || errno == EWOULDBLOCK){
            openports.push_back(dest_port);
            sourceports.push_back(source_port);
            break;
        }

        // Handle other receive errors
        perror("recv");
        close(rawsock);
        close(recvsock);
        return;
    }

    // Interpret the received packet as an IPv4 header
    iphdr* iprecv=(iphdr*)buffer;

    // Locate the TCP header using the IP header length
    tcphdr* tcprecv=(tcphdr*)(buffer+iprecv->ihl*4);

    // A TCP RST response indicates that the destination port is closed
    if (tcprecv->rst == 1 &&
    ntohs(tcprecv->source) == dest_port &&
    ntohs(tcprecv->dest) == source_port) {

    cout << "close " << dest_port << endl;
    break;
}

}

// Clear the receive buffer
memset(buffer,0,sizeof(buffer));

// Close the raw sockets
close(rawsock);
close(recvsock);
}
