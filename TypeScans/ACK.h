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

// Send a TCP ACK packet to the target port
void ack_connect(int dest_port,string ipaddress){

// Generate a random source port between 1024 and 65535
random_device rd;
mt19937 gen(rd());
uniform_int_distribution<int> dist(1024, 65535);
int source_port = dist(gen);

// Create a raw socket for sending custom TCP/IP packets
int rawsock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
if(rawsock<0){
perror("socket");
return;
}

// Enable manual construction of the IP header
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

// Buffer used to construct the complete IP + TCP packet
char packet[1024]={0};

// Point to the IP header at the beginning of the packet
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

// Configure the TCP header
tcp->source=htons(source_port);
tcp->dest=htons(dest_port);
tcp->seq=htonl(4000);
tcp->window=htons(65535);
tcp->doff=5;

// Configure TCP flags
tcp->syn=0;
tcp->rst=0;
tcp->fin=0;
tcp->ack=1;
tcp->urg=0;
tcp->psh=0;

// Calculate the IPv4 header checksum
ip->check=0;
ip->check=TCP_SYN_checksum((uint16_t *)ip,ip->ihl * 4);

// Calculate the TCP checksum
int tcp_len = ntohs(ip->tot_len) - (ip->ihl * 4);
tcp->check = tcp_checksum(ip, tcp, tcp_len);

// Configure the destination socket address
sockaddr_in dest;
dest.sin_family=AF_INET;
inet_pton(AF_INET, ipaddress.c_str(), &dest.sin_addr);

// Calculate the total packet size
int packet_size =sizeof(struct iphdr) +sizeof(struct tcphdr);

// Create a raw socket for receiving TCP packets
int recvsock=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
if (recvsock < 0) {
perror("socket");
close(rawsock);
return;
}

// Configure a 200ms receive timeout
struct timeval timeout;
timeout.tv_sec = 0;
timeout.tv_usec = 200000;

if(setsockopt(recvsock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0){
perror("setsockopt");
close(rawsock);
close(recvsock);
return;
}

// Send the crafted TCP ACK packet
ssize_t send=sendto(rawsock,packet,packet_size,0,(sockaddr*)&dest,sizeof(dest));

if(send<0){
perror("sendto");
}

// Buffer used to store received packets
char buffer[1024]={0};

// Try to receive responses
for(int i=0;i<=1;i++){

    // Receive a packet from the raw socket
    ssize_t received = recv(recvsock,buffer,sizeof(buffer),0);

    // Handle receive errors and timeout
    if(received < 0){

        // Stop scanning if the receive operation timed out
        if(errno == EAGAIN || errno == EWOULDBLOCK){
            break;
        }

        // Handle other receive errors
        perror("recv");
        close(rawsock);
        close(recvsock);
        return;
    }

    // Interpret the beginning of the received data as an IP header
    iphdr* iprecv=(iphdr*)buffer;

    // Locate the TCP header using the IP header length
    tcphdr* tcprecv=(tcphdr*)(buffer+iprecv->ihl*4);

// Check whether the received packet is a TCP RST
// and verify that the source and destination ports match
if(tcprecv->rst=1 && ntohs(tcprecv->source)==dest_port && ntohs(tcprecv->dest)==source_port){
           
// Store the detected destination port
openports.push_back(dest_port);

// Store the source port associated with the response
sourceports.push_back(source_port);
    }
}

// Clear the receive buffer
memset(buffer,0,sizeof(buffer));

// Close the sending and receiving raw sockets
close(rawsock);
close(recvsock);
}
