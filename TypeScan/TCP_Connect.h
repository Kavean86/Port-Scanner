#pragma once
#include <vector>
#include <fcntl.h>
#include "Global_var.h"
using namespace std;

// Attempt to establish a TCP connection to the specified port
void tcp_connect(int main_socket,int port,sockaddr_in sock){

// Set the socket to non-blocking mode
fcntl(main_socket,F_SETFL,O_NONBLOCK);

// Try to connect immediately
if(connect(main_socket,(sockaddr*)&sock,sizeof(sock))==0){

// Get the local socket address
socklen_t addrLen = sizeof(sock);
if(getsockname(main_socket,(sockaddr*)&sock,&addrLen)==0){

// Store the local source port and target port
sourceports.push_back(ntohs(sock.sin_port));
openports.push_back(port);
}

}else if(errno==EINPROGRESS){

// File descriptor set used to monitor the socket for writability
fd_set writefds;
FD_ZERO(&writefds);
FD_SET(main_socket,&writefds);

// Set the maximum time to wait for the connection
timeval timeout{};
timeout.tv_sec=0;
timeout.tv_usec=200000;

// Wait until the socket becomes writable or the timeout expires
int result=select(main_socket+1,nullptr,&writefds,nullptr,&timeout);

if(result>0 && FD_ISSET(main_socket,&writefds)){

// Variable used to retrieve the connection error status
int error=0;
socklen_t len=sizeof(error);

// Get the result of the asynchronous connection attempt
getsockopt(main_socket,SOL_SOCKET,SO_ERROR,&error,&len);

if(error==0){

// Get the local socket address after a successful connection
socklen_t addrLen=sizeof(sock);
if(getsockname(main_socket,(sockaddr*)&sock,&addrLen)==0){

// Store the local source port and target port
sourceports.push_back(ntohs(sock.sin_port));
openports.push_back(port);
}

}
}
}

// Close the socket after the connection attempt
close(main_socket);
}
