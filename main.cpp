#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <chrono>
#include <string>
#include <regex>
#include "scan_info.h"
#include "TCP_Connect.h"
#include "UDP.h"
#include "XMAS.h"
#include "ACK.h"
#include "FIN.h"
#include "NULL.h"
#include "TCP_SYN.h"
#include "functions.h"
#include "Global_var.h"
using namespace std;
using namespace chrono;

int main(int argc,char* argv[]){

// Check if the minimum required command-line arguments were provided
if (argc < 3) {
cerr << "Usage: " << argv[0] << " <IP> " <<"<TYPESCAN>\n";
return 1;
}

// Store the target IP address and scan type from command-line arguments
string IP=argv[1];
string type=argv[2];

// Variables for the first and last ports
string Fport;
string Lport;

// Get the first and last ports if they were provided
if(argc >= 5){
Fport = argv[3];
Lport = argv[4];
}

// Delay between starting scans
int delay_ms;

// Regular expression used to validate IPv4 addresses and localhost
regex regex_ip(R"(^(localhost|((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}))$)");

// Regular expression used to validate supported scan types
regex regex_type(R"(^(tcs|scs|ncs|xmascs|fcs|acs|ucs)$)");

// Check whether the target IP has a valid format
if(!regex_match(IP,regex_ip)){
cerr << "Your IP format is invalid!\n";
return 1;
}

// Check whether the selected scan type is valid
if(!regex_match(type,regex_type)){
cerr << "Your IP format is invalid!!\n";
return 1;
}

// Set the default first port if no port was provided
if(Fport.empty()){
Fport="1";
}

// Set the default last port if no port was provided
if(Lport.empty()){
Lport="1000";
}

// Convert the port strings to integers
int first_port=stoi(Fport);
int last_port=stoi(Lport);

// Use a shorter delay for localhost
if(IP=="127.0.0.1"||IP=="localhost"){
delay_ms=1;
}else{
delay_ms=100;
}

// Convert localhost to the IPv4 loopback address
if(IP=="localhost"){
IP="127.0.0.1";
}

// Record the start time of the scan
auto start = high_resolution_clock::now();

// Display information about the scan
info(IP,type,Fport,Lport);   

// Iterate through all ports in the specified range
for(int i=first_port;i<=last_port;i++){

// Create a TCP socket for the current port
int main_socket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

// Check whether socket creation failed
if(main_socket<0){
perror("socket");
return 0;
}

// Initialize the socket address structure
sockaddr_in sock={};

// Set the address family to IPv4
sock.sin_family=AF_INET;

// Set the current port number
sock.sin_port=htons(i);

// Convert the target IP address from text to binary format
inet_pton(AF_INET,IP.c_str(),&sock.sin_addr);

// Select the requested scan type and start it in a separate thread
if(type=="tcs"){
//thread(tcp_connect,main_socket,i,sock).detach();
threads.emplace_back(tcp_connect,main_socket,i,sock);
}else if(type=="scs"){
//thread(syn_connect,i,IP).detach();
threads.emplace_back(syn_connect,i,IP);
}else if(type=="ucs"){
//thread(udp_connect,i,IP).detach();   
threads.emplace_back(udp_connect,i,IP);
}else if (type=="acs"){
//thread(ack_connect,i,IP).detach();
threads.emplace_back(ack_connect,i,IP);
}else if (type=="fcs"){
//thread(fin_connect,i,IP).detach();
threads.emplace_back(fin_connect,i,IP);
}else if (type=="ncs"){
//thread(null_connect,i,IP).detach();    
threads.emplace_back(null_connect,i,IP);
}else if(type=="xmascs"){
//thread(xmas_connect,i,IP).detach(); 
threads.emplace_back(xmas_connect,i,IP);
}

// Wait before starting the scan for the next port
this_thread::sleep_for(chrono::milliseconds(delay_ms));
}
for(auto& t : threads){
    t.join();
}
// Record the end time after all scan threads have been started
auto end = high_resolution_clock::now();

// Calculate the elapsed execution time
auto duration = duration_cast<milliseconds>(end - start);

// Display the scan results
print_results(type);

// Display the execution time in seconds and milliseconds
cout << "Execution time: "<< duration.count() / 1000 << " s "<< duration.count() % 1000 << " ms\n";
}
