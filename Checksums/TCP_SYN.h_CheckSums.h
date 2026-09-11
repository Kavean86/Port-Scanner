#pragma once
#include <cstdint>

uint16_t TCP_SYN_checksum(uint16_t *data, int length)
{
uint32_t sum = 0;
while (length > 1)
{
sum += *data++;
length -= 2;
}
if (length == 1)
sum += *(uint8_t *)data;
while (sum >> 16)
sum = (sum & 0xFFFF) + (sum >> 16);
return (uint16_t)(~sum);
}


struct pseudo_header
{
	    uint32_t source_address;
	        uint32_t dest_address;
		    uint8_t  placeholder;
		        uint8_t  protocol;
			    uint16_t tcp_length;
};

uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int tcp_len)
{
pseudo_header psh{};
psh.source_address = ip->saddr;
psh.dest_address = ip->daddr;
psh.placeholder = 0;
psh.protocol = IPPROTO_TCP;
psh.tcp_length = htons(tcp_len);
int total_len = sizeof(pseudo_header) + tcp_len;
uint8_t *buffer = new uint8_t[total_len];
memcpy(buffer, &psh, sizeof(pseudo_header));
memcpy(buffer + sizeof(pseudo_header), tcp, tcp_len);
uint32_t sum = 0;
uint16_t *ptr = (uint16_t *)buffer;
while (total_len > 1)
{
sum += *ptr++;
total_len -= 2;
}
if (total_len == 1)
sum += *(uint8_t *)ptr;
while (sum >> 16)
sum = (sum & 0xFFFF) + (sum >> 16);
delete[] buffer;
return (uint16_t)(~sum);
}
