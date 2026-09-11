#pragma once
#include <cstdint>

uint16_t UDP_checksum(uint16_t *data, int length)
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


uint16_t udp_checksum(iphdr* ip, udphdr* udp)
{
uint32_t sum = 0;
sum += (ntohl(ip->saddr) >> 16) & 0xFFFF;
sum += ntohl(ip->saddr) & 0xFFFF;
sum += (ntohl(ip->daddr) >> 16) & 0xFFFF;
sum += ntohl(ip->daddr) & 0xFFFF;
sum += IPPROTO_UDP;
sum += ntohs(udp->len);
uint16_t* ptr = (uint16_t*)udp;
for (int i = 0; i < sizeof(udphdr) / 2; i++)
sum += ntohs(ptr[i]);
while (sum >> 16)
sum = (sum & 0xFFFF) + (sum >> 16);
return htons(~sum & 0xFFFF);
}
