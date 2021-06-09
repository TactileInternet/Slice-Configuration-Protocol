#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include <inttypes.h>

struct {
  char zeros[8];
  uint16_t reason;
  uint16_t source_ingress;
  uint16_t port;
  uint16_t dev_id;
} cpu_hdr;


int main() {
    // Structs that contain source IP addresses
    struct sockaddr_in source_socket_address, dest_socket_address;
    int bandwidth[4] = {122500, 41250, 20000, 16250};
    int packet_size;
    char cmdbuf[256], zeros[8];
    // Allocate string buffer to hold incoming packet data
    unsigned char *buffer = (unsigned char *)malloc(16);
    // Open the raw socket
    int sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }
    while(1) {
      // recvfrom is used to read data from a socket
      packet_size = recvfrom(sock , buffer , 16 , 0 , NULL, NULL);
      if (packet_size == -1) {
        printf("Failed to get packets\n");
        return 1;
      }


   	memset(zeros, 0, sizeof(zeros));
   	if (memcmp(zeros, buffer, sizeof(zeros))) return 1;
   	memcpy(&cpu_hdr, buffer, sizeof(cpu_hdr));
   	cpu_hdr.reason = ntohs(cpu_hdr.reason);
   	cpu_hdr.dev_id = ntohs(cpu_hdr.dev_id);
   	cpu_hdr.source_ingress = ntohs(cpu_hdr.source_ingress);
   	cpu_hdr.port = ntohs(cpu_hdr.port);
   	//printf("Incoming Packet %u: %u s%u-eth%u\n", (unsigned int)cpu_hdr.source_ingress, (unsigned int)cpu_hdr.reason, (unsigned int)cpu_hdr.dev_id -1, (unsigned int)cpu_hdr.port);
   	if (cpu_hdr.source_ingress == 1) snprintf(cmdbuf, sizeof(cmdbuf), "allocate_bandwidth.sh %d s%u-eth%u",  bandwidth[cpu_hdr.reason-1], (unsigned int)cpu_hdr.dev_id -1, (unsigned int)cpu_hdr.port);
   	else snprintf(cmdbuf, sizeof(cmdbuf), "release_bandwidth.sh %d s%u-eth%u", bandwidth[cpu_hdr.reason-1], (unsigned int)cpu_hdr.dev_id -1, (unsigned int)cpu_hdr.port);
	
	int err = system(cmdbuf);
	if (err) fprintf(stderr, "failed to %s\n", cmdbuf); 
   }
    return 0;
}

