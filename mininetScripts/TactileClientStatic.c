// Client side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <time.h>  
#include <stdio.h>
#include <sys/time.h>
#define PORT     8080
#define MAXLINE 1024 
  
// Driver code 
int main() { 
    int sockfd; 
    char buffer[MAXLINE]; 
    char *data = " Some tactile data"; 
    struct sockaddr_in     servaddr; 
    struct timeval  tv;
    int optval;  
    time_t t;
    int n, len;
    static int delay[4] = {2914, 6834, 14984, 59414};
    static int tos[4]   = {4, 8, 12, 16};
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
  
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr.s_addr = inet_addr("200.0.1.10"); 
      
    optval = 4;
    while (optval > 1) {
    	printf("Slice Switch \n");
    	
    	setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos[optval], sizeof(optval));
    	t = time(NULL) + 5;
    	while (time(NULL) < t){
    	    usleep(delay[optval]);
    	    char output[100];
    	    gettimeofday(&tv, NULL);
    	    long time_in_us = (tv.tv_sec) * 1000000 + (tv.tv_usec);
    	    snprintf(output, 50, "%d %ld", optval, time_in_us);
    	    strcat(output, data);
    	    sendto(sockfd, (const char *)&output, 100, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
    	printf("%s\n",output);
    	}
    }
  
    close(sockfd); 
    return 0; 
} 

