// Server side implementation of UDP client-server model 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <sys/time.h>
  
#define PORT    8080
#define MAXLINE 1024 
  
// Driver code 
int main() { 
    int sockfd; 
    char buffer[MAXLINE]; 
    char *hello = "Hello from server"; 
    struct sockaddr_in servaddr, cliaddr; 
      
    // Creating socket file descriptor 
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(PORT); 
      
    // Bind the socket with the server address 
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
    { 
        perror("bind failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    int len, n;
    char time_sent[16];
    int tos;
    char *pEnd;

    struct timeval  tv;
    while(1){ 
    n = recvfrom(sockfd, (char *)buffer, MAXLINE,  
                MSG_WAITALL, ( struct sockaddr *) &cliaddr, 
                &len); 
    gettimeofday(&tv, NULL);
    long time_in_us = (tv.tv_sec) * 1000000 + (tv.tv_usec);
    buffer[n] = '\0';
    int optval = strtol((char *)buffer ,&pEnd, 10);
    long dest = strtol (pEnd,&pEnd,10);
    setsockopt(sockfd, IPPROTO_IP, IP_TOS, &optval, sizeof(optval));
    printf("%d, %d, %ld, %ld, %ld \n", n, optval, dest, time_in_us, time_in_us - dest); 
    cliaddr.sin_port = htons(PORT+1); 
    sendto(sockfd, (const char *)buffer, strlen(buffer), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len); 
    }
    return 0; 
} 
