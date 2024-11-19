#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define LISTEN_PORT 8080
#define SYN_FLAG 0x02  // SYN flag
#define ACK_FLAG 0x10  // ACK flag
#define FIN_FLAG 0x01  // Macro for FIN flag

enum TCPState {
    CLOSED,
    LISTEN,
    SYN_RECEIVED,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK
};

struct TCPHeader {
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t dataOffset;  // Header length (5 << 4 for 20 bytes)
    uint8_t flags;       // Flags (SYN, ACK, etc.)
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;

    TCPHeader() {
        sourcePort = htons(12345);  // Arbitrary source port
        destPort = htons(LISTEN_PORT); // Listen port
        seqNum = htonl(1000);       // Arbitrary sequence number
        ackNum = 0;
        dataOffset = 5 << 4;        // 5 words (20 bytes) << 4
        flags = 0;
        windowSize = htons(1024);
        checksum = 0;
        urgentPointer = 0;
    }
};

// Function to calculate checksum
uint16_t calculateChecksum(uint16_t *buffer, int size) {
    uint32_t sum = 0;
    for (int i = 0; i < size; i++) {
        sum += ntohs(buffer[i]);
        if (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
    }
    return htons(~sum);
}

int main() {
    TCPState state = CLOSED;
    state = LISTEN;
    
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Enable IP_HDRINCL to let the kernel know that headers are included in the packet
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting socket options");
        return -1;
    }

    char recvPacket[4096];
    struct iphdr *ipHeader = (struct iphdr *)recvPacket;
    struct TCPHeader *tcpHeader = (struct TCPHeader *)(recvPacket + sizeof(struct iphdr));

    // Destination address for sending the SYN-ACK response
    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(LISTEN_PORT);
    destAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Replace with client's IP

    // Bind to the listen port (should match the client's destination port)
    struct sockaddr_in listenAddr;
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_port = htons(LISTEN_PORT);
    listenAddr.sin_addr.s_addr = inet_addr("0.0.0.0");  // Listen on all interfaces

    if (bind(sock, (struct sockaddr *)&listenAddr, sizeof(listenAddr)) < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }
    printf("Server is listening on port %d\n", LISTEN_PORT);
    // Listen for incoming packets (SYN)
    socklen_t addrLen;
    while(true){

        addrLen = sizeof(listenAddr);
        int recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&listenAddr, &addrLen);
        if ((recvLen) < 0) {
            perror("Failed to receive packet");
            close(sock);
            return -1;
        }

        // Check if it's a SYN packet from the client
        if (tcpHeader->flags == SYN_FLAG) {
            std::cout << "Received SYN packet. Sending SYN-ACK...\n";

            // Prepare the SYN-ACK response
            tcpHeader->flags = SYN_FLAG | ACK_FLAG;  // Set SYN and ACK flags
            tcpHeader->ackNum = ntohl(tcpHeader->seqNum) + 1;  // Acknowledge client's seqNum + 1
            tcpHeader->seqNum = htonl(2000);  // Arbitrary seqNum for server

            // Calculate checksum for the TCP header
            tcpHeader->checksum = 0;  // Reset checksum before calculation
            tcpHeader->checksum = calculateChecksum((uint16_t *)tcpHeader, sizeof(TCPHeader) / 2);

            // Prepare the IP header
            ipHeader->ihl = 5;
            ipHeader->version = 4;
            ipHeader->tos = 0;
            ipHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader);
            ipHeader->id = htons(54321);  // Arbitrary ID
            ipHeader->frag_off = 0;
            ipHeader->ttl = 255;
            ipHeader->protocol = IPPROTO_TCP;
            ipHeader->saddr = inet_addr("172.31.177.226");  // Server's IP
            ipHeader->daddr = inet_addr("192.168.1.2");    // Client's IP

            // Send the SYN-ACK response
            if (sendto(sock, recvPacket, ipHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
                perror("Failed to send SYN-ACK");
                close(sock);
                return -1;
            }

            std::cout << "SYN-ACK sent. Waiting for ACK...\n";
            break;
        }

    }
    while(true){
        char buffer[4096];
        struct iphdr *ipHeader = (struct iphdr *)buffer;
        struct TCPHeader *tcpHeader = (struct TCPHeader *)(buffer + sizeof(struct iphdr));
        int recvLen = recvfrom(sock, buffer, sizeof(recvPacket), 0, (struct sockaddr *)&listenAddr, &addrLen); 
        if(tcpHeader->flags==FIN_FLAG){
            std::cout << "Received message: " << "Sender sent a FIN flag" << std::endl;
            break;
        }  
        std::string message(buffer + sizeof(struct iphdr) + sizeof(struct TCPHeader), recvLen - sizeof(struct iphdr) - sizeof(struct TCPHeader));
        std::cout << "Received message: " << message << std::endl;
    }
    

    close(sock);
    return 0;
}
