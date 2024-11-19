#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define DEST_IP "127.0.0.1"
#define DEST_PORT 8080
#define SYN_FLAG 0x02  // Macro for SYN flag
#define ACK_FLAG 0x10  // ACK flag
#define FIN_FLAG 0x01  // Macro for FIN flag

enum TCPState {
    CLOSED,
    SYN_SENT,
    ESTABLISHED,
    FIN_WAIT
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
        destPort = htons(8080);     // Arbitrary destination port
        seqNum = htonl(1000);       // Arbitrary sequence number
        ackNum = 0;
        dataOffset = 5 << 4;        // 5 words (20 bytes) << 4
        flags = 0;
        windowSize = htons(1024);
        checksum = 0;
        urgentPointer = 0;
    }
};

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
    
    std::string message;

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

    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ipHeader = (struct iphdr *)packet;
    struct TCPHeader *tcpHeader = (struct TCPHeader *)(packet + sizeof(struct iphdr));

    // Fill in the IP Header
    ipHeader->ihl = 5;
    ipHeader->version = 4;
    ipHeader->tos = 0;
    ipHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader) + message.size();
    ipHeader->id = htons(54321);
    ipHeader->frag_off = 0;
    ipHeader->ttl = 255;
    ipHeader->protocol = IPPROTO_TCP;
    ipHeader->saddr = inet_addr("127.0.0.1");  // Replace with client's IP
    ipHeader->daddr = inet_addr(DEST_IP);

    // Fill in the TCP Header
    tcpHeader->sourcePort = htons(12345);  // Arbitrary source port
    tcpHeader->destPort = htons(DEST_PORT);
    tcpHeader->seqNum = htonl(0);
    tcpHeader->ackNum = 0;
    tcpHeader->dataOffset = 5 << 4;
    tcpHeader->flags = SYN_FLAG;  // SYN flag set
    tcpHeader->windowSize = htons(1024);

    // Calculate the checksum
    tcpHeader->checksum = calculateChecksum((uint16_t *)tcpHeader, sizeof(TCPHeader) / 2);

    // Destination address
    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(DEST_PORT);
    destAddr.sin_addr.s_addr = inet_addr(DEST_IP);

    // Send the SYN packet
    if (sendto(sock, packet, ipHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
        perror("Packet sending failed");
        close(sock);
        return -1;
    }

    std::cout << "SYN packet sent. Waiting for response...\n";
    state = SYN_SENT;

    // Now, let's wait for the incoming SYN-ACK packet
    struct sockaddr_in sourceAddr;
    socklen_t sourceAddrLen = sizeof(sourceAddr);
    char recvPacket[4096];

    while (true) {
        int recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&sourceAddr, &sourceAddrLen);
        if (recvLen < 0) {
            perror("Error receiving packet");
            close(sock);
            return -1;
        }

        struct iphdr *recvIpHeader = (struct iphdr *)recvPacket;
        struct TCPHeader *recvTcpHeader = (struct TCPHeader *)(recvPacket + sizeof(struct iphdr));

        // Check if the received packet is a TCP packet and has both SYN and ACK flags set
        if (recvIpHeader->protocol == IPPROTO_TCP) {
            if ((recvTcpHeader->flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
                std::cout << "Received SYN-ACK packet from server!\n";
                state = ESTABLISHED;
                break;
            }
        }
    }
    while(true){

        std::cout << "Enter some input: ";
        std::getline(std::cin, message);  // Reads a full line of input from the user
        

        // Send the message to the server
        char messagePacket[4096];
        memset(messagePacket, 0, sizeof(messagePacket));

        struct iphdr *messageIpHeader = (struct iphdr *)messagePacket;
        struct TCPHeader *messageTcpHeader = (struct TCPHeader *)(messagePacket + sizeof(struct iphdr));

        // Fill in the IP Header
        messageIpHeader->ihl = 5;
        messageIpHeader->version = 4;
        messageIpHeader->tos = 0;
        messageIpHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader) + message.size();
        messageIpHeader->id = htons(54322);
        messageIpHeader->frag_off = 0;
        messageIpHeader->ttl = 255;
        messageIpHeader->protocol = IPPROTO_TCP;
        messageIpHeader->saddr = inet_addr("127.0.0.1");  // Replace with client's IP
        messageIpHeader->daddr = inet_addr(DEST_IP);

        // Fill in the TCP Header
        messageTcpHeader->sourcePort = htons(12345);  // Arbitrary source port
        messageTcpHeader->destPort = htons(DEST_PORT);
        messageTcpHeader->seqNum = htonl(0);
        messageTcpHeader->ackNum = 0;
        messageTcpHeader->dataOffset = 5 << 4;
        messageTcpHeader->flags = ACK_FLAG;  // ACK flag set
        messageTcpHeader->windowSize = htons(1024);

        // Calculate the checksum
        messageTcpHeader->checksum = calculateChecksum((uint16_t *)messageTcpHeader, sizeof(TCPHeader) / 2);

        // Append the message to the packet
        

        // Send the message to the server
        if (message == "exit") {
            messageTcpHeader->flags = FIN_FLAG;
            memcpy(messagePacket + sizeof(struct iphdr) + sizeof(TCPHeader), message.c_str(), message.size());
            if (sendto(sock, messagePacket, messageIpHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
                perror("Message sending failed");
                close(sock);
                return -1;
            }
            break;  // Exit the loop if 'exit' is entered
        }
        memcpy(messagePacket + sizeof(struct iphdr) + sizeof(TCPHeader), message.c_str(), message.size());
        if (sendto(sock, messagePacket, messageIpHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
            perror("Message sending failed");
            close(sock);
            return -1;
        }

        std::cout << "Message sent: " << message << std::endl;
    }
    close(sock);
    return 0;
}
