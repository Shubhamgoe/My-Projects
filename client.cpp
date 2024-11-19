#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
// using namespace std;

#define DEST_IP "127.0.0.1"
#define DEST_PORT 8080
#define SYN_FLAG 0x02
#define ACK_FLAG 0x10
#define FIN_FLAG 0x01

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
    uint8_t dataOffset;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;

    TCPHeader() {
        sourcePort = htons(12345);
        destPort = htons(8080);
        seqNum = htonl(1000);
        ackNum = 0;
        dataOffset = 5 << 4;
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
    ipHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader);
    ipHeader->id = htons(54321);
    ipHeader->frag_off = 0;
    ipHeader->ttl = 255;
    ipHeader->protocol = IPPROTO_TCP;
    ipHeader->saddr = inet_addr("127.0.0.1");
    ipHeader->daddr = inet_addr(DEST_IP);

    // Fill in the TCP Header
    tcpHeader->sourcePort = htons(12345);
    tcpHeader->destPort = htons(DEST_PORT);
    tcpHeader->seqNum = htonl(0);
    tcpHeader->ackNum = 0;
    tcpHeader->dataOffset = 5 << 4;
    tcpHeader->flags = SYN_FLAG;
    tcpHeader->windowSize = htons(1024);
    tcpHeader->checksum = calculateChecksum((uint16_t *)tcpHeader, sizeof(TCPHeader) / 2);

    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(DEST_PORT);
    destAddr.sin_addr.s_addr = inet_addr(DEST_IP);

    if (sendto(sock, packet, ipHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
        perror("Packet sending failed");
        close(sock);
        return -1;
    }

    std::cout << "SYN packet sent. Waiting for response...\n" << std::flush;
    

    state = SYN_SENT;
    // cout<<"ready";
    
    struct sockaddr_in sourceAddr;
    socklen_t sourceAddrLen = sizeof(sourceAddr);
    char recvPacket[4096];
    
    while (true) {
        // cout<<"ready";
        // std::cout << "before" << std::endl;
        int recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&sourceAddr, &sourceAddrLen);
        // std::cout << recven << std::endl;
        // cout<<"got it";
        if (recvLen < 0) {
            perror("Error receiving packet");
            close(sock);
            return -1;
        }

        struct iphdr *recvIpHeader = (struct iphdr *)recvPacket;
        struct TCPHeader *recvTcpHeader = (struct TCPHeader *)(recvPacket + sizeof(struct iphdr));

        // Assuming you have already set up recvPacket and parsed the IP and TCP headers
        // Check the first 20 bytes of the packet to ensure it's an IP packet
        std::cout << "Received packet length: " << recvLen << std::endl;
        std::cout << "First byte: " << (int)recvPacket[0] << std::endl;
        std::cout << "Protocol field in IP header: " << (int)recvIpHeader->protocol << std::endl;
        std::cout << "TCP flags: " << (int)recvTcpHeader->flags << std::endl;
        state = ESTABLISHED;
        break;



        // if (recvIpHeader->protocol == IPPROTO_TCP && (recvTcpHeader->flags & (SYN_FLAG | ACK_FLAG)) == (SYN_FLAG | ACK_FLAG)) {
        //     std::cout << "Received SYN-ACK packet from server!\n";
        //     state = ESTABLISHED;
        //     break;
        // }
    }

    while (state == ESTABLISHED) {
        std::cout << "Enter some input: ";
        std::getline(std::cin, message);

        char messagePacket[4096];
        memset(messagePacket, 0, sizeof(messagePacket));

        struct iphdr *messageIpHeader = (struct iphdr *)messagePacket;
        struct TCPHeader *messageTcpHeader = (struct TCPHeader *)(messagePacket + sizeof(struct iphdr));

        messageIpHeader->ihl = 5;
        messageIpHeader->version = 4;
        messageIpHeader->tos = 0;
        messageIpHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader) + message.size();
        messageIpHeader->id = htons(54322);
        messageIpHeader->frag_off = 0;
        messageIpHeader->ttl = 255;
        messageIpHeader->protocol = IPPROTO_TCP;
        messageIpHeader->saddr = inet_addr("127.0.0.1");
        messageIpHeader->daddr = inet_addr(DEST_IP);

        messageTcpHeader->sourcePort = htons(12345);
        messageTcpHeader->destPort = htons(DEST_PORT);
        messageTcpHeader->seqNum = htonl(0);
        messageTcpHeader->ackNum = 0;
        messageTcpHeader->dataOffset = 5 << 4;
        messageTcpHeader->flags = ACK_FLAG;
        messageTcpHeader->windowSize = htons(1024);
        messageTcpHeader->checksum = calculateChecksum((uint16_t *)messageTcpHeader, sizeof(TCPHeader) / 2);

        if (message == "exit") {
            messageTcpHeader->flags = FIN_FLAG;
            memcpy(messagePacket + sizeof(struct iphdr) + sizeof(TCPHeader), message.c_str(), message.size());
            if (sendto(sock, messagePacket, messageIpHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
                perror("Message sending failed");
                close(sock);
                return -1;
            }
            state = FIN_WAIT;
            std::cout << "Connection is terminating.\n";
            
            int recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&sourceAddr, &sourceAddrLen);
            if (recvLen < 0) {
                perror("Error receiving packet");
                close(sock);
                return -1;
            }
            struct iphdr *recvIpHeader = (struct iphdr *)recvPacket;
            struct TCPHeader *recvTcpHeader = (struct TCPHeader *)(recvPacket + sizeof(struct iphdr));
            if(recvIpHeader->protocol == IPPROTO_TCP && ((recvTcpHeader->flags&ACK_FLAG)==ACK_FLAG)){
                std::cout << "Fin-ack recieved\n";
            }

            recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&sourceAddr, &sourceAddrLen);
            if (recvLen < 0) {
                perror("Error receiving packet");
                close(sock);
                return -1;
            }
            
            if(recvIpHeader->protocol == IPPROTO_TCP && ((recvTcpHeader->flags&FIN_FLAG)==FIN_FLAG)){
                std::cout << "Fin recieved from server\n";
            }

            memcpy(messagePacket + sizeof(struct iphdr) + sizeof(TCPHeader), message.c_str(), message.size());
            if (sendto(sock, messagePacket, messageIpHeader->tot_len, 0, (struct sockaddr *)&destAddr, sizeof(destAddr)) < 0) {
                perror("Message sending failed");
                close(sock);
                return -1;
            }
            std::cout << "Final ack sent and connection terminated\n";
            break;
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
