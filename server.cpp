#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define SYN_FLAG 0x02
#define ACK_FLAG 0x10
#define FIN_FLAG 0x01

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
    uint8_t dataOffset;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;

    TCPHeader() {
        sourcePort = htons(SERVER_PORT);
        destPort = 0;
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
    state = LISTEN;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(SERVER_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);

    char recvPacket[4096];
    struct sockaddr_in clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    std::cout << "Server is in LISTEN state, waiting for incoming connections...\n";

    while (state == LISTEN) {
        int recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (recvLen < 0) {
            perror("Error receiving packet");
            close(sock);
            return -1;
        }

        struct iphdr *recvIpHeader = (struct iphdr *)recvPacket;
        struct TCPHeader *recvTcpHeader = (struct TCPHeader *)(recvPacket + sizeof(struct iphdr));

        if (recvIpHeader->protocol == IPPROTO_TCP && (recvTcpHeader->flags & SYN_FLAG) == SYN_FLAG) {
            std::cout << "Received SYN packet from client!\n";
            state = SYN_RECEIVED;

            char synAckPacket[4096];
            memset(synAckPacket, 0, sizeof(synAckPacket));

            struct iphdr *synAckIpHeader = (struct iphdr *)synAckPacket;
            struct TCPHeader *synAckTcpHeader = (struct TCPHeader *)(synAckPacket + sizeof(struct iphdr));

            synAckIpHeader->ihl = 5;
            synAckIpHeader->version = 4;
            synAckIpHeader->tos = 0;
            synAckIpHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader);
            synAckIpHeader->id = htons(54321);
            synAckIpHeader->frag_off = 0;
            synAckIpHeader->ttl = 255;
            synAckIpHeader->protocol = IPPROTO_TCP;
            synAckIpHeader->saddr = inet_addr(SERVER_IP);
            synAckIpHeader->daddr = recvIpHeader->saddr;

            synAckTcpHeader->sourcePort = htons(SERVER_PORT);
            synAckTcpHeader->destPort = recvTcpHeader->sourcePort;
            synAckTcpHeader->seqNum = htonl(1001);
            synAckTcpHeader->ackNum = htonl(ntohl(recvTcpHeader->seqNum) + 1);
            synAckTcpHeader->dataOffset = 5 << 4;
            synAckTcpHeader->flags |= (SYN_FLAG | ACK_FLAG);
            synAckTcpHeader->windowSize = htons(1024);
            synAckTcpHeader->checksum = calculateChecksum((uint16_t *)synAckTcpHeader, sizeof(TCPHeader) / 2);

            std::cout << "SYN-ACK Packet flags: " << int(synAckTcpHeader->flags) << std::endl;

            if (sendto(sock, synAckPacket, synAckIpHeader->tot_len, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0) {
                perror("Error sending SYN-ACK packet");
                close(sock);
                return -1;
            }

            std::cout << "SYN-ACK packet sent to client. Transitioning to ESTABLISHED state.\n";
            state = ESTABLISHED;
        }

        while (state == ESTABLISHED) {
            recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
            if (recvLen < 0) {
                perror("Error receiving packet");
                close(sock);
                return -1;
            }

            recvIpHeader = (struct iphdr *)recvPacket;
            recvTcpHeader = (struct TCPHeader *)(recvPacket + sizeof(struct iphdr));

            if (recvIpHeader->protocol == IPPROTO_TCP && (recvTcpHeader->flags & FIN_FLAG) == FIN_FLAG) {
                std::cout << "Received FIN packet from client. Transitioning to CLOSE-WAIT state.\n";
                state = CLOSE_WAIT;

                // Send ACK for the received FIN
                char ackPacket[4096];
                memset(ackPacket, 0, sizeof(ackPacket));

                struct iphdr *ackIpHeader = (struct iphdr *)ackPacket;
                struct TCPHeader *ackTcpHeader = (struct TCPHeader *)(ackPacket + sizeof(struct iphdr));

                ackIpHeader->ihl = 5;
                ackIpHeader->version = 4;
                ackIpHeader->tos = 0;
                ackIpHeader->tot_len = sizeof(struct iphdr) + sizeof(TCPHeader);
                ackIpHeader->id = htons(54323);
                ackIpHeader->frag_off = 0;
                ackIpHeader->ttl = 255;
                ackIpHeader->protocol = IPPROTO_TCP;
                ackIpHeader->saddr = inet_addr(SERVER_IP);
                ackIpHeader->daddr = recvIpHeader->saddr;

                ackTcpHeader->sourcePort = htons(SERVER_PORT);
                ackTcpHeader->destPort = recvTcpHeader->sourcePort;
                ackTcpHeader->seqNum = htonl(ntohl(recvTcpHeader->ackNum));
                ackTcpHeader->ackNum = htonl(ntohl(recvTcpHeader->seqNum) + 1);
                ackTcpHeader->dataOffset = 5 << 4;
                ackTcpHeader->flags = ACK_FLAG;
                ackTcpHeader->windowSize = htons(1024);
                ackTcpHeader->checksum = calculateChecksum((uint16_t *)ackTcpHeader, sizeof(TCPHeader) / 2);

                if (sendto(sock, ackPacket, ackIpHeader->tot_len, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0) {
                    perror("Error sending ACK packet for FIN");
                    close(sock);
                    return -1;
                }

                std::cout << "ACK for FIN sent. Transitioning to LAST-ACK state.\n";
                state = LAST_ACK;

                // Send FIN to complete the termination
                ackTcpHeader->flags = FIN_FLAG;
                if (sendto(sock, ackPacket, ackIpHeader->tot_len, 0, (struct sockaddr *)&clientAddr, sizeof(clientAddr)) < 0) {
                    perror("Error sending FIN packet");
                    close(sock);
                    return -1;
                }

                std::cout << "FIN packet sent. Waiting for final ACK from client.\n";
            }else if (state == LAST_ACK) {
                recvLen = recvfrom(sock, recvPacket, sizeof(recvPacket), 0, (struct sockaddr *)&clientAddr, &clientAddrLen);
                if (recvLen > 0 && (recvTcpHeader->flags & ACK_FLAG) == ACK_FLAG) {
                    std::cout << "Final ACK received. Connection closed.\n";
                    state = CLOSED;
                    break;
                }
            }else{
                std::string message(recvPacket + sizeof(struct iphdr) + sizeof(struct TCPHeader), recvLen - sizeof(struct iphdr) - sizeof(struct TCPHeader));
                std::cout << "Received message: " << message << std::endl;
            }
        }
    }

    close(sock);
    std::cout << "Server closed the connection.\n";
    return 0;
}
