#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <iomanip>

// For MinGW: Define SIO_RCVALL manually
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)

#pragma warning(disable:4996)  // For VS; ignore deprecated warnings
using namespace std;

// IP Header
typedef struct iphdr {
    unsigned char  ihl : 4;
    unsigned char  version : 4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
} IPHeader;

// TCP Header
typedef struct tcphdr {
    unsigned short source;
    unsigned short dest;
    unsigned int   seq;
    unsigned int   ack_seq;
    unsigned short flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
} TCPHeader;

// UDP Header
typedef struct udphdr {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
} UDPHeader;

// ICMP Header
typedef struct icmphdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
} ICMPHeader;

void PrintIPHeader(const IPHeader* iph) {
    struct in_addr s, d;
    s.S_un.S_addr = iph->saddr;
    d.S_un.S_addr = iph->daddr;

    cout << "\n====== IP HEADER ======" << endl;
    cout << "Source IP      : " << inet_ntoa(s) << endl;
    cout << "Destination IP : " << inet_ntoa(d) << endl;
    cout << "Protocol       : ";
    switch (iph->protocol) {
        case IPPROTO_ICMP: cout << "ICMP"; break;
        case IPPROTO_TCP:  cout << "TCP"; break;
        case IPPROTO_UDP:  cout << "UDP"; break;
        default:           cout << (int)iph->protocol;
    }
    cout << endl;
}

void PrintTCPHeader(const TCPHeader* tcp) {
    cout << "------ TCP HEADER ------" << endl;
    cout << "Source Port      : " << ntohs(tcp->source) << endl;
    cout << "Destination Port : " << ntohs(tcp->dest) << endl;
}

void PrintUDPHeader(const UDPHeader* udp) {
    cout << "------ UDP HEADER ------" << endl;
    cout << "Source Port      : " << ntohs(udp->source) << endl;
    cout << "Destination Port : " << ntohs(udp->dest) << endl;
}

void PrintICMPHeader(const ICMPHeader* icmp) {
    cout << "------ ICMP HEADER ------" << endl;
    cout << "Type             : " << (int)icmp->type << endl;
    cout << "Code             : " << (int)icmp->code << endl;
}

int main() {
    WSADATA wsa;
    SOCKET rawSocket;
    char buffer[65536];

    cout << "Initializing Winsock..." << endl;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cerr << "WSAStartup failed: " << WSAGetLastError() << endl;
        return 1;
    }

    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (rawSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed: " << WSAGetLastError() << endl;
        return 1;
    }

    char hostname[100];
    gethostname(hostname, sizeof(hostname));
    struct hostent* local = gethostbyname(hostname);

    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = ((struct in_addr*)(local->h_addr))->s_addr;

    if (bind(rawSocket, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        cerr << "Bind failed: " << WSAGetLastError() << endl;
        return 1;
    }

    u_long optval = 1;
    if (ioctlsocket(rawSocket, SIO_RCVALL, &optval) != 0) {
    cerr << "Failed to set promiscuous mode: " << WSAGetLastError() << endl;
    return 1;
    }


    cout << "Sniffing on interface: " << inet_ntoa(*(in_addr*)local->h_addr) << "\n\n";

    while (true) {
        int dataSize = recv(rawSocket, buffer, sizeof(buffer), 0);
        if (dataSize > 0) {
            IPHeader* iph = (IPHeader*)buffer;
            PrintIPHeader(iph);

            if (iph->protocol == IPPROTO_TCP) {
                TCPHeader* tcp = (TCPHeader*)(buffer + iph->ihl * 4);
                PrintTCPHeader(tcp);
            } else if (iph->protocol == IPPROTO_UDP) {
                UDPHeader* udp = (UDPHeader*)(buffer + iph->ihl * 4);
                PrintUDPHeader(udp);
            } else if (iph->protocol == IPPROTO_ICMP) {
                ICMPHeader* icmp = (ICMPHeader*)(buffer + iph->ihl * 4);
                PrintICMPHeader(icmp);
            }

            cout << "==============================\n";
        }
    }

    closesocket(rawSocket);
    WSACleanup();
    return 0;
}
