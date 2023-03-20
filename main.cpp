#include <iostream>
#include <cstring>
#include <queue>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <pcap.h>

#include "packet_reader.hpp"

struct ip*     ip_hdr{ };
struct tcphdr* tcp_hdr{ };

void callback(u_char*, const struct pcap_pkthdr*, const u_char*);

int main(int argc, const char** argv)
{
    Packman packman{ };
    packman.create_pcapd();
    packman.set_filter_rule(argv[2]);
    packman.start_loop(atoi(argv[1]), callback, nullptr);
}

void callback(u_char* useless,
        const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    // header
    struct ether_header* p_eth_hdr{ (struct ether_header*)packet };

    // Offset payload
    packet += sizeof(struct ether_header);

    // Get upper layer protocol type (L3 Type)
    unsigned short eth_type{ ntohs(p_eth_hdr->ether_type) };
    if (eth_type != ETHERTYPE_IP)
    {
        std::cout << "ip packet not exists." << std::endl;
        std::cout << std::endl;
        return;
    }

    ip_hdr = (struct ip*)packet;
    printf("/////// IP packet\n");
    printf("|\tVersion    : %d\n", ip_hdr->ip_v);
    printf("|\tHeader Len : %d\n", ip_hdr->ip_hl);
    printf("|\tIdent      : %d\n", ip_hdr->ip_id);
    printf("|\tTTL        : %d\n", ip_hdr->ip_ttl);
    printf("|\tSrc Address: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("|\tDst Address: %s\n", inet_ntoa(ip_hdr->ip_dst));

    if (ip_hdr->ip_p == IPPROTO_TCP)
    {
        tcp_hdr = (struct tcphdr*)(packet + (ip_hdr->ip_hl * 4));
        printf("|//////// TCP packet\n");
        printf("|\t\tSrc Port: %d\n", ntohs(tcp_hdr->source));
        printf("|\t\tDst Port: %d\n", ntohs(tcp_hdr->dest));
    }

    int cnt{ 0 };
    std::queue<u_char> q{ };
    bpf_u_int32 pkthdr_len{ pkthdr->len };
    while (pkthdr_len--)
    {
        u_char ch{ *(packet++) };
        printf("%02x ", ch);
        q.push(ch);
        if ((++cnt % 16) == 0)
        {
            while (!q.empty())
            {
                u_int n{ q.front() };
                if (n > 32 && n < 126 )
                {
                    printf("%c", n);
                }
                else
                {
                    printf(".");
                }
                q.pop();
            }
            printf("\n");
        }
    }

    printf("\n\n");
}

