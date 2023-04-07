#include "callback.hpp"

void set_icmp_hdr(char* buf)
{
    icmp_hdr = (struct icmphdr*)buf;
    icmp_hdr->type = ICMP_DEST_UNREACH;
    icmp_hdr->code = ICMP_PROT_UNREACH;
    icmp_hdr->checksum = 0x00;
}

void send_icmp(struct icmphdr* icmp_hdr, const in_addr src_addr)
{
    int sockfd{ socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    if (sockfd < 0)
    {
        std::cerr << "socket(...) failed..." << std::endl;
        close(sockfd);
        return;
    }

    struct sockaddr_in addr_info{};
    addr_info.sin_family = AF_INET;
    addr_info.sin_addr.s_addr = src_addr.s_addr;

    if (::sendto(sockfd, icmp_hdr, sizeof(*icmp_hdr), 0,
                 (struct sockaddr*)&addr_info, sizeof(addr_info)) < 0)
    {
        std::cerr << "sendto(...) failed..." << std::endl;
        close(sockfd);
        return;
    }

    close(sockfd);
}

void print_eth_hdr(const struct ether_header* eth_hdr)
{
    printf("/----------------------- Ethernet Header -----------------------\\\n");
    printf("|Src: %02x", eth_hdr->ether_shost[0]);
    for (size_t i = 1; i < 6; i++)
    {
        printf(":%02x", eth_hdr->ether_shost[i]);
    }
    printf("\n");
    printf("|Dst: %02x", eth_hdr->ether_dhost[0]);
    for (size_t i = 1; i < 6; i++)
    {
        printf(":%02x", eth_hdr->ether_dhost[i]);
    }
    printf("\n");
}

void print_ip_hdr(const struct ip* ip_hdr)
{
    printf("|------------------------- IP Header ---------------------------|\n");
    printf("|\tVersion    : %d\n", ip_hdr->ip_v);
    printf("|\tHeader Len : %d\n", ip_hdr->ip_hl);
    printf("|\tIdent      : %d\n", ip_hdr->ip_id);
    printf("|\tTTL        : %d\n", ip_hdr->ip_ttl);
    printf("|\tSrc Address: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("|\tDst Address: %s\n", inet_ntoa(ip_hdr->ip_dst));
}

void print_tcp_hdr(const struct tcphdr* tcp_hdr)
{
    printf("|------------------------- TCP Header --------------------------|\n");
    printf("|\t\tSrc Port: %d\n", ntohs(tcp_hdr->source));
    printf("|\t\tDst Port: %d\n", ntohs(tcp_hdr->dest));
}

void print_udp_hdr(const struct udphdr* udp_hdr)
{
    printf("|------------------------- UDP Header --------------------------|\n");
    printf("|\t\tSrc Port: %d\n", ntohs(udp_hdr->source));
    printf("|\t\tDst Port: %d\n", ntohs(udp_hdr->dest));
}

void print_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    printf("\\---------------------------------------------------------------/\n");

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

    if (!q.empty())
    {
        for (size_t i = 0; i < 16 - q.size(); i++)
        {
            printf("   ");
        }

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
    }
}

void callback(u_char* useless,
        const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    // header
    struct ether_header* eth_hdr{ (struct ether_header*)packet };

    // Print Ethernet Header
    print_eth_hdr(eth_hdr);

    // Get upper layer protocol type (L3 Type)
    uint16_t eth_type{ ntohs(eth_hdr->ether_type) };
    if (eth_type != ETHERTYPE_IP)
    {
        std::cout << "\t\t !! ip packet not exists." << std::endl;
        print_packet(pkthdr, packet);
        std::cout << std::endl;
        return;
    }

    // Print IP Header
    const size_t eth_hdr_len{ sizeof(struct ether_header) };  // 14 Byte
    ip_hdr = (struct ip*)(packet + eth_hdr_len);
    print_ip_hdr(ip_hdr);

    // Print TCP or UDP Header
    const u_char* payload{ packet + eth_hdr_len + (ip_hdr->ip_hl * 4) };
    switch (ip_hdr->ip_p)
    {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        {
            char buf[8]{ };
            set_icmp_hdr(buf);
            send_icmp((struct icmphdr*)buf, ip_hdr->ip_src);

            break;
        }
    //case IPPROTO_TCP:
    //    tcp_hdr = (struct tcphdr*)payload;
    //    print_tcp_hdr(tcp_hdr);
    //    break;
    //case IPPROTO_UDP:
    //    udp_hdr = (struct udphdr*)payload;
    //    print_udp_hdr(udp_hdr);
    //    break;
    //case IPPROTO_TCP:
    //    {
    //        tcp_hdr = (struct tcphdr*)payload;
    //        int sockfd{ socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) };
    //        send_icmp(sockfd, (struct iphdr*)ip_hdr, tcp_hdr);
    //        break;
    //    }
    default:
        break;
    }

    // Print packet
    //print_packet(pkthdr, packet);
    printf("\n\n");
}

