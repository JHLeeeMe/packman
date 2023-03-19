#include <iostream>
#include <cstring>
#include <queue>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <pcap.h>

#define PROMISCUOUS (1)
#define NONPROMISCUOUS (0)

struct ip*     ip_hdr{ };
struct tcphdr* tcp_hdr{ };

void print_alldevs(pcap_if_t* alldevs);
void get_ifname(const char** buf, pcap_if_t* alldevs);
void callback(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet);

int main(int argc, const char** argv)
{
    pcap_if_t* alldevs{ };
    char       errbuf[PCAP_ERRBUF_SIZE]{ };

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "pcap_findallalldevs(...) failed..." << std::endl
                  << "\tError Msg: " << errbuf
        << std::endl;
        return 1;
    }

    print_alldevs(alldevs);

    const char* dev{ };
    get_ifname(&dev, alldevs);

    bpf_u_int32 netp{ };
    bpf_u_int32 maskp{ };
    if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
    {
        std::cerr << "pcap_lookupnet(...) failed..." << std::endl
                  << "\tError Msg: " << errbuf
        << std::endl;
        return 2;
    }
    std::cout << "dev: " << dev << std::endl;

    // Print ip & mask
    struct in_addr addr{ };

    addr.s_addr = netp;
    char* net{ inet_ntoa(addr) };
    if (!net)
    {
        std::cerr << "inet_ntoa(addr) failed..." << std::endl;
        return 3;
    }
    std::cout << "ip: " << net << std::endl;

    addr.s_addr = maskp;
    char* mask{ inet_ntoa(addr) };
    if (!mask)
    {
        std::cerr << "inet_ntoa(addr) failed..." << std::endl;
        return 4;
    }
    std::cout << "mask: " << mask << std::endl;

    // Create packet capture descriptor
    pcap_t* pcapd{ pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf)};
    if (!pcapd)
    {
        std::cerr << "pcap_open_live(...) failed..." << std::endl
                  << "\t Error Msg: " << errbuf
        << std::endl;
        return 5;
    }

    // Define compile option
    struct bpf_program fp{ };
    if (pcap_compile(pcapd, &fp, argv[2], 0, netp) == -1)
    {
        std::cerr << "pcap_compile(...) failed..." << std::endl;
        return 6;
    }

    // Set filter with compile option
    if (pcap_setfilter(pcapd, &fp) == -1)
    {
        std::cerr << "pcap_setfilter(...) failed..." << std::endl;
        return 7;
    }

    // Capture packet
    pcap_loop(pcapd, atoi(argv[1]), callback, nullptr);

    return 0;
}

void print_alldevs(pcap_if_t* alldevs)
{
    std::cout << "------ alldevs -------" << std::endl;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        std::cout << d->name << std::endl;
    }
    std::cout << "----------------------" << std::endl;
}

void get_ifname(const char** buf, pcap_if_t* alldevs)
{
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        if (strncmp(d->name, "en", 2) == 0 ||
            strncmp(d->name, "eth", 3) == 0)
        {
            *buf = d->name;
        }
    }
}

void callback(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    // header
    struct ether_header* p_eth_hdr{ (struct ether_header*)packet };

    // Offset payload
    packet += sizeof(struct ether_header);

    // Get upper layer protocol type
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

