#include <iostream>
#include <cstring>
#include <netinet/in.h>

#include <pcap.h>

void print_alldevs(pcap_if_t* alldevs);
void get_ifname(const char** buf, pcap_if_t* alldevs);

int main()
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
    if (net == nullptr)
    {
        std::cerr << "inet_ntoa(addr) failed..." << std::endl;
        return 3;
    }
    std::cout << "ip: " << net << std::endl;

    addr.s_addr = maskp;
    char* mask{ inet_ntoa(addr) };
    if (mask == nullptr)
    {
        std::cerr << "inet_ntoa(addr) failed..." << std::endl;
        return 4;
    }
    std::cout << "mask: " << mask << std::endl;

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

