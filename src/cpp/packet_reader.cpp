#include "packet_reader.hpp"

Packman::Packman()
{
    init();
}

Packman::~Packman()
{
    ::pcap_freealldevs(alldevs);
    ::pcap_close(pcapd);
}

void Packman::create_pcapd(int buf_size, int promisc, int time_out)
{
    pcapd = ::pcap_open_live(dev, buf_size, promisc, time_out, errbuf);
    if (!pcapd)
    {
        std::cerr << "pcap_open_live(...) failed..." << std::endl
                  << "\t Error Msg: " << errbuf
        << std::endl;
        exit(-1);
    }
}

void Packman::set_filter_rule(const char* rule) const
{
    struct bpf_program fp{ };

    if (::pcap_compile(pcapd, &fp, rule, 0, netp) == -1)
    {
        std::cerr << "pcap_compile(...) failed..." << std::endl;
        exit(-1);
    }

    if (pcap_setfilter(pcapd, &fp) == -1)
    {
        std::cerr << "pcap_setfilter(...) failed..." << std::endl;
        exit(-1);
    }
}

void Packman::start_loop(size_t packet_cnt,
        pcap_handler callback, u_char* user_data) const
{
    ::pcap_loop(pcapd, packet_cnt, callback, user_data);
}

void Packman::init()
{
    find_alldevs();
    print_alldevs();

    set_ifname();
    set_addr();
    print_addr();
}

void Packman::find_alldevs()
{
    if (::pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        std::cerr << "pcap_findallalldevs(...) failed..." << std::endl
                  << "\tError Msg: " << errbuf
        << std::endl;
        exit(1);
    }
}

void Packman::print_alldevs() const
{
    std::cout << "/--- alldevs ---" << std::endl;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        std::cout << "| " << d->name << std::endl;
    }
    std::cout << "\\---------------" << std::endl << std::endl;
}

void Packman::set_ifname()
{
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
    {
        if (strncmp(d->name, "en", 2) == 0 ||
            strncmp(d->name, "eth", 3) == 0)
        {
            dev = d->name;
        }
    }

    if (!dev)
    {
        std::cerr << "`en~` or `eth~` not found." << std::endl;
        exit(2);
    }
}

void Packman::set_addr()
{
    if (::pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1)
    {
        std::cerr << "pcap_lookupnet(...) failed..." << std::endl
                  << "\tError Msg: " << errbuf
        << std::endl;
        exit(3);
    }
}

void Packman::print_addr() const
{
    struct in_addr addr{ };
    const char* net{ };

    addr.s_addr = netp;
    net = inet_ntoa(addr);
    if (!net)
    {
        std::cerr << "inet_ntoa(addr) failed..." << std::endl;
        exit(4);
    }
    std::cout << "IP: " << net << std::endl;

    addr.s_addr = maskp;
    net = inet_ntoa(addr);
    if (!net)
    {
        std::cerr << "inet_ntoa(addr) failed..." << std::endl;
        exit(4);
    }
    std::cout << "MASK: " << net << std::endl;

    std::cout << std::endl;
}

