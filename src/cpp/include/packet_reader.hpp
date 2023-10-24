#pragma once

#include "pch.h"

#define PROMISCUOUS    (1)
#define NONPROMISCUOUS (0)

class Packman
{
public:
    Packman();
    Packman(const Packman&) = delete;
    Packman(Packman&&) = delete;
    ~Packman();
public:
    void create_pcapd(int buf_size = BUFSIZ,
            int promisc = PROMISCUOUS, int time_out = -1);
    void set_filter_rule(const char* rule = "") const;
    void start_loop(size_t packet_cnt,
            pcap_handler callback, u_char* user_data = nullptr) const;
private:
    void init();
    void find_alldevs();
    void print_alldevs() const;
    void set_ifname();
    void set_addr();
    void print_addr() const;
private:
    char        errbuf[PCAP_ERRBUF_SIZE]{ };
    pcap_if_t*  alldevs{ };
    const char* dev{ };
    bpf_u_int32 netp{ };
    bpf_u_int32 maskp{ };

    pcap_t* pcapd{ };
};

