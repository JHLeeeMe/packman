#pragma once

#include <iostream>
#include <cstring>
#include <queue>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#include <pcap.h>

static struct ip*     ip_hdr{ };
static struct tcphdr* tcp_hdr{ };

void print_eth_hdr(const struct ether_header* eth_hdr);

void print_ip_hdr(const struct ip* ip_hdr);

void print_tcp_hdr(const struct tcphdr* tcp_hdr);

void print_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet);

void callback(u_char*, const struct pcap_pkthdr*, const u_char*);
