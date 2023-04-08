#pragma once

#include <iostream>
#include <cstring>
#include <queue>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <pcap.h>

static struct ip*     ip_hdr{ };
static struct tcphdr* tcp_hdr{ };
static struct udphdr* udp_hdr{ };

void print_ip_hdr(const struct ip*);
void print_tcp_hdr(const struct tcphdr*);
void print_udp_hdr(const struct udphdr*);
void print_eth_hdr(const struct ether_header*);
void print_packet(const struct pcap_pkthdr*, const u_char*);
void callback(u_char*, const struct pcap_pkthdr*, const u_char*);

