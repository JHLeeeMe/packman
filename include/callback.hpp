#pragma once

#include <iostream>
#include <cstring>
#include <queue>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>

#include <pcap.h>

static struct ip*      ip_hdr{ };
static struct tcphdr*  tcp_hdr{ };
static struct udphdr*  udp_hdr{ };
static struct icmphdr* icmp_hdr{ };

void set_icmp_hdr(char* buf);
void send_icmp(struct icmphdr* icmp_hdr, const in_addr src_addr);
void callback(u_char*, const struct pcap_pkthdr*, const u_char*);

