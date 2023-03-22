#pragma once

#include <iostream>
#include <cstring>
#include <queue>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <pcap.h>

static struct ip*     ip_hdr{ };
static struct tcphdr* tcp_hdr{ };
static struct udphdr* udp_hdr{ };

void callback(u_char*, const struct pcap_pkthdr*, const u_char*);

