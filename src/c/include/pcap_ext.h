#pragma once

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct PFHeader
{
    u_int32_t magic;
    u_short   major;
    u_short   minor;
    u_int     gmt_to_local;
    u_int     timestamp;
    u_int     max_caplen;
    uint      linktype;
};

struct PHeader
{
    u_int time;
    u_int utime;
    u_int caplen;
    u_int pktlen;
};

#define LT_ETHER (0x01)
#define PF_MAGIC (0xA1B2C3D4)

int parse_pcap_file(FILE* fp, struct PFHeader* pfh);
void print_pcap_file(struct PFHeader* pfh);

void parse_ether(FILE* fp);
void print_pkthdr(struct PHeader* pkthdr, int pno);
