#pragma once

#include "pch.h"

#ifdef _WIN32
#pragma pack(push, 1)
struct ether_header
{
  uint8_t  ether_dhost[6];
  uint8_t  ether_shost[6];
  uint16_t ether_type;
};

struct ip
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;
    unsigned int ip_v:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;
    unsigned int ip_hl:4;
#endif
    uint8_t ip_tos;                   /* type of service */
    unsigned short ip_len;            /* total length */
    unsigned short ip_id;             /* identification */
    unsigned short ip_off;            /* fragment offset field */
#define IP_RF 0x8000                  /* reserved fragment flag */
#define IP_DF 0x4000                  /* dont fragment flag */
#define IP_MF 0x2000                  /* more fragments flag */
#define IP_OFFMASK 0x1fff             /* mask for fragmenting bits */
    uint8_t ip_ttl;                   /* time to live */
    uint8_t ip_p;                     /* protocol */
    unsigned short ip_sum;            /* checksum */
    struct in_addr ip_src, ip_dst;    /* source and dest address */
};

#define tcp_seq uint32_t
struct tcphdr
{
    union
    {
        struct
        {
            uint16_t th_sport;    /* source port */
            uint16_t th_dport;    /* destination port */
            tcp_seq th_seq;        /* sequence number */
            tcp_seq th_ack;        /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
            uint8_t th_x2:4;    /* (unused) */
            uint8_t th_off:4;    /* data offset */
#elif __BYTE_ORDER == __BIG_ENDIAN
            uint8_t th_off:4;    /* data offset */
            uint8_t th_x2:4;    /* (unused) */
#endif
            uint8_t th_flags;
# define TH_FIN     (0x01)
# define TH_SYN     (0x02)
# define TH_RST     (0x04)
# define TH_PUSH    (0x08)
# define TH_ACK     (0x10)
# define TH_URG     (0x20)
            uint16_t th_win;    /* window */
            uint16_t th_sum;    /* checksum */
            uint16_t th_urp;    /* urgent pointer */
        };
        struct
        {
            uint16_t source;
            uint16_t dest;
            uint32_t seq;
            uint32_t ack_seq;
#if __BYTE_ORDER == __LITTLE_ENDIAN
            uint16_t res1:4;
            uint16_t doff:4;
            uint16_t fin:1;
            uint16_t syn:1;
            uint16_t rst:1;
            uint16_t psh:1;
            uint16_t ack:1;
            uint16_t urg:1;
            uint16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
            uint16_t doff:4;
            uint16_t res1:4;
            uint16_t res2:2;
            uint16_t urg:1;
            uint16_t ack:1;
            uint16_t psh:1;
            uint16_t rst:1;
            uint16_t syn:1;
            uint16_t fin:1;
#endif
            uint16_t window;
            uint16_t check;
            uint16_t urg_ptr;
        };
    };
};

struct udphdr
{
    union
    {
        struct
        {
          uint16_t uh_sport;    /* source port */
          uint16_t uh_dport;    /* destination port */
          uint16_t uh_ulen;     /* udp length */
          uint16_t uh_sum;      /* udp checksum */
        };
        struct
        {
          uint16_t source;
          uint16_t dest;
          uint16_t len;
          uint16_t check;
        };
    };
};
#pragma pack(pop)

/* Ethernet protocol ID's */
#define ETHERTYPE_IP    (0x0800)

#endif

static struct ip*     ip_hdr{ };
static struct tcphdr* tcp_hdr{ };
static struct udphdr* udp_hdr{ };

void print_ip_hdr(const struct ip*);
void print_tcp_hdr(const struct tcphdr*);
void print_udp_hdr(const struct udphdr*);
void print_eth_hdr(const struct ether_header*);
void print_packet(const struct pcap_pkthdr*, const u_char*);
void callback(u_char*, const struct pcap_pkthdr*, const u_char*);

