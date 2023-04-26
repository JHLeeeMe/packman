#include "pcap_ext.h"

int parse_pcap_file(FILE* fp, struct PFHeader* pfh)
{
    fread(pfh, sizeof(struct PFHeader), 1, fp);
    if (pfh->magic != PF_MAGIC)
    {
        return -1;
    }

    print_pcap_file(pfh);

    return 0;
}

void print_pcap_file(struct PFHeader* pfh)
{
    //FILE* output_file = fopen("test.txt", "w");
    //fwrite(pfh, sizeof(struct PFHeader), 1, output_file);
    printf("========= pcap file header info =========\n");
    printf("\t버전: %d.%d\n", pfh->major, pfh->minor);
    printf("\t최대 캡쳐 길이: %d bytes\n", pfh->max_caplen);
}

void parse_packet(FILE* fp)
{
    u_char buf[4096] = { 0 };

    struct PHeader pkthdr = { 0 };
    int pno = 0;
    while (fread(&pkthdr, sizeof(struct PHeader), 1, fp) == 1)
    {
        pno++;
        print_pkthdr(&pkthdr, pno);
        fread(buf, 1, pkthdr.caplen, fp);
        parse_ether(buf, pkthdr.caplen);
    }
}

void print_pkthdr(struct PHeader* pkthdr, int pno)
{
    printf("!!! <%4d th> frame !!!\n", pno);
    printf("Packet: %6d bytes, 캡쳐: %6d\n", pkthdr->pktlen, pkthdr->caplen);
}

void parse_ether(u_char* packet, size_t pktlen)
{
    struct ether_header* eth_hdr = (struct ether_header*)packet;
    u_char* l3_packet = packet + sizeof(struct ether_header);
    pktlen -= sizeof(struct ether_header);

    print_eth_hdr(eth_hdr);

    switch (ntohs(eth_hdr->ether_type))
    {
    case L3_IPv4:
        printf("IPv4: ok\n");
        break;
    case L3_ARP:
        printf("ARP: ok\n");
        break;
    default:
        printf("Not Support\n");
        break;
    }

    printf("\n");
}

void print_eth_hdr(struct ether_header* eth_hdr)
{
    printf("/===== ethernet header info =====\\\n");

    printf("| src: %02x", eth_hdr->ether_shost[0]);
    for (size_t i = 1; i < 6; i++)
    {
        printf(":%02x", eth_hdr->ether_shost[i]);
    }
    printf("\n");
    printf("| dst: %02x", eth_hdr->ether_dhost[0]);
    for (size_t i = 1; i < 6; i++)
    {
        printf(":%02x", eth_hdr->ether_dhost[i]);
    }
    printf("\n");

    printf("| L3 Type: %#06x\n", ntohs(eth_hdr->ether_type));
    printf("| (IPv4: 0x0800, ARP: 0x0806)\n");
    printf("\\================================/\n");
}

