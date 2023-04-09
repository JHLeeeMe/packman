#include "pcap_ext.h"

int parse_pcap_file(FILE* fp, struct PFHeader* pfh)
{
    fread(pfh, sizeof(struct PFHeader), 1, fp);
    if (pfh->magic != PF_MAGIC)
    {
        return 0;
    }

    print_pcap_file(pfh);

    return 1;
}

void print_pcap_file(struct PFHeader* pfh)
{
    printf("========= pcap file header info =========\n");
    printf("\t버전: %d.%d\n", pfh->major, pfh->minor);
    printf("\t최대 캡쳐 길이: %d bytes\n", pfh->max_caplen);
}

void parse_ether(FILE* fp)
{
    char buf[4096] = { 0 };

    struct PHeader pkthdr = { 0 };
    int pno = 0;
    while (fread(&pkthdr, sizeof(struct PHeader), 1, fp) == 1)
    {
        pno++;
        print_pkthdr(&pkthdr, pno);
        fread(buf, 1, pkthdr.caplen, fp);
    }
}

void print_pkthdr(struct PHeader* pkthdr, int pno)
{
    printf("!!! <%4d th> frame !!!\n", pno);
    printf("Packet: %6d bytes, 캡쳐: %6d\n", pkthdr->pktlen, pkthdr->caplen);
}

