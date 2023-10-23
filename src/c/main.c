//*

#include "pcap_ext.h"


#define BUF_SIZE (4096)

int main(int argc, char** argv)
{
    int sockfd;
    char buf[BUF_SIZE] = { 0 };

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket(...) failed...");
        return 1;
    }

    struct ifaddrs* ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs(...) failed...");
        return 1;
    }

    const char* dev = NULL;
    int family = 0;
    char host[NI_MAXHOST] = { 0, };
    struct ifaddrs* ifaddr_tmp = ifaddr;
    while (1)
    {
        if (ifaddr_tmp == NULL)
        {
            break;
        }

        family = ifaddr_tmp->ifa_addr->sa_family;
        if (family != AF_INET)
        {
            ifaddr_tmp = ifaddr_tmp->ifa_next;
            continue;
        }

        struct sockaddr_in* addr_in = (struct sockaddr_in*)ifaddr_tmp->ifa_addr;
        inet_ntop(family, &(addr_in->sin_addr), host, sizeof(host));
        printf("%s\tAddress: <%s>\n", ifaddr_tmp->ifa_name, host);
        
        if (strncmp(ifaddr_tmp->ifa_name, "en", 2) == 0 ||
            strncmp(ifaddr_tmp->ifa_name, "eth", 3) == 0)
        {
            dev = ifaddr_tmp->ifa_name;
        }

        ifaddr_tmp = ifaddr_tmp->ifa_next;
    }
    freeifaddrs(ifaddr);

    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev) + 1))
    {
        perror("setsockopt(...) bind failed...");
        return 2;
    }

    struct ifreq eth_req = { 0, };
    strncpy(eth_req.ifr_name, dev, strlen(dev) + 1);
    if (ioctl(sockfd, SIOCGIFFLAGS, &eth_req) == -1)
    {
        perror("ioctl(..., SIOCGIFFLAGS, ...) failed.");
        return 3;
    }

    eth_req.ifr_flags |= IFF_PROMISC;
    if (ioctl(sockfd, SIOCSIFFLAGS, &eth_req) == -1)
    {
        perror("ioctl(..., SIOCsIFFLAGS, ...) failed.");
        return 4;
    }

    // TCP
    struct sock_filter bpf_code[] = {
        {0x28, 0, 0, 0x0000000c},
        {0x15, 0, 5, 0x000086dd},
        {0x30, 0, 0, 0x00000014},
        {0x15, 6, 0, 0x00000006},
        {0x15, 0, 6, 0x0000002c},
        {0x30, 0, 0, 0x00000036},
        {0x15, 3, 4, 0x00000006},
        {0x15, 0, 3, 0x00000800},
        {0x30, 0, 0, 0x00000017},
        {0x15, 0, 1, 0x00000006},
        {0x6, 0, 0, 0x00040000},
        {0x6, 0, 0, 0x00000000}
    };

    struct sock_fprog filter;
    filter.len = sizeof(bpf_code) / sizeof(bpf_code[0]);
    filter.filter = bpf_code;

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
    {
        perror("socksetopt(...) attach filter failed...");
        return 5;
    }

    int recv_bytes = 0;
    int n = 0;
    while (1)
    {
        while(1)
        {
            n = recvfrom(sockfd, buf, BUF_SIZE, 0, NULL, NULL);
            if (n < BUF_SIZE)
            {
                recv_bytes += n;
                break;
            }
            else if (n < 1)
            {
                close(sockfd);
                return 7;
            }
        }

        if (recv_bytes < 42)
        {
            printf("%d\n", recv_bytes);
            perror("recvfrom(...): ");
            printf("Incomplete packet (errno is %d)\n", errno);
            close(sockfd);
            return 7;
        }

        struct ether_header* eth_hdr = (struct ether_header*)buf;

        printf("Src: %02x", eth_hdr->ether_shost[0]);
        for (size_t i = 1; i < 6; i++)
        {
            printf(":%02x", eth_hdr->ether_shost[i]);
        }
        printf("\n");

        printf("Dst: %02x", eth_hdr->ether_dhost[0]);
        for (size_t i = 1; i < 6; i++)
        {
            printf(":%02x", eth_hdr->ether_dhost[i]);
        }
        printf("\n");

        struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));

        struct in_addr ip_addr;
        ip_addr.s_addr = ip_hdr->saddr;
        printf("Src: %s\n", inet_ntoa(ip_addr));
        ip_addr.s_addr = ip_hdr->daddr;
        printf("Dst: %s\n", inet_ntoa(ip_addr));
    }

    return 0;
}

/*/

#include <stdio.h>

#include "pcap_ext.h"

int main()
{
    char fname[256 + 1] = { 0 };
    printf("분석할 pcap 파일명: ");
    scanf("%s", fname);

    FILE* fp = NULL;
    if ((fp = fopen(fname, "rb")) == 0)
    {
        perror("file open failed...");
        fclose(fp);
        return 1;
    }

    struct PFHeader pfh = { 0 };
    if (parse_pcap_file(fp, &pfh) < 0)
    {
        printf("pcap file이 아닙니다.\n");
        fclose(fp);
        return 2;
    }

    switch (pfh.linktype)
    {
    case LT_ETHER:
        parse_packet(fp);
        break;
    default:
        printf("Not Support\n");
        break;
    }

    fclose(fp);

    return 0;
}
//*/

