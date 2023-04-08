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

    const char* dev = "enp3s0";
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev) + 1))
    {
        perror("setsockopt(...) bind failed...");
        return 2;
    }

    struct ifreq eth_req;
    strncpy(eth_req.ifr_name, dev, strlen(dev) + 1);
    if (ioctl(sockfd, SIOCGIFFLAGS, &eth_req) == -1)
    {
        perror("ioctl(..., SIOCGIFFLAGS, ...) failed.");
        return 3;
    }

    if (ioctl(sockfd, SIOCSIFFLAGS, &eth_req) == -1)
    {
        perror("ioctl(..., SIOCsIFFLAGS, ...) failed.");
        return 4;
    }

    struct sock_filter bpf_code[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 5, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 6, 0, 0x00000006 },
        { 0x15, 0, 6, 0x0000002c },
        { 0x30, 0, 0, 0x00000036 },
        { 0x15, 3, 4, 0x00000006 },
        { 0x15, 0, 3, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 1, 0x00000006 },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 }
    };

    struct sock_fprog filter;
    filter.len = sizeof(bpf_code) / sizeof(bpf_code[0]);
    filter.filter = bpf_code;

    if (setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0)
    {
        perror("socksetopt(...) attach filter failed...");
        return 5;
    }

    int recv_bytes;
    int n;
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

