#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include "../include/probeSender.h"
#include "../include/revPingRequest.h"
#include "../include/netUtils.h"

#define PAYLOAD_BYTES_SIZE 9

void usage(char *);

int
main(int argc, char **argv)
{
    libnet_t *l = NULL;
    u_long src_ip = 0, dst_ip = 0;
    u_int32_t end_ip = 0;
    int i, c;
    libnet_ptag_t t;
    char payload [PAYLOAD_BYTES_SIZE];
    u_short payload_s = PAYLOAD_BYTES_SIZE;
    int ttl = 1;
    char *device = NULL;
    char *pDst = NULL, *pSrc = "localhost\0", *pEndPoint;
    char errbuf[LIBNET_ERRBUF_SIZE];
    char label[LIBNET_LABEL_SIZE];

    while((c = getopt(argc, argv, "d:s:t:e:")) != EOF)
    {
        switch (c)
        {
        case 'd':
            pDst = optarg;
            break;
        case 's':
            pSrc = optarg;
            break;
        case 'i':
            device = optarg;
            break;
        case 't':
            ttl = strtoul(optarg, 0, 10);
            break;
        case 'e':
            pEndPoint = optarg;
            break;
        }
    }


    if (!pSrc || !pDst || !pEndPoint)
    {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    l = libnet_init(
            LIBNET_RAW4,                  /* injection type */
            device,                       /* network interface */
            errbuf);                      /* errbuf */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    if (!dst_ip && (dst_ip = libnet_name2addr4(l, pDst,
                             LIBNET_RESOLVE)) == -1)
    {
        fprintf(stderr, "Bad destination IP address: %s\n", pDst);
        exit(1);
    }

    if (!src_ip && (src_ip = libnet_name2addr4(l, pSrc,
                             LIBNET_RESOLVE)) == -1)
    {
        fprintf(stderr, "Bad source IP address: %s\n", pSrc);
        exit(1);
    }
    fprintf(stderr, "Src %d and dest %lu\n", src_ip, dst_ip);

    if (!end_ip && (end_ip = libnet_name2addr4(l, pEndPoint,
                             LIBNET_RESOLVE)) == -1)
    {
        fprintf(stderr, "Bad source IP address: %s\n", pEndPoint);
        exit(1);
    }

    printf("End Point : %lu \n", end_ip);

    payload[0] = ttl;

    ip2ByteArray(end_ip, (payload+1));

    printf("End Point Debug: %lu \n", byteArray2ip((payload+1)));

    probeSend(ICMP_REVPING_REQUEST_CODE, src_ip, dst_ip, DEFAULT_TTL, payload, PAYLOAD_BYTES_SIZE);


    return (EXIT_SUCCESS);
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
}

void
usage(char *name)
{
    fprintf(stderr, "usage: %s [-s source_ip] -d destination_ip -e endpoint_ip"
            " [-i iface] [-c count = 10] [-t ttl = 10]\n ", name);
}

/* EOF */
