#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include "./revPingRequest.h"

void usage(char *);

#define PAYLOAD_BYTES_SIZE 9

int
main(int argc, char **argv)
{
    libnet_t *l = NULL;
    u_long src_ip = 0, dst_ip = 0;
    u_int32_t end_ip = 0;
    u_long count = 1;
    int i, c;
    libnet_ptag_t t;
    char payload [PAYLOAD_BYTES_SIZE];
    u_short payload_s = PAYLOAD_BYTES_SIZE;
    int ttl = 1;
    char *device = NULL;
    char *pDst = NULL, *pSrc = "localhost\0", *pEndPoint;
    char errbuf[LIBNET_ERRBUF_SIZE];
    char label[LIBNET_LABEL_SIZE];

    while((c = getopt(argc, argv, "d:s:i:c:p:t:e:")) != EOF)
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
        case 'c':
            count = strtoul(optarg, 0, 10);
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

    /*
     *  Fill the context queue with "count" packets, each with their own
     *  context.
     */
    for (i = 0; i < count; i++)
    {
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

		payload[1] = (end_ip & 0xff000000) >> 24;

		payload[2] = (end_ip & 0xff0000) >> 16;

		payload[3] = (end_ip & 0xff00) >> 8;

		payload[4] = (end_ip & 0xff);



        t = libnet_build_icmpv4_echo(
            ICMP_ECHO,                            /* type */
            ICMP_REVPING_REQUEST_CODE,                    /* code */
            0,                                    /* checksum */
            0,          						  /* id */
            1,                                    /* sequence number */
            (uint8_t *)payload,                                 /* payload */
            PAYLOAD_BYTES_SIZE,                                    /* payload size */
            l,                                    /* libnet handle */
            0);
        if (t == -1)
        {
            fprintf(stderr, "Can't build ICMP header: %s\n",
                    libnet_geterror(l));
            goto bad;
        }

        t = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_s,   /* length */
            0,                                                  /* TOS */
            IP_REVPING_CODE,                                    /* IP ID */
            0,                                    /* IP Frag */
            DEFAULT_TTL,                                   /* TTL */
            IPPROTO_ICMP,                         /* protocol */
            0,                                    /* checksum */
            src_ip,                               /* source IP */
            dst_ip,                               /* destination IP */
            NULL,                   			  /* payload */
            0,                            		  /* payload size */
            l,                                    /* libnet handle */
            0);
        if (t == -1)
        {
            fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
            goto bad;
        }

        /* and finally, put it in the context queue */
        snprintf(label, sizeof(label)-1, "echo %d", i);
    }

        c = libnet_write(l);
        if (c == -1)
        {
            fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
            goto bad;
        }
        else
        {
            fprintf(stderr, "Wrote %d byte ICMP packet from context \"%s\"; "
                    "check the wire.\n", c, libnet_cq_getlabel(l));
        }

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
