#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "../include/revPingServer.h"
#include "../include/packetParser.h"
#include "../include/probeSender.h"

uint32_t _source_ip = 0;

pcap_t* open_pcap_socket(char* device, const char* bpfstr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd;
    uint32_t  srcip, netmask;
    struct bpf_program  bpf;

    // If no network interface (device) is specfied, get the first one.
    if (!*device && !(device = pcap_lookupdev(errbuf)))
    {
        printf("pcap_lookupdev(): %s\n", errbuf);
        return NULL;
    }

    // Open the device for live capture, as opposed to reading a packet
    // capture file.
    if ((pd = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL)
    {
        printf("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }

    // Get network device source IP address and netmask.
    if (pcap_lookupnet(device, &srcip, &netmask, errbuf) < 0)
    {
        printf("pcap_lookupnet: %s\n", errbuf);
        return NULL;
    }
    _source_ip = srcip;

    // Convert the packet filter epxression into a packet
    // filter binary.
    if (pcap_compile(pd, &bpf, (char*)bpfstr, 0, netmask))
    {
        printf("pcap_compile(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    // Assign the packet filter to the given libpcap socket.
    if (pcap_setfilter(pd, &bpf) < 0)
    {
        printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
        return NULL;
    }

    return pd;
}

void capture_loop(pcap_t* pd, int packets, pcap_handler func)
{
    int linktype;

    // Determine the datalink layer type.
    if ((linktype = pcap_datalink(pd)) < 0)
    {
        printf("pcap_datalink(): %s\n", pcap_geterr(pd));
        return;
    }

    // Set the datalink layer header size.
    switch (linktype)
    {
    case DLT_NULL:
        linkhdrlen = 4;
        break;

    case DLT_EN10MB:
        linkhdrlen = 14;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;

    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }

    // Start capturing packets.
    if (pcap_loop(pd, packets, func, 0) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pd));
}

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,
                  u_char *packetptr)
{
    // Skip the datalink layer header and get the IP header fields.*-*/
	packetptr += linkhdrlen;
	check2Forward(packetptr);
}

void check2Forward(u_char *packetptr){
	struct ip *iphdr;
	struct icmphdr *icmp_hdr;
	u_char *backupPacketPtr = packetptr;
	long totalPacketSize = 0;

	// printig for debug
	pure_parse(packetptr);

	iphdr = (struct ip*) packetptr;
	// advance to get the next hdr
	packetptr += 4 * iphdr->ip_hl;

	// check the protocol
	switch (iphdr->ip_p) {
	case IPPROTO_ICMP:

		printf(" IP ID %d \n", iphdr->ip_id);
		icmp_hdr = (struct icmphdr*) packetptr;
		if (icmp_hdr->type == ICMP_TIMXCEED) {
			u_long dst_ip;
			u_short ttl;

			struct ip *iphdrP;
			struct icmphdr *icmphdrP;
			//printf("=== Probe Answer =======================================\n");
			//totalPacketSize = (packetptr - backupPacketPtr);
			//printf(" Partial Packet Size (IP1): %d bytes\n", totalPacketSize);

			//Advance to the payload
			packetptr += ICMP_LEN;
			iphdrP = (struct ip*) packetptr;
			totalPacketSize = (packetptr - backupPacketPtr);
			//printf(" Partial Packet Size (IP1+ICMP1): %d bytes\n", totalPacketSize);

			//printf(" Payload ... \n");
			// printig for debug
			//pure_parse(packetptr);

			packetptr += 4 * iphdrP->ip_hl;
			icmphdrP = (struct icmphdr*) packetptr;
			//totalPacketSize = (packetptr - backupPacketPtr);
			//printf(" Partial Packet Size (IP1+ICMP1+IP2): %d bytes\n", totalPacketSize);

			//totalPacketSize = ((packetptr + ICMP_LEN) - backupPacketPtr);
			//printf(" Packet Size (IP1+ICMP1+IP2+ICMP2): %d bytes\n", totalPacketSize);


            if ((icmphdrP->type == ICMP_ECHO) && (icmphdrP->code == ICMP_REVPING_PROBE_CODE) ) {
                pure_parse(packetptr);
                packetptr += ICMP_LEN;
                ttl = iphdrP->ip_ttl;
                printf("=== Probe Answer =======================================\n");
                printf(" Payload ttl: %d \n", ttl);
                printf(" Payload src_ip: %lu \n", iphdrP->ip_src);
                printf(" Payload dst_ip: %lu \n", iphdrP->ip_dst);
                printf("========================================================\n");


            }


		}
		else if ((icmp_hdr->type == ICMP_ECHO) && (icmp_hdr->code == ICMP_REVPING_REQUEST_CODE) ) {
			printf("=== Probe Seding  =======================================\n");
			u_long dst_ip;
			u_short ttl;

			packetptr += ICMP_LEN;
			ttl = packetptr[0];

			printf(" Payload ttl: %d \n", ttl);

			packetptr += 1;
			totalPacketSize = (packetptr - backupPacketPtr);
			printf(" Packet Size (Payload TTL): %d bytes\n", totalPacketSize);


            dst_ip = byteArray2ip (packetptr);

			packetptr += 4;
			totalPacketSize = (packetptr  - backupPacketPtr);
			printf(" Packet Size (Payload %lu -> %lu): %d bytes\n", iphdr->ip_dst.s_addr, dst_ip, totalPacketSize);

			probeSend(ICMP_REVPING_PROBE_CODE, iphdr->ip_dst.s_addr, dst_ip, ttl, NULL, 0);
			printf("========================================================\n");

		}
		break;
	}

}



void bailout(int signo)
{
    struct pcap_stat stats;

    if (pcap_stats(pd, &stats) >= 0)
    {
        printf("%d packets received\n", stats.ps_recv);
        printf("%d packets dropped\n\n", stats.ps_drop);
    }
    pcap_close(pd);
    exit(0);
}


