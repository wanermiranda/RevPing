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


