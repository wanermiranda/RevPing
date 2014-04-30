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
#include "../include/packetParser.h"

void pure_parse(u_char *packetptr) {
	struct ip* iphdr;
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	char iphdrInfo[256], srcip[256], dstip[256];
	unsigned short id, seq;


	iphdr = (struct ip*) packetptr;
	strcpy(srcip, inet_ntoa(iphdr->ip_src));
	strcpy(dstip, inet_ntoa(iphdr->ip_dst));


	// Advance to the transport layer header then parse and display
	packetptr += 4 * iphdr->ip_hl;
	switch (iphdr->ip_p) {
		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*) packetptr;
                        printf("------------ Parsing Packet ------------------------------------=\n"); 

			printf("ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d \n",
					ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl, 4 * iphdr->ip_hl,
					ntohs(iphdr->ip_len));


			printf("ICMP %s -> %s\n", srcip, dstip);
			memcpy(&id, (u_char*) icmphdr + 4, 2);
			memcpy(&seq, (u_char*) icmphdr + 6, 2);
			printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type,
					icmphdr->code, ntohs(id), ntohs(seq));

			// if there is a time exceed message, just read the payload.
			if (icmphdr->type == ICMP_TIMXCEED) {
				pure_parse(packetptr + ICMP_LEN);

			}
                        printf("------------ End Parsing --------------------------------------=\n");
			break;
	}
}
