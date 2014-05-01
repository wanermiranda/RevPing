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

void icmp_ext(u_char *packetptr)
{
  uint32_t mpls_exp; 
  unsigned long mpls_label; 
  // skipping the header and going to the mpls tags
  mpls_label = ((unsigned long)packetptr[4]<<12) +
    ((unsigned int)packetptr[5]<<4) + ((packetptr[6]>>4) & 0xff); 
  mpls_exp = (packetptr[6] >> 1) & 0x7;

  printf("\n Label %lu, exp %d \n", mpls_label, mpls_exp);

}

void pure_parse(u_char *packetptr, uint32_t len) {
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
                        printf("Size: %d \n", len);
			// if there is a time exceed message, just read the payload.
			if (icmphdr->type == ICMP_TIMXCEED) {
				pure_parse(packetptr + ICMP_LEN,len);

			}
                        printf("------------ End Parsing --------------------------------------=\n");
			break;
	}
}
