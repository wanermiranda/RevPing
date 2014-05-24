#include <libnet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "../include/revPingServer.h"
#include "../include/probeSender.h"
#include "../include/netUtils.h"
#include "../include/packetParser.h"

#define MAX_SLOTS  256

u_char ip_matrix[MAX_SLOTS][4];
u_short ip_slots = 0; 

u_short get_slot()
{
  ip_slots ++; 
  if (ip_slots > 255) ip_slots = 0; 
  return ip_slots; 
}

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,
		u_char *packetptr)
{
	// Skip the datalink layer header and get the IP header fields.*-*/
        //printf("Caplen %d, len %d \n", packethdr->caplen, packethdr->len);
	packetptr += linkhdrlen;
	check2Forward(packetptr, packethdr->len);
}

void check2Forward(u_char *packetptr, uint32_t len){
	struct ip *iphdr;
	struct icmphdr *icmp_hdr;
	u_char *backupPacketPtr = packetptr;
	long totalPacketSize = 0;

	// printig for debug
	pure_parse(packetptr,len);

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
                      u_long dst_ip;
                      u_short probe_id = ntohs(iphdrP->ip_id); 
                      //memcpy(&probe_id, (u_char *) icmphdrP + 4, 2);
                     // pure_parse(packetptr,len);
                      packetptr += ICMP_LEN;
                      ttl = iphdrP->ip_ttl;
                      printf("=== Probe Answer =======================================\n");
                      printf(" ttl: %d \n", ttl);
                      printf(" src_ip: %lu \n", iphdr->ip_src);
                      printf(" dst_ip: %lu \n", iphdr->ip_dst);
                      printf("========================================================\n");
                      printf(" Payload ttl: %d \n", ttl);
                      printf(" Payload src_ip: %lu \n", iphdrP->ip_src);
                      printf(" Payload dst_ip: %lu \n", iphdrP->ip_dst);
                      printf("========================================================\n");
                    
                      printf("Probe id %d received \n", probe_id);   
                      dst_ip = byteArray2ip (ip_matrix[probe_id]);

                      printf("dest ip %d \n", dst_ip); 
                      packetptr += IP_SIZE; 
                      totalPacketSize = (packetptr  - backupPacketPtr);
                      probeSend(0, ICMP_REVPING_REQUEST_CODE, iphdr->ip_dst.s_addr, dst_ip, DEFAULT_TTL, backupPacketPtr, len, 0);	


                    }


                  }
                  else if ((icmp_hdr->type == ICMP_ECHO) && (icmp_hdr->code == ICMP_REVPING_REQUEST_CODE) ) {
                    printf("=== Probe Sending  =======================================\n");
                    u_long dst_ip;
                    u_char payload[IP_SIZE]; 
                    u_short ttl, id; 

                    packetptr += ICMP_LEN;
                    ttl = packetptr[0];
                    printf(" ttl: %d \n", ttl);
                    printf(" src_ip: %lu \n", iphdr->ip_src);
                    printf(" dst_ip: %lu \n", iphdr->ip_dst);
                    printf("========================================================\n");

                    printf(" Payload ttl: %d \n", ttl);

                    packetptr += 1;
                    totalPacketSize = (packetptr - backupPacketPtr);
                    printf(" Packet Size (Payload TTL): %d bytes\n", totalPacketSize);

                    id = get_slot(); 
                    dst_ip = byteArray2ip (packetptr);
                    printf("Probe id %d sent\n", id); 
                    ip2ByteArray(iphdr->ip_src.s_addr, ip_matrix[id]);
                    //ip2ByteArray(iphdr->ip_src.s_addr, payload);

                    packetptr += 4;
                    totalPacketSize = (packetptr  - backupPacketPtr);
                    printf(" Packet Size (Payload %lu -> %lu): %d bytes\n", iphdr->ip_dst.s_addr, dst_ip, totalPacketSize);

                    probeSend(ICMP_ECHO, ICMP_REVPING_PROBE_CODE, iphdr->ip_dst.s_addr, dst_ip, ttl, NULL, 0, id);
                    printf("========================================================\n");

                  }
                  else if ((icmp_hdr->type == ICMP_ECHO) && (icmp_hdr->code == ICMP_REVPING_RESULTS_CODE) ) {
                    printf("=== Client Request Answer  =======================================\n");
                    packetptr += ICMP_LEN; 		
                    pure_parse(packetptr,len); 

                    struct ip *iphdrP1; 
                    struct icmphdr *icmphdrP1;

                    iphdrP1 = (struct ip*) packetptr;
                    packetptr += 4 * iphdrP1->ip_hl;
                    icmphdrP1 = (struct icmphdr*) packetptr;

                    packetptr += ICMP_LEN;

                    struct ip *iphdrP2;
                    struct icmphdr *icmphdrP2;

                    //pure_parse(packetptr);

                    printf("===========================================================\n");

                  }
                  break;
        }

}

int main(int argc, char **argv)
{
  char interface[256] = "", bpfstr[256] = "";
  int packets = 0, c, i;

  // Get the command line options, if any
  while ((c = getopt (argc, argv, "hi:n:")) != -1)
  {
    switch (c)
    {
      case 'h':
        printf("usage: %s [-h] [-i ] [-n ] []\n", argv[0]);
        exit(0);
        break;
      case 'i':
        strcpy(interface, optarg);
        break;
      case 'n':
        packets = atoi(optarg);
        break;
    }
  }

  // Get the packet capture filter expression, if any.
  for (i = optind; i < argc; i++)
  {
    strcat(bpfstr, argv[i]);
    strcat(bpfstr, " ");
  }

  // Open libpcap, set the program termination signals then start
  // processing packets.
  if ((pd = open_pcap_socket(interface, bpfstr)))
  {
    signal(SIGINT, bailout);
    signal(SIGTERM, bailout);
    signal(SIGQUIT, bailout);
    capture_loop(pd, packets, (pcap_handler)parse_packet);
    bailout(0);
  }
  exit(0);
}
