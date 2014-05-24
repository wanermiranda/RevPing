#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include "../include/revPingServer.h"
#include "../include/probeSender.h"
#include "../include/revPingRequest.h"
#include "../include/netUtils.h"
#include "../include/packetParser.h"
#define PAYLOAD_BYTES_SIZE 9
#define TIMEOUT 1.5


static clock_t probeStarted; 

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,
    u_char *packetptr)
{
  // Skip the datalink layer header and get the IP header fields.*-*/
  packetptr += linkhdrlen;
  check2Forward(packetptr, packethdr->len);
}

void check2Forward(u_char *packetptr, uint32_t len){
  struct ip *iphdr;
  struct icmphdr *icmp_hdr;
  u_char *backupPacketPtr = packetptr;
  long totalPacketSize = 0;
  double elapsed = 0; 
  // printig for debug
  //pure_parse(packetptr, len);

  iphdr = (struct ip*) packetptr;
  // advance to get the next hdr
  packetptr += 4 * iphdr->ip_hl;

  // check the protocol
  switch (iphdr->ip_p) {
    case IPPROTO_ICMP:

      icmp_hdr = (struct icmphdr*) packetptr;
      if ((icmp_hdr->type == 0) && (icmp_hdr->code == ICMP_REVPING_REQUEST_CODE) && (len > 110) ) {
        //printf("=== Request Answer  =======================================\n");
        packetptr += ICMP_LEN; 		
        //pure_parse(packetptr); 

        struct ip *iphdrP1; 
        struct icmphdr *icmphdrP1;
        char hopIP[256]; 
        uint32_t size; 
        int seq; 

        iphdrP1 = (struct ip*) packetptr;
        packetptr += 4 * iphdrP1->ip_hl;
        icmphdrP1 = (struct icmphdr*) packetptr;

        strcpy(hopIP, inet_ntoa(iphdrP1->ip_src)); 

        packetptr += ICMP_LEN;

        struct ip *iphdrP2;
        struct icmphdr *icmphdrP2;

        iphdrP2 = (struct ip*) packetptr;
        packetptr += 4 * iphdrP2->ip_hl;
        icmphdrP2 = (struct icmphdr*) packetptr;

        memcpy(&seq, (u_char*) icmphdrP2 + 6, 2);

        printf("Hop %d -> %s \n", ntohs(seq), hopIP); 
        packetptr += ICMP_LEN;
        size = packetptr - backupPacketPtr;
        printf("Size %lu actual size %lu ", len, size);
        if (len > 188) {
          icmp_ext(backupPacketPtr + 188); 
        }
        //printf("===========================================================\n");
        pcap_breakloop(pd); 

      }
      break;
  }

  elapsed = ((double)(clock() - probeStarted) / CLOCKS_PER_SEC); 
  //printf ("elapsed : %4.2f,  %lu - %lu \/ %lu \n", elapsed, clock(), probeStarted, CLOCKS_PER_SEC); 
  if ( elapsed > TIMEOUT ) {
    printf(" Timed out \n"); 
    pcap_breakloop(pd); 
  }
}


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
  int maxTTL = 10;
  char *device = NULL;
  char *pDst = NULL, *pSrc = "localhost\0", *pEndPoint;
  char errbuf[LIBNET_ERRBUF_SIZE];
  char label[LIBNET_LABEL_SIZE];

  char interface[256] = "", bpfstr[256] = "";
  int packets = 0 ;


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
        maxTTL = strtoul(optarg, 0, 10);
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

  ip2ByteArray(end_ip, (payload+1));
  int ttl; 
  for (ttl = maxTTL; ttl <= maxTTL; ttl++) 
    if ((pd = open_pcap_socket(interface, bpfstr)))
    {
      payload[0] = ttl;
      printf("Send request with maxttl : %lu - %d\n", byteArray2ip(payload+1), payload[0]);
      probeStarted = clock(); 
      probeSend(ICMP_ECHO, ICMP_REVPING_REQUEST_CODE, src_ip, dst_ip, DEFAULT_TTL, payload, PAYLOAD_BYTES_SIZE, 0);
      signal(SIGINT, bailout);
      signal(SIGTERM, bailout);
      signal(SIGQUIT, bailout);
      capture_loop(pd, packets, (pcap_handler)parse_packet);
      /*bailout(0);*/
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
      " [-t maxTTL = 10]\n ", name);
}

/* EOF */
