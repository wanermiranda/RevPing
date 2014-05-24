#include <libnet.h>
#include "../include/probeSender.h"

int probeSend(uint32_t icmp_type, uint32_t icmp_code, u_long srcIP, u_long dstIP, int ttl, char *payload,
    u_short payloadSize, u_short id) {

  libnet_ptag_t libnetpTag;
  libnet_t *libnetHnd = NULL;
  int queueResult;
  char errbuf[LIBNET_ERRBUF_SIZE];
  char *device = NULL;

  libnetHnd = libnet_init(
      LIBNET_RAW4, /* injection type */
      device, /* network interface */
      errbuf); /* errbuf */

  if (libnetHnd == NULL) {
    fprintf(stderr, "libnet_init() failed: %s", errbuf);
    exit(EXIT_FAILURE);
  }

  libnetpTag = libnet_build_icmpv4_echo(
      icmp_type, /* type */
      icmp_code, /* code */
      0, /* checksum */
      id, /* id */
      ttl, /* sequence number */
      (uint8_t *) payload, /* payload */
      payloadSize, /* payload size */
      libnetHnd, /* libnet handle */
      0);
  if (libnetpTag == -1) {
    fprintf(stderr, "Can't build ICMP header: %s\n",
        libnet_geterror(libnetHnd));
    goto bad;
  }

  libnetpTag = libnet_build_ipv4(
      LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payloadSize, /* length */
      0, /* TOS */
      id, /* IP ID */
      0, /* IP Frag */
      ttl, /* TTL */
      IPPROTO_ICMP, /* protocol */
      0, /* checksum */
      srcIP, /* source IP */
      dstIP, /* destination IP */
      NULL, /* payload */
      0, /* payload size */
      libnetHnd, /* libnet handle */
      0);
  if (libnetpTag == -1) {
    fprintf(stderr, "Can't build IP header: %s\n",
        libnet_geterror(libnetHnd));
    goto bad;
  }

  queueResult = libnet_write(libnetHnd);

  if (queueResult == -1) {
    fprintf(stderr, "Write error: %s\n", libnet_geterror(libnetHnd));
    goto bad;
  } else {
    /*fprintf(stderr, "Wrote %d byte ICMP packet from context \"%s\"; "
        "check the wire.\n", queueResult,
        libnet_cq_getlabel(libnetHnd));*/
  }

  return (EXIT_SUCCESS);

  // exception flow
bad: libnet_destroy(libnetHnd);
     return (EXIT_FAILURE);

}
