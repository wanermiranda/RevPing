/*
 * revPingServer.h
 *
 *  Created on: Apr 22, 2014
 *      Author: root
 */

#ifndef REVPINGSERVER_H_
#define REVPINGSERVER_H_


pcap_t* pd;
int linkhdrlen;

void check2Forward(u_char *packetptr, uint32_t len);

pcap_t* open_pcap_socket(char* device, const char* bpfstr);

void capture_loop(pcap_t* pd, int packets, pcap_handler func);

void parse_packet(u_char *user, struct pcap_pkthdr *packethdr,u_char *packetptr);

void bailout(int signo);

#endif /* REVPINGSERVER_H_ */
