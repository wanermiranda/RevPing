/*
 * packetParser.h

 *
 *  Created on: Apr 21, 2014
 *      Author: Waner
 */

#ifndef PACKET_PARSER_H_
#define PACKET_PARSER_H_

#define IP_LEN sizeof(struct iphdr)
#define ICMP_LEN sizeof(struct icmphdr)

void pure_parse(u_char *packetptr);


#endif /* PACKET_PARSER_H_ */
