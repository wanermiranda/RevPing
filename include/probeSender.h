#ifndef PROBESENDER_H_
#define PROBESENDER_H_

#define ICMP_REVPING_CODE 0x42
#define IP_REVPING_CODE 0X45
#define ICMP_REVPING_PROBE_CODE 0X46
#define ICMP_REVPING_REQUEST_CODE 0X47
#define ICMP_REVPING_RESULTS_CODE 0X48
#define DEFAULT_TTL 64

int probeSend(u_int32_t icmp_code, u_long srcIP, u_long dstIP, int ttl, u_char *payload,
		u_short payloadSize);

#endif /* PROBESENDER_H_ */
