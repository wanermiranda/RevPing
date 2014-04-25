#ifndef NETUTILS_H_
#define NETUTILS_H_
#include <libnet.h>

void ip2ByteArray (u_long ip, char *bytes);

u_long byteArray2ip (unsigned char bytes[5]);

#endif // NETUTILS_H_
