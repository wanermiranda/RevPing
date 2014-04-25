
#include "../include/netUtils.h"

void ip2ByteArray (u_long ip, char *bytes){

		bytes[0] = (ip & 0xff000000) >> 24;

		bytes[1] = (ip & 0xff0000) >> 16;

		bytes[2] = (ip & 0xff00) >> 8;

		bytes[3] = (ip & 0xff);
}

u_long byteArray2ip (unsigned char bytes[5]){

		return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | (bytes[3]) ;
}
