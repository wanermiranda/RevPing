#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <pcap.h>

#include "../include/revPingServer.h"

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
