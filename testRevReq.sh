#!/bin/sh
gcc revPingRequest.c -lnet -o revPingRequest
./revPingRequest -s 192.168.25.49 -d 192.168.25.40 -e www.google.com -t 1 
