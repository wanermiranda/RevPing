#!/bin/sh
gcc revPingRequest.c -lnet -o revPingRequest
./revPingRequest -s 192.168.25.40 -d www.google.com -t 1 
