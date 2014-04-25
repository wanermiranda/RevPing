#!/bin/sh
make client && sudo ./revPingRequest -s 192.168.25.49 -d 192.168.25.40 -e www.google.com -t 1 
