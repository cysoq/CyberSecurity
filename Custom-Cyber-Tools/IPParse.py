#!/usr/bin/python3

# For getting a list of IPS:

import re
import ipaddress
import sys 

# Collect file as a string
try:
    file = open(sys.argv[1], "r")
except:
    print("No such file")
    exit()
txt = file.read()
file.close()

# Get and sort IPs
IPList = list(set(re.findall(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',txt)))

IPList = sorted([ipaddress.ip_address(addr) for addr in IPList])

# Print them 
for IP in IPList:
    print(IP)