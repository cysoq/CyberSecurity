- [Host & Network Penetration Testing: Network-Based Attacks](#host--network-penetration-testing-network-based-attacks)
  - [Introduction](#introduction)
  - [Network-Based Attacks: Overview](#network-based-attacks-overview)
    - [Network-Based Attacks - Part 1](#network-based-attacks---part-1)
    - [Network-Based Attacks - Part 2](#network-based-attacks---part-2)
  - [Network-Based Attacks: Labs](#network-based-attacks-labs)
    - [Tshark](#tshark)
    - [Filtering Basics](#filtering-basics)
    - [ARP Poisoning](#arp-poisoning)

# Host & Network Penetration Testing: Network-Based Attacks #

## Introduction ##

***Topic Overview***:
+ Network Attacks
  + Service related
  + Man in the Middle MITM
+ Packet analysis
+ Labs

Learning Objectives
+ Describe network attacks
+ Identify network traffic
+ Perform analysis on captured traffic
+ Perform Man-in-the-Middle attack

## Network-Based Attacks: Overview ##

### Network-Based Attacks - Part 1 ###

What is a Network-Based Attack?
+ Deals with networks and network services, does not deal with OS's
+ Services including 
  + ARP
  + DHCP
  + SMB
  + FTP
  + Telnet
  + SSH
+ However is big focus is Man in the Middle
  + Sitting between a conversation and listening or more 
  + To listen to traffic not meant to the machine, will need to be on a span port or do poisoning  
    + Most common is <o>ARP poisoning</o>
      + Spoofing one allows the traffic meant for another to go to us
    + Can also do <o>promiscuous</o> mode
      + Can hear traffic not intended for us 

In Wireshark, can `open`, and `save` captures 
+ Will first select an interface
+ in `View > Name Resolution` can resolve MAC, IP, or PORT addresses 
+ in `View > Name Resolution` can colorize packets and see color rules 
+ `Statistics` Will show what is used the most 
  + including hierarchy, endpoints, flow graphs, HTTP, etc
+ Line at the far left represent a single conversation 

### Network-Based Attacks - Part 2 ###

Can edit all sorts of settings in ***WireShark*** 
+ edit how the time is displayed 
+ Add Columns and align columns 
  + For example adding source port and destination port
+ Can click on a packet and dig into details
  + see the packet, dig into headers, source, destinations, flags, data 
+ On a packet, can go to streams and follow 
  + which will put on a display filter
  + Will quickly see if it is encrypted or not 
+ the filter can be edited with basic Booleans (and, or, !, etc)
  + can view field names as well 
  + `ip.addr` is one of the most useful, can specify what IPs traffic you want to see 

## Network-Based Attacks: Labs ##

### Tshark ###

Tshark is the CLI version of Wireshark 
+ Can check out the help menu with `tshark -h` and can look at that page by page with `tshark -h | more`
+ Can open a pcap with `tshark -r FILENAME.pcap` and will quickly find that this can deliver an overwhelming amount of packets
  + Can check out number of lines with `tshark -r FILENAME.pcap | wc -l`
+ Will need to script this and automate it as the data is too overwhelming 
+ Can look at Hierarchy Statistics with `tshark -r FILENAME.pcap -z io,phs -q`

### Filtering Basics ###

Can use the `-Y` to apply a filter 
+ Example: `tshark -r HTTP_traffic.pcap -Y 'ip.src==192.168.252.128 && ip.dst==52.32.74.91'`
  + gets traffic from 192.168.252.128 AND to 52.32.74.91
+ Example: `tshark -r HTTP_traffic.pcap -Y 'http.request.method==GET'`
  + gets all GET requests

Can get fields with `-Tfields`  and specify a field with `-e`
+ Example: `tshark -r HTTP_traffic.pcap -Y 'http.request.method==GET' -Tfields -e frame.time -e ip.src -e http.request.full_uri`
  + This will give a list of URIs, and could script this with a list of known bad for example
+ Example: `tshark -r HTTP_traffic.pcap -Y 'http contains password'`
  + This will do a look for the string matching for password
+ Example: `tshark -r HTTP_traffic.pcap -Y 'http.request.method==GET && http.host=www.nytimes.com' -Tfields -e ip.dst`
  + See what requests went to `nytimes` and what that ip address to it was 
+ Example: `tshark -r HTTP_traffic.pcap -Y 'ip contains amazon.in && ip.src==192.168.252.128' -Tfields -e ip.src -e http.cookie`
  + Will return the IP address and cookie that has the source of 192.168.252.128 and an ip with amazon.in

### ARP Poisoning ###

The tool <o>arpspoof</o> can be used for poisoning 

Will first:
+ `echo 1 > /proc/sys/net/ipv4/ip_forward`
  + Which will temporally turn IP forwarding on (0 for off)

Then can do the spoof via:
+ `arpspoof -i eth1 -t (Who are spoofing) -r (The IP we tell that we are the spoofed IP)`
+ Example: `arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36`

Can now look at Wireshark to see what is sent to us
+ Example: We can spoof a machine that someone might telnet to, then collect the credentials













































<style>
r { color: Red; font-weight: bold}
o { color: Orange; font-weight: bold }
g { color: LightGreen; font-weight: bold }
b { color: #04d9ff; font-weight: bold}
pu { color: #be03fc; font-weight: bold}
</style>