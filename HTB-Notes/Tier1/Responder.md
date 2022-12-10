```toc
```
# HTB Notes - Responder #

+ **Date**: 12-9-2022
+ **Author**: Noah Soqui
+ **Tags**: #WinRM #Web

## Intelligence Gathering ##

Scanning machine
+ `nmap -sV -sC TARGET_IP`
+ Output:
``` Shell
Nmap scan report for 10.129.155.146
Host is up (0.042s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

Redirects to `http://unika.htb/`

## Misconfiguration and Vulnerability Analysis  ##

## Exploitation ##

## Post Exploitation ##

## Reporting ##

### Executive Summary ###

