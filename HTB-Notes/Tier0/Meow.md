```toc
```
# HTB Notes - Meow #

+ **Date**: 11-29-2022
+ **Author**: Noah Soqui
+ **Tags**: #Telnet

## Intelligence Gathering ##

Test machine connection:
+ `ping TARGET_IP`
	+ Will get echo requests if assessable

Scanning port 23 on the target
+ `nmap -sV -sC -p 23 TARGET_IP` 
+ Output:
``` Shell
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.82 seconds
```


## Misconfiguration and Vulnerability Analysis  ##

Username **root** on telnet service has **no password requirement** 

## Exploitation ##

+ This is a telnet misconfiguration, rather than an exploit
+ `telnet TARGET_IP` 
	+ And then user `root` and entering passed the password 

## Post Exploitation ##

Get the flag now that initial access is made 
+ `cat flag.txt` 

## Reporting ##

### Executive Summary ###

This is a simple starter box. An initial scan shows telnet, which is already a insecure protocol. Then trying a simple common username: `root` allows access without a password. Now have legitimate authentication, and can `cat` the flag.
