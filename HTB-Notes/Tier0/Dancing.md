```toc
```
# HTB Notes - Dancing #

+ **Date**: 11-30-2022
+ **Author**: Noah Soqui
+ **Tags**: #SMB #Anonymous 

## Intelligence Gathering ##

Scanning machine
+ `sudo nmap -sV -sC -O TARGET_IP`
+ Output:
``` Shell
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
```

Assuming port 445 is actually SMB, Will enumerate shares with a Null session 
+ `smbclient -L 10.129.34.222 -N`
+ Output:
``` Shell
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WorkShares      Disk      

```
+ `IPC$` will a null session indicates a possible connection 
	+ The dollar sign and the end of the top three mean <mark style="background: #ADCCFFA6;">default share</mark> indicate it is for administrators 
	+ Certain versions of Windows allowed one to authenticate and mount the `IPC$` share without providing a username or password (Null Session)
## Misconfiguration and Vulnerability Analysis  ##

SMB is setup for connection and enumeration with a null session (no password), can use `smbclient` to enumerate and login.

## Exploitation ##

Connect to the share `WorkShares`
+ `smbclient //10.129.34.222/WorkShares -N`

## Post Exploitation ##

+ Download the flag after navigating to it with `get` 

## Reporting ##

### Executive Summary ###

This box shows the danger of a null session SMB service. Without authentication being setup, the contents of a share can be retrieved will no password.