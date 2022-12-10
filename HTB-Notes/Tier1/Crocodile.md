```toc
```
# HTB Notes - Crocodile #

+ **Date**: 12-9-2022
+ **Author**: Noah Soqui
+ **Tags**: #Web #FTP #Anonymous 

## Intelligence Gathering ##

Scanning machine
+ `nmap -sV -sC TARGET_IP`
+ Output:
``` Shell
Nmap scan report for 10.129.4.139
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.207
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Jun 08  2021 allowed.userlist
|_-rw-r--r--    1 ftp      ftp            62 Apr 20  2021 allowed.userlist.passwd
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Smash - Bootstrap Business Template
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Unix
```

It can be seen that this machine hosts both a FTP server and a web server.

Directory brute-force the website
``` Shell
$ gobuster dir --wordlist /usr/share/wordlists/dirb/big.txt -x php --url http://10.129.4.139/
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.4.139/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/12/09 11:25:20 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/assets               (Status: 301) [Size: 313] [--> http://10.129.4.139/assets/]
/config.php           (Status: 200) [Size: 0]
/css                  (Status: 301) [Size: 310] [--> http://10.129.4.139/css/]
/dashboard            (Status: 301) [Size: 316] [--> http://10.129.4.139/dashboard/]
/fonts                (Status: 301) [Size: 312] [--> http://10.129.4.139/fonts/]
/js                   (Status: 301) [Size: 309] [--> http://10.129.4.139/js/]
/login.php            (Status: 200) [Size: 1577]
/logout.php           (Status: 302) [Size: 0] [--> login.php]
/server-status        (Status: 403) [Size: 277]
```

## Misconfiguration and Vulnerability Analysis  ##

FTP allows anonymous login.

## Exploitation ##

Login into FTP
+ `ftp 10.129.4.139`, and the username: `anonymous`
	+ Download files in there with `get` 
		+ Now have a password list and username list, including the credentials `admin:rKXM59ESxesUFHAd`

Now that we have credentials, will use the `/login.php` to get access to the server
+ The credentials `admin:rKXM59ESxesUFHAd` work 

## Post Exploitation ##

The flag is displayed after authenticating as admin

## Reporting ##

### Executive Summary ###

This box will first have us look through the open ftp service that contains a list of clear text passwords. With those password, we will have to navigate to the login of the website in order to authenticate. Looking for `php` or `js` files with a wordlist using <mark style="background: #BBFABBA6;">gobuster</mark> will quickly find a login. Then it is simple to use the credentials previously found.