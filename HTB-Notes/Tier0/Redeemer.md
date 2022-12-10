```toc
```
# HTB Notes - Redeemer #

+ **Date**: 12-2-2022
+ **Author**: Noah Soqui
+ **Tags**: #Redis #Anonymous 

## Intelligence Gathering ##

Scanning machine
+ `sudo nmap -sV -sC -O TARGET_IP`
+ Output:
``` Shell
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7
```

## Misconfiguration and Vulnerability Analysis  ##

Can connect to the Redis service using redis-cli without credentials, a Null session vulnerability. In the you do require authentication, it would display `-NOAUTH Authentication required.` when the `info` command is ran.

## Exploitation ##

Connect to the Redis service
+ `redis-cli -h 10.129.77.129`
+ One authenticated, can use `info` to enumerate information about the Redis service
	+ can quickly see the redis version this way
+ Can also use `info keyspace` to see how many keys there is 
+ `KEYS *` to list all the keys 

## Post Exploitation ##

Now that we see the key `flag` exists, will use the following to show the flag:
+ `GET flag`

## Reporting ##

### Executive Summary ###

Redis is an in-memory database, meaning it uses lots of RAM to quickly have information available quickly, NoSQL based. Though it allows anonymous access, allowing for quick access without credentials.
