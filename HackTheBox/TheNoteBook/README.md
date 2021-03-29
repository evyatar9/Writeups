# TheNoteBook - HackTheBox
Linux, 30 Base Points, Medium

## Machine

![TheNoteBook.JPG](images/TheNoteBook.JPG)
 
## The Note Book Solution

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

## TheNoteBook is still active machine - [Full writeup](TheNoteBook-Writeup.pdf) avaliable with root password only.


[@evyatar9](https://t.me/evyatar9)