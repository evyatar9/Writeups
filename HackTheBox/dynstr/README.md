# dynstr - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏dynstr.JPG](images/dynstr.JPG)
 
## dynstr Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/dynstr]
└──╼ $ nmap -sC -sV -oA nmap/dynstr 10.10.10.244
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-21 22:06 IDT
Nmap scan report for 10.10.10.244
Host is up (0.082s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.39 seconds

```

Let's observe port 80:
![port80.JPG](images/port80.JPG)

By clicking on "Services" we can see the follow:
![services.JPG](images/services.JPG)

And on the bottom of the page we can see domain ```dyna.htb``` and username ```dns```:
![domain.JPG](images/domain.JPG)

## dynstr is still active machine - [Full writeup](dynstr-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)