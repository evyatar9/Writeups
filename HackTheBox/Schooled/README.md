# Schooled - HackTheBox
FreeBSD, 30 Base Points, Medium

## Machine

![Schooled.JPG](images/Schooled.JPG)
 
## Schooled Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Schooled]
└──╼ $nmap -sC -sV -oA nmap/Schooled 10.10.10.234
Starting Nmap 7.80 ( https://nmap.org ) at 2021-04-09 00:59 IDT
Nmap scan report for 10.10.10.234
Host is up (0.092s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:69:83:78:fc:91:f8:19:c8:75:a7:1e:76:45:05:dc (RSA)
|   256 e9:b2:d2:23:9d:cf:0e:63:e0:6d:b9:b1:a6:86:93:38 (ECDSA)
|_  256 7f:51:88:f7:3c:dd:77:5e:ba:25:4d:4c:09:25:ea:1f (ED25519)
80/tcp open  http    Apache httpd 2.4.46 ((FreeBSD) PHP/7.4.15)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (FreeBSD) PHP/7.4.15
|_http-title: Schooled - A new kind of educational institute
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.94 seconds
```

Let's try to observe port 80:

![port80.JPG](images/port80.JPG)


At the bottom of the page we can see:

![details.JPG](images/details.JPG)

## Schooled is still active machine - [Full writeup](Schooled-Writeup.pdf) avaliable with root hash password only (OpenBSD from ```/etc/master.passwd```).

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)