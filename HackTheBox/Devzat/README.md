# Devzat - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Devzat.JPG](images/Devzat.JPG)


## Devzat Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ nmap -sV -sC -oA nmap/Devzat 10.10.11.118
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-29 01:45 IDT
Nmap scan report for 10.10.11.118
Host is up (0.27s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=10/29%Time=617B2843%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page (Redirected to [http://devzat.htb/](http://devzat.htb/)):

![port80.JPG](images/port80.JPG)

## Devzat is still active machine - [Full writeup](Devzat-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)
