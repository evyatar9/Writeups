# Knife - HackTheBox
Linux, 20 Base Points, Easy

## Machine

![‏‏Knife.JPG](images/Knife.JPG)
 
## Knife Solution

### User

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Knife]
└──╼ $ nmap -sC -sV -oA nmap/Knife 10.10.10.242
Starting Nmap 7.80 ( https://nmap.org ) at 2021-05-22 22:16 IDT
Nmap scan report for 10.10.10.242
Host is up (0.097s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.06 seconds
```

Let's try to observe port 80:

![port80.JPG](images/port80.JPG)

## Knife is still active machine - [Full writeup](Knife-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)