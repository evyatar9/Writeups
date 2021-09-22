# Forge - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Forge.JPG](images/Forge.JPG)
 
## Forge Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ nmap -sV -sC -oA nmap/Forge 10.10.11.111
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-20 01:28 IDT
Nmap scan report for 10.10.11.111
Host is up (0.14s latency).
Not shown: 997 closed ports
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

By observing port 80 we get the following web page (Redirected to [http://forge.htb/](http://forge.htb/)):

![port80.JPG](images/port80.JPG)


## Forge is still active machine - [Full writeup](Forge-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)
