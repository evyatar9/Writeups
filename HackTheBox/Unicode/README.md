# Unicode - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Unicode.JPG](images/Unicode.JPG)


## Unicode Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Unicode]
└──╼ $ nmap -sV -sC -oA nmap/Unicode 10.10.11.126
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-22 03:24 IST
Nmap scan report for 10.10.11.126
Host is up (0.28s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hackmedia
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

## Unicode is still an active machine - [Full writeup](Unicode-Writeup.pdf) available with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9#5800](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)