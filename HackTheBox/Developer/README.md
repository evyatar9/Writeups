# Developer - HackTheBox - Writeup
Linux, 40 Base Points, Hard

![info.JPG](images/info.JPG)

## Machine

![‏‏Developer.JPG](images/Developer.JPG)

## Developer Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Developer]
└──╼ $ nmap -sV -sC -oA nmap/Developer 10.10.11.103
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-09 22:00 IST
Nmap scan report for 10.10.11.103
Host is up (0.27s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://developer.htb/
Service Info: Host: developer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 on [http://developer.htb/](http://developer.htb/) we get the following web page:

![port80.JPG](images/port80.JPG)


## Developer is still active machine - [Full writeup](Developer-Writeup.pdf) available with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)