# Spider - HackTheBox - Writeup
Linux, 40 Base Points, Hard

## Machine

![‏‏Spider.JPG](images/Spider.JPG)


## Spider Solution


### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ nmap -p- -sC -sV -oA nmap/Spider 10.10.10.243
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-10 03:21 IDT
Nmap scan report for 10.10.10.243
Host is up (0.15s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
|_  256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://spider.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following (We need to add ```spider.htb``` to ```/etc/hosts``` before):

![port80.JPG](images/port80.JPG)


## Spider is still active machine - [Full writeup](Spider-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)
