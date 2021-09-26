# Pikaboo - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Pikaboo.JPG](images/Pikaboo.JPG)
 
## Pikaboo Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Pikaboo]
└──╼ $ nmap -sV -sC -oA nmap/Pikaboo 10.10.10.249
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-25 00:21 IDT
Nmap scan report for 10.10.10.249
Host is up (0.084s latency).
Not shown: 961 closed ports, 36 filtered ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 17:e1:13:fe:66:6d:26:b6:90:68:d0:30:54:2e:e2:9f (RSA)
|   256 92:86:54:f7:cc:5a:1a:15:fe:c6:09:cc:e5:7c:0d:c3 (ECDSA)
|_  256 f4:cd:6f:3b:19:9c:cf:33:c6:6d:a5:13:6a:61:01:42 (ED25519)
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Pikaboo
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page (Redirected to [http://forge.htb/](http://forge.htb/)):

![port80.JPG](images/port80.JPG)

Where [pokatdex](http://10.10.10.249/pokatdex.php) page contains:

![pokatdex.JPG](images/pokatdex.JPG)

## Pikaboo is still active machine - [Full writeup](Pikaboo-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)