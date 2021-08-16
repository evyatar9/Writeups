# Writer - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Writer.JPG](images/Writer.JPG)


## Writer Solution


### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ nmap -sC -sV -oA nmap/Writer 10.10.11.101 
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-12 18:29 IDT
Nmap scan report for 10.10.11.101
Host is up (0.10s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 4m32s
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-12T15:34:54
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.76 seconds

```

Let's observe port 80:

![port80.JPG](images/port80.JPG)


## Writer is still active machine - [Full writeup](Writer-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)