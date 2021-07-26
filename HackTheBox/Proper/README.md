# Proper - HackTheBox - Writeup
Windows, 40 Base Points, Hard

## Machine

![‏‏Proper.JPG](images/Proper.JPG)

## Proper Solution


### User

Let's try with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Proper]
└──╼ $ nmap -sC -sV -oA nmap/Proper 10.10.10.231
Starting Nmap 7.80 ( https://nmap.org ) at 2021-07-11 00:14 IDT
Nmap scan report for 10.10.10.231
Host is up (0.092s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: OS Tidy Inc.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.22 seconds
```

Let's observe port 80:
![port80.JPG](images/port80.JPG)


## Proper is still active machine - [Full writeup](Proper-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)