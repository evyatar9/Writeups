# Shibboleth - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Shibboleth.JPG](images/Shibboleth.JPG)
 

## Shibboleth Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Shibboleth]
└──╼ $ nmap -sV -sC -oA nmap/Shibboleth 10.10.11.124
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-21 00:33 IST
Nmap scan report for 10.10.11.124
Host is up (0.11s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 
```

By observing port 80 we get the following web page [http://shibboleth.htb/](http://shibboleth.htb/):

![port80.JPG](images/port80.JPG)


## Shibboleth is still active machine - [Full writeup](Shibboleth-Writeup.pdf) available with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)
