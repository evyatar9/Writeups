# Ophiuchi - HackTheBox
Linux, 30 Base Points, Medium

## Machine
![Ophiuchi.JPG](images/Ophiuchi.JPG)

## Ophiuchi Solution

### User

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Ophiuchi]
└──╼ $nmap -sC -sV -oA nmap/Ophiuchi 10.10.10.227
# Nmap 7.80 scan initiated Mon Feb 22 22:01:34 2021 as: nmap -sC -sV -oA Ophiuchi 10.10.10.227
Nmap scan report for 10.10.10.227
Host is up (0.072s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    Apache Tomcat 9.0.38
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 22 22:01:46 2021 -- 1 IP address (1 host up) scanned in 12.19 seconds
```

We can see port ```8080``` which is ```Apache Tomcat 9.0.38```.

Let's try to browse this port:

![port8080.JPG](images/port8080.JPG)


## Ophiuchi is still active machine - [Full writeup](Ophiuchi-Writeup.pdf) avaliable with root password only.
Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)