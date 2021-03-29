# Spectra - HackTheBox
?, 20 Base Points, Easy

## Machine

![‏‏Spectra.JPG](images/‏‏Spectra.JPG)
  
## Spectra Solution

### User

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Spectra]
└──╼ $nmap -sC -sV -oA nmap/Spectra 10.10.10.229
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-20 20:05 IST
Nmap scan report for 10.10.10.229
Host is up (0.079s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|_  4096 52:47:de:5c:37:4f:29:0e:8e:1d:88:6e:f9:23:4d:5a (RSA)
80/tcp   open  http    nginx 1.17.4
|_http-server-header: nginx/1.17.4
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql   MySQL (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.88 seconds

```

First, Let's browse port 80:
![port80.JPG](images/port80.JPG)

```Software Issue Tracker``` pointed to [http://spectra.htb/main/index.php](http://spectra.htb/main/index.php)
And ```Test``` pointed to [http://spectra.htb/testing/index.php](http://spectra.htb/testing/index.php).

So Let's add ```spectra.htb``` to ```/etc/hosts``` file as follow:
```bash
10.10.10.229    spectra.htb
```

## Spectra is still active machine - [Full writeup](Spectra-Writeup.pdf) avaliable with root password only.

[@evyatar9](https://t.me/evyatar9)