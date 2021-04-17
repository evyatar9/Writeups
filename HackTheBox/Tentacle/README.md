# Tentacle - HackTheBox
Linux, 40 Base Points, Hard

## Machine
 
![Tentacle.JPG](images/Tentacle.JPG)

## Tentacle Solution

### User 1

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Tentacle]
└──╼ $nmap -sC -sV -oA nmap/Tentacle 10.10.10.224
# Nmap 7.80 scan initiated Tue Feb  9 20:35:52 2021 as: nmap -sC -sV -Pn -oA nmap/Tentacle 10.10.10.224
Nmap scan report for 10.10.10.224
Host is up (0.084s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE      VERSION
88/tcp   open   kerberos-sec MIT Kerberos (server time: 2021-02-09 18:40:58Z)
3128/tcp open   http-proxy   Squid http proxy 4.11
|_http-server-header: squid/4.11
|_http-title: ERROR: The requested URL could not be retrieved
9090/tcp closed zeus-admin
Service Info: Host: REALCORP.HTB

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  9 20:37:17 2021 -- 1 IP address (1 host up) scanned in 84.96 seconds
```

## Tentacle is still active machine - [Full writeup](Tentacle-Writeup.pdf) avaliable with root hash password only.
*You can get machine root hash with: ```cat /etc/shadow | grep root | cut -d ':' -f2```.*

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)