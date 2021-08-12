# Seal - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Seal.JPG](images/Seal.JPG)


## Seal Solution


### User 

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Seal]
└──╼ $ nmap -p- -sC -sV -oA nmap/Seal 10.10.10.250

Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-11 00:17 IDT
Nmap scan report for 10.10.10.250
Host is up (0.21s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
443/tcp  open  ssl/http   nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Seal Market
| ssl-cert: Subject: commonName=seal.htb/organizationName=Seal Pvt Ltd/stateOrProvinceName=London/countryName=UK
| Not valid before: 2021-05-05T10:24:03
|_Not valid after:  2022-05-05T10:24:03
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
8080/tcp open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Tue, 10 Aug 2021 21:22:17 GMT
|     Set-Cookie: JSESSIONID=node0187gqx3v1pvm8xiosluw7o11e2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   GetRequest: 
|     HTTP/1.1 401 Unauthorized
|     Date: Tue, 10 Aug 2021 21:22:14 GMT
|     Set-Cookie: JSESSIONID=node01oy35tej6qj3t1n2y3ayg88pw70.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 0
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 10 Aug 2021 21:22:15 GMT
|     Set-Cookie: JSESSIONID=node0y0mbz5ecx71i1d3782u17f20l1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RPCCheck: 
|     HTTP/1.1 400 Illegal character OTEXT=0x80
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 71
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character OTEXT=0x80</pre>
|   RTSPRequest: 
|     HTTP/1.1 505 Unknown Version
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|     <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
|   Socks4: 
|     HTTP/1.1 400 Illegal character CNTL=0x4
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|     <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x4</pre>
|   Socks5: 
|     HTTP/1.1 400 Illegal character CNTL=0x5
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 69
|     Connection: close
|_    <h1>Bad Message 400</h1><pre>reason: Illegal character CNTL=0x5</pre>
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.80%I=7%D=8/11%Time=6112ECF7%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,F5,"HTTP/1\.1\x20401\x20Unauthorized\r\nDate:\x20Tue,\x2010\x2
SF:0Aug\x202021\x2021:22:14\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01oy35
SF:tej6qj3t1n2y3ayg88pw70\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Th
SF:u,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/htm
SF:l;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,108,"HT
SF:TP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2010\x20Aug\x202021\x2021:22:15\
SF:x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0y0mbz5ecx71i1d3782u17f20l1\.no
SF:de0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2
SF:000:00:00\x20GMT\r\nContent-Type:\x20text/html;charset=utf-8\r\nAllow:\
SF:x20GET,HEAD,POST,OPTIONS\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,AD,"HTTP/1\.1\x20505\x20Unknown\x20Version\r\nContent-Type:\x20text/h
SF:tml;charset=iso-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close
SF:\r\n\r\n<h1>Bad\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Versio
SF:n</pre>")%r(FourOhFourRequest,F4,"HTTP/1\.1\x20401\x20Unauthorized\r\nD
SF:ate:\x20Tue,\x2010\x20Aug\x202021\x2021:22:17\x20GMT\r\nSet-Cookie:\x20
SF:JSESSIONID=node0187gqx3v1pvm8xiosluw7o11e2\.node0;\x20Path=/;\x20HttpOn
SF:ly\r\nExpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nConte
SF:nt-Type:\x20text/html;charset=utf-8\r\nContent-Length:\x200\r\n\r\n")%r
SF:(Socks5,C3,"HTTP/1\.1\x20400\x20Illegal\x20character\x20CNTL=0x5\r\nCon
SF:tent-Type:\x20text/html;charset=iso-8859-1\r\nContent-Length:\x2069\r\n
SF:Connection:\x20close\r\n\r\n<h1>Bad\x20Message\x20400</h1><pre>reason:\
SF:x20Illegal\x20character\x20CNTL=0x5</pre>")%r(Socks4,C3,"HTTP/1\.1\x204
SF:00\x20Illegal\x20character\x20CNTL=0x4\r\nContent-Type:\x20text/html;ch
SF:arset=iso-8859-1\r\nContent-Length:\x2069\r\nConnection:\x20close\r\n\r
SF:\n<h1>Bad\x20Message\x20400</h1><pre>reason:\x20Illegal\x20character\x2
SF:0CNTL=0x4</pre>")%r(RPCCheck,C7,"HTTP/1\.1\x20400\x20Illegal\x20charact
SF:er\x20OTEXT=0x80\r\nContent-Type:\x20text/html;charset=iso-8859-1\r\nCo
SF:ntent-Length:\x2071\r\nConnection:\x20close\r\n\r\n<h1>Bad\x20Message\x
SF:20400</h1><pre>reason:\x20Illegal\x20character\x20OTEXT=0x80</pre>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.82 seconds

```

Port 8080 contains:

![port8080.JPG](images/port8080.JPG)

And port 443:

![port443.JPG](images/port443.JPG)


## Seal is still active machine - [Full writeup](Seal-Writeup.pdf) avaliable with root hash password only.

Telegram: [@evyatar9](https://t.me/evyatar9)

Discord: [evyatar9](https://discordapp.com/users/812805349815091251)

![pwn.JPG](images/pwn.JPG)