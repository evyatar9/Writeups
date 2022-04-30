# OTP Vault - NahamCon CTF 2022 - [https://www.nahamcon.com/](https://www.nahamcon.com/)
Mobile, 402 Points

## Description

![‏‏info.JPG](images/info.JPG)
 
## OTP Vault Solution

Let's install the [OTPVault.apk](./OTPVault.apk) on [Genymotion Android emulator](https://www.genymotion.com/):

![emulator.JPG](images/emulator.JPG)

If we are trying to insert an invalid OTP we get the message "Invalid OTP":

![invalid.JPG](images/invalid.JPG)

By decompiling the application using [jadx](https://github.com/skylot/jadx)) we can see it's build using [ReactJS](https://reactjs.org/).

To decompile it we need to extract the ```index.android.bundle``` file from the ```apk``` file.

First let's decompile the application using [apktool](https://ibotpeaches.github.io/Apktool/):
```console
┌─[evyatar@parrot]─[/mobile/otp_vault]
└──╼ $ apktool d OTPVault.apk
I: Using Apktool 2.5.0-dirty on OTPVault.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/evyatar/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
 
```

The file locate on ```OTPVault/assets/```:
```console
┌─[evyatar@parrot]─[/mobile/otp_vault/]
└──╼ $ cp OTPVault/assets/index.android.bundle .
```

Next, Let's decompile the file ```index.android.bundle``` using [https://github.com/nomi9995/react-native-decompiler](https://github.com/nomi9995/react-native-decompiler):
```console
┌─[evyatar@parrot]─[/mobile/otp_vault/]
└──╼ $ npx react-native-decompiler -i ./index.android.bundle -o ./output
Reading file...
Parsing JS...
Finding modules...
Took 2401.436999000609ms
Pre-parsing modules...
 ████████████████████████████████████████ 100% | ETA: 0s | 430/430
Took 1312.295910000801ms
Tagging...
 ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 0% | ETA: 22s | 1/430
Took 51.46273799985647ms
Filtering out modules only depended on ignored modules...
42 remain to be decompiled
Took 151.97934100031853ms
Decompiling...
 █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 2% | ETA: 12s | 1/42
Took 274.45974899828434ms
Generating code...
 ████████████████████████████████████████ 100% | ETA: 0s | 42/42
Took 990.1041969954967ms
Saving...
 ████████████████████████████████████████ 100% | ETA: 0s | 42/42
Writing to cache...
Took 473.6084560006857ms
Done!
```

By navigating to ```output``` directory we can see the following sources:
```console
┌─[evyatar@parrot]─[/mobile/otp_vault/output]
└──╼ $ ls
0.js   11.js  13.js  15.js   397.js  400.js  402.js  404.js  406.js  408.js  410.js  412.js  414.js  416.js  418.js  420.js  422.js  424.js  426.js  428.js  7.js  null.cache
10.js  12.js  14.js  396.js  398.js  401.js  403.js  405.js  407.js  409.js  411.js  413.js  415.js  417.js  419.js  421.js  423.js  425.js  427.js  429.js  8.js
```

Let's search for "Invalid OTP":
```console
┌─[evyatar@parrot]─[/mobile/otp_vault/output]
└──╼ $ grep -r "Invalid OTP" . | less
./396.js:            output: 'Invalid OTP',
./null.cache:{"inputChecksum":["acf388bdead56a3a78306
...
```

As we can see we found it on [./396.js](./396) file.

Let's observe on the function ```O``` from this file:
```javascript
function O() {
      var n;
      module7.default(this, O);
      (n = b.call(this, ...args)).state = {
        output: 'Insert your OTP to unlock your vault',
        text: '',
      };
      n.s = 'JJ2XG5CIMFRWW2LOM4';
      n.url = 'http://congon4tor.com:7777';
      n.token = '652W8NxdsHFTorqLXgo=';

      n.getFlag = function () {
        var module7, o;
        return regeneratorRuntime.default.async(
          function (u) {
            for (;;)
              switch ((u.prev = u.next)) {
                case 0:
                  u.prev = 0;
                  module7 = {
                    headers: {
                      Authorization: 'Bearer KMGQ0YTYgIMTk5Mjc2NzZY4OMjJlNzAC0WU2DgiYzE41ZDwN',
                    },
                  };
                  u.next = 4;
                  return regeneratorRuntime.default.awrap(module400.default.get(n.url + '/flag', module7));

                case 4:
                  o = u.sent;
                  n.setState({
                    output: o.data.flag,
                  });
                  u.next = 12;
                  break;

                case 8:
                  u.prev = 8;
                  u.t0 = u.catch(0);
                  console.log(u.t0);
                  n.setState({
                    output: 'An error occurred getting the flag',
                  });

                case 12:
                case 'end':
                  return u.stop();
              }
          },
          null,
          null,
          [[0, 8]],
          Promise
        );
      };

      n.onChangeText = function (t) {
        n.setState({
          text: t,
        });
      };

      n.onPress = function () {
        var t = module397.default(n.s);
        console.log(t);
        if (t === n.state.text) n.getFlag();
        else
          n.setState({
            output: 'Invalid OTP',
          });
      };

      return n;
    }
```

As we can see, ```onPress``` event checks if the input value equals to the return value from ```module397.default(n.s)```.

We can try to understand the ```module397.default(n.s)``` function to know what is the OTP but we can get the flag by following the code on ```n.getFlag``` function.

According to the function, we can send the following HTTP POST request to [http://congon4tor.com:7777](http://congon4tor.com:7777) to get the flag:
```HTTP
GET /flag HTTP/1.1
Host: congon4tor.com
Authorization: Bearer KMGQ0YTYgIMTk5Mjc2NzZY4OMjJlNzAC0WU2DgiYzE41ZDwN


``` 

And we get the flag on the response:
```HTTP
HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Date: Sat, 30 Apr 2022 19:55:48 GMT
Content-Type: application/json
Content-Length: 50
Connection: keep-alive
Access-Control-Allow-Origin: *

{"flag":"flag{5450384e093a0444e6d3d39795dd7ddd}"}
```

And we get the flag ```flag{5450384e093a0444e6d3d39795dd7ddd}```.