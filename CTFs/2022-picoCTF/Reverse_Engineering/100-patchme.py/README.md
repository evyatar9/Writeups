# patchme.py - picoCTF 2022 - CMU Cybersecurity Competition
Reverse Engineering, 100 Points

## Description

![‏‏info.JPG](images/info.JPG)
 
## patchme.py Solution

By observing the [attached code](./patchme.flag.py) we can see the following ```if``` statement on ```level_1_pw_check``` function:
```python
...
if( user_pw == "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
...
```

By changing the ```if``` from ```==``` to ```!=``` we can insert any password we want to get the flag:
```python
if( user_pw != "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
```

Run it:
```console
┌─[evyatar@parrot]─[/pictoctf2022/reverse_engineering/patchme.py]
└──╼ $ python3 patchme.flag.py
Please enter correct password for flag: evyatar9
Welcome back... your flag, user:
picoCTF{p47ch1ng_l1f3_h4ck_4d5af99c}
```

And we get the flag ```picoCTF{p47ch1ng_l1f3_h4ck_4d5af99c}```.