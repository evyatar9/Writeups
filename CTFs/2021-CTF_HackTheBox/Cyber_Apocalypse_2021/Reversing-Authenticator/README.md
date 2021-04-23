# CTF HackTheBox 2021 Cyber Apocalypse 2021 - Authenticator

Category: Reversing, Points: 300

![info.JPG](images/info.JPG)

Attached file: [authenticator](authenticator)

# Authenticator Solution

Let's run the attached binary:
```console
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/reversing/authenticator]
└──╼ $ ./authenticator 

Authentication System 👽

Please enter your credentials to continue.

Alien ID: 1111
Access Denied!
```

We can see the program check the user input and print message "Access Denied".

Let's try to observe the main function using Ghidra:
```c

undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  long in_FS_OFFSET;
  char local_58 [32];
  char local_38 [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  printstr(&DAT_00100bc3,0);
  printstr("Please enter your credentials to continue.\n\n",0);
  printstr("Alien ID: ",0);
  fgets(local_58,0x20,stdin);
  iVar1 = strcmp(local_58,"11337\n");
  if (iVar1 == 0) {
    printstr("Pin: ",0);
    fgets(local_38,0x20,stdin);
    uVar2 = checkpin(local_38);
    if ((int)uVar2 == 0) {
      printstr("Access Granted! Submit pin in the flag format: CHTB{fl4g_h3r3}\n",0);
    }
    else {
      printstr("Access Denied!\n",1);
    }
  }
  else {
    printstr("Access Denied!\n",1);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So first, we can see the ```strcmp``` with our input ```local_58```:
```c
iVar1 = strcmp(local_58,"11337\n");
```

So if "Alien ID" equals to ```11337``` we can pass the first check.

Next, We can see the program ask for ```Pin``` then the program call to ```checkpin``` function with our input ```local_38```, If we enter incorrect pin we get the message "Access Denied!":
```c
printstr("Pin: ",0);
    fgets(local_38,0x20,stdin);
    uVar2 = checkpin(local_38);
    if ((int)uVar2 == 0) {
      printstr("Access Granted! Submit pin in the flag format: CHTB{fl4g_h3r3}\n",0);
    }
    else {
      printstr("Access Denied!\n",1);
    }
``` 

Let's observe on ```checkpin``` function:
```c

undefined8 checkpin(char *param_1)

{
  size_t sVar1;
  int local_24;
  
  local_24 = 0;
  while( true ) {
    sVar1 = strlen(param_1);
    if (sVar1 - 1 <= (ulong)(long)local_24) {
      return 0;
    }
    if ((byte)("}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"[local_24] ^ 9U) != param_1[local_24])
    break;
    local_24 = local_24 + 1;
  }
  return 1;
}
```

So we can see the following ```if``` statment:
```c
if ((byte)("}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"[local_24] ^ 9U) != param_1[local_24])
```

So It's make XOR with 9 for each character on the string ```"}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"``` and check if it's equals to our input, So actuaclly the flag in XOR with 9 with the string above.

Let's write python code (using pwntools) to solve it:
```python
from pwn import *

def get_decrypt_flag():
        encrypted_flag="}a:Vh|}a:g}8j=}89gV<p<}:dV8<Vg9}V<9V<:j|{:"
        xor_value=0x9
        decrypted_flag=[chr(ord(c)^xor_value) for c in encrypted_flag]
        return "".join(decrypted_flag)

alien_id="11337"

p = process("./authenticator")
print(p.recvuntil(':').decode("utf-8")) #Receive untill ':' before Alien ID:
print(alien_id)
p.sendline(alien_id)

print(p.recvuntil(':').decode("utf-8")) #Receive untill ':' before Pin:
decrypted_flag=get_decrypt_flag()
p.sendline(get_decrypt_flag())

print(get_decrypt_flag())
print(p.recvuntil('}').decode("utf-8")) #Receive untill '}' which is the last char of flag format
```

Run it:
```console
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/reversing/authenticator]
└──╼ $ python authenticator.py
[+] Starting local process './authenticator': pid 835735

Authentication System 👽

Please enter your credentials to continue.

Alien ID:
11337
 Pin:
th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3
 Access Granted! Submit pin in the flag format: CHTB{fl4g_h3r3}
```

And the flag is: ```CHTB{th3_auth3nt1c4t10n_5y5t3m_15_n0t_50_53cur3}```.