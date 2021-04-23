# CTF HackTheBox 2021 Cyber Apocalypse 2021 - passphrase

Category: Reversing, Points: 300

![info.JPG](images/info.JPG)

Attached file: [passphrase](passphrase)

# passphrase Solution

Let's run the attached binary:

```console
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/reversing/passphrase]
└──╼ $ ./passphrase 

Halt! ⛔
You do not look familiar..
Tell me the secret passphrase: 111111

Intruder alert! 🚨

```

Let's observe the main function using Ghidra:
```c

undefined8 main(void)

{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char local_58;
  undefined local_57;
  undefined local_56;
  undefined local_55;
  undefined local_54;
  undefined local_53;
  undefined local_52;
  undefined local_51;
  undefined local_50;
  undefined local_4f;
  undefined local_4e;
  undefined local_4d;
  undefined local_4c;
  undefined local_4b;
  undefined local_4a;
  undefined local_49;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  char acStack57 [41];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  local_58 = '3';
  local_57 = 0x78;
  local_56 = 0x74;
  local_55 = 0x72;
  local_54 = 0x34;
  local_53 = 0x74;
  local_52 = 0x33;
  local_51 = 0x72;
  local_50 = 0x52;
  local_4f = 0x33;
  printstr(&DAT_00100bc8);
  printstr("\nYou do not look familiar..");
  printstr("\nTell me the secret passphrase: ");
  local_4e = 0x73;
  local_4d = 0x74;
  local_4c = 0x52;
  local_4b = 0x31;
  local_4a = 0x34;
  local_49 = 0x4c;
  local_48 = 0x35;
  local_47 = 0x5f;
  local_46 = 0x56;
  fgets(acStack57 + 1,0x28,stdin);
  local_45 = 0x53;
  local_44 = 0x5f;
  local_43 = 0x68;
  local_42 = 0x75;
  sVar2 = strlen(acStack57 + 1);
  acStack57[sVar2] = '\0';
  local_41 = 0x6d;
  local_40 = 0x34;
  local_3f = 0x6e;
  local_3e = 0x35;
  local_3d = 0;
  iVar1 = strcmp(&local_58,acStack57 + 1);
  if (iVar1 == 0) {
    puts(&DAT_00100c2e);
    printf("\x1b[32m");
    printf(
           "\nSorry for suspecting you, please transfer this important message to the chief:CHTB{%s}\n\n"
           ,acStack57 + 1);
  }
  else {
    printf("\x1b[31m");
    printstr(&DAT_00100c17);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```

So with ```fgets(acStack57 + 1,0x28,stdin);``` our input stored in ```acStack57 + 1```, Next it will compare to ```local_58`` using ```iVar1 = strcmp(&local_58,acStack57 + 1);``` and if we have the flag the program print the message "Sorry for suspecting you, please transfer this important message to the chief:CHTB{%s}".

So let's run the program using ```gdb```, We need to break before ```strcmp``` function called, then we need to look at ```strcmp``` arguments which stored in registers ```rdi``` , ```rsi```.

``` asm
┌─[evyatar@parrot]─[/ctf_htb/cyber_apocalypse/reversing/passphrase]
└──╼ $ gdb passphrase
└──╼ $gdb passphrase
GNU gdb (Debian 9.2-1) 9.2
gef➤  disassemble main
Dump of assembler code for function main:
   0x00000000000009c6 <+0>:	push   rbp
   0x00000000000009c7 <+1>:	mov    rbp,rsp
   0x00000000000009ca <+4>:	sub    rsp,0x50
   0x00000000000009ce <+8>:	mov    rax,QWORD PTR fs:0x28
   0x00000000000009d7 <+17>:	mov    QWORD PTR [rbp-0x8],rax
   0x00000000000009db <+21>:	xor    eax,eax
   0x00000000000009dd <+23>:	mov    rax,QWORD PTR [rip+0x20162c]        # 0x202010 <stdout@@GLIBC_2.2.5>
   0x00000000000009e4 <+30>:	mov    esi,0x0
   0x00000000000009e9 <+35>:	mov    rdi,rax
   0x00000000000009ec <+38>:	call   0x7f0 <setbuf@plt>
   0x00000000000009f1 <+43>:	mov    BYTE PTR [rbp-0x50],0x33
   0x00000000000009f5 <+47>:	mov    BYTE PTR [rbp-0x4f],0x78
   0x00000000000009f9 <+51>:	mov    BYTE PTR [rbp-0x4e],0x74
   0x00000000000009fd <+55>:	mov    BYTE PTR [rbp-0x4d],0x72
   0x0000000000000a01 <+59>:	mov    BYTE PTR [rbp-0x4c],0x34
   0x0000000000000a05 <+63>:	mov    BYTE PTR [rbp-0x4b],0x74
   0x0000000000000a09 <+67>:	mov    BYTE PTR [rbp-0x4a],0x33
   0x0000000000000a0d <+71>:	mov    BYTE PTR [rbp-0x49],0x72
   0x0000000000000a11 <+75>:	mov    BYTE PTR [rbp-0x48],0x52
   0x0000000000000a15 <+79>:	mov    BYTE PTR [rbp-0x47],0x33
   0x0000000000000a19 <+83>:	lea    rdi,[rip+0x1a8]        # 0xbc8
   0x0000000000000a20 <+90>:	call   0x96a <printstr>
   0x0000000000000a25 <+95>:	lea    rdi,[rip+0x1a7]        # 0xbd3
   0x0000000000000a2c <+102>:	call   0x96a <printstr>
   0x0000000000000a31 <+107>:	lea    rdi,[rip+0x1b8]        # 0xbf0
   0x0000000000000a38 <+114>:	call   0x96a <printstr>
   0x0000000000000a3d <+119>:	mov    BYTE PTR [rbp-0x46],0x73
   0x0000000000000a41 <+123>:	mov    BYTE PTR [rbp-0x45],0x74
   0x0000000000000a45 <+127>:	mov    BYTE PTR [rbp-0x44],0x52
   0x0000000000000a49 <+131>:	mov    BYTE PTR [rbp-0x43],0x31
   0x0000000000000a4d <+135>:	mov    BYTE PTR [rbp-0x42],0x34
   0x0000000000000a51 <+139>:	mov    BYTE PTR [rbp-0x41],0x4c
   0x0000000000000a55 <+143>:	mov    BYTE PTR [rbp-0x40],0x35
   0x0000000000000a59 <+147>:	mov    BYTE PTR [rbp-0x3f],0x5f
   0x0000000000000a5d <+151>:	mov    BYTE PTR [rbp-0x3e],0x56
   0x0000000000000a61 <+155>:	mov    rdx,QWORD PTR [rip+0x2015b8]        # 0x202020 <stdin@@GLIBC_2.2.5>
   0x0000000000000a68 <+162>:	lea    rax,[rbp-0x30]
   0x0000000000000a6c <+166>:	mov    esi,0x28
   0x0000000000000a71 <+171>:	mov    rdi,rax
   0x0000000000000a74 <+174>:	call   0x810 <fgets@plt>
   0x0000000000000a79 <+179>:	mov    BYTE PTR [rbp-0x3d],0x53
   0x0000000000000a7d <+183>:	mov    BYTE PTR [rbp-0x3c],0x5f
   0x0000000000000a81 <+187>:	mov    BYTE PTR [rbp-0x3b],0x68
   0x0000000000000a85 <+191>:	mov    BYTE PTR [rbp-0x3a],0x75
   0x0000000000000a89 <+195>:	lea    rax,[rbp-0x30]
   0x0000000000000a8d <+199>:	mov    rdi,rax
   0x0000000000000a90 <+202>:	call   0x7d0 <strlen@plt>
   0x0000000000000a95 <+207>:	sub    rax,0x1
   0x0000000000000a99 <+211>:	mov    BYTE PTR [rbp+rax*1-0x30],0x0
   0x0000000000000a9e <+216>:	mov    BYTE PTR [rbp-0x39],0x6d
   0x0000000000000aa2 <+220>:	mov    BYTE PTR [rbp-0x38],0x34
   0x0000000000000aa6 <+224>:	mov    BYTE PTR [rbp-0x37],0x6e
   0x0000000000000aaa <+228>:	mov    BYTE PTR [rbp-0x36],0x35
   0x0000000000000aae <+232>:	mov    BYTE PTR [rbp-0x35],0x0
   0x0000000000000ab2 <+236>:	lea    rdx,[rbp-0x30]
   0x0000000000000ab6 <+240>:	lea    rax,[rbp-0x50]
   0x0000000000000aba <+244>:	mov    rsi,rdx
   0x0000000000000abd <+247>:	mov    rdi,rax
   0x0000000000000ac0 <+250>:	call   0x820 <strcmp@plt>
   0x0000000000000ac5 <+255>:	test   eax,eax
   0x0000000000000ac7 <+257>:	je     0xaed <main+295>
   0x0000000000000ac9 <+259>:	lea    rdi,[rip+0x141]        # 0xc11
   0x0000000000000ad0 <+266>:	mov    eax,0x0
   0x0000000000000ad5 <+271>:	call   0x800 <printf@plt>
   0x0000000000000ada <+276>:	lea    rdi,[rip+0x136]        # 0xc17
   0x0000000000000ae1 <+283>:	call   0x96a <printstr>
   0x0000000000000ae6 <+288>:	mov    eax,0x0
   0x0000000000000aeb <+293>:	jmp    0xb27 <main+353>
   0x0000000000000aed <+295>:	lea    rdi,[rip+0x13a]        # 0xc2e
   0x0000000000000af4 <+302>:	call   0x7c0 <puts@plt>
   0x0000000000000af9 <+307>:	lea    rdi,[rip+0x132]        # 0xc32
   0x0000000000000b00 <+314>:	mov    eax,0x0
   0x0000000000000b05 <+319>:	call   0x800 <printf@plt>
   0x0000000000000b0a <+324>:	lea    rax,[rbp-0x30]
   0x0000000000000b0e <+328>:	mov    rsi,rax
   0x0000000000000b11 <+331>:	lea    rdi,[rip+0x120]        # 0xc38
   0x0000000000000b18 <+338>:	mov    eax,0x0
   0x0000000000000b1d <+343>:	call   0x800 <printf@plt>
   0x0000000000000b22 <+348>:	mov    eax,0x0
   0x0000000000000b27 <+353>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x0000000000000b2b <+357>:	xor    rcx,QWORD PTR fs:0x28
   0x0000000000000b34 <+366>:	je     0xb3b <main+373>
   0x0000000000000b36 <+368>:	call   0x7e0 <__stack_chk_fail@plt>
   0x0000000000000b3b <+373>:	leave  
   0x0000000000000b3c <+374>:	ret    
End of assembler dump.
```

We can see the ```strcmp``` function called on ```   0x0000000000000ac0 <+250>:	call   0x820 <strcmp@plt>```, Let's add break point at this line:
```asm
gef➤  b *main+250
Breakpoint 1 at 0xac0
```

Now, let's run the program:
```asm
gef➤  r
Starting program: /home/user/Downloads/passphrase 

Halt! ⛔
You do not look familiar..
Tell me the secret passphrase: AAAAAAAA

Breakpoint 1, 0x0000555555554ac0 in main ()

[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdfe0  →  "3xtr4t3rR3stR14L5_VS_hum4n5"
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x00007fffffffe000  →  "AAAAAAAA"
$rsp   : 0x00007fffffffdfe0  →  "3xtr4t3rR3stR14L5_VS_hum4n5"
$rbp   : 0x00007fffffffe030  →  0x0000555555554b40  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe000  →  "AAAAAAAA"
$rdi   : 0x00007fffffffdfe0  →  "3xtr4t3rR3stR14L5_VS_hum4n5"
$rip   : 0x0000555555554ac0  →  <main+250> call 0x555555554820 <strcmp@plt>
$r8    : 0x00007fffffffe000  →  "AAAAAAAA"
$r9    : 0x00007ffff7fa4be0  →  0x00005555557576a0  →  0x0000000000000000
$r10   : 0x6e              
$r11   : 0x246             
$r12   : 0x0000555555554860  →  <_start+0> xor ebp, ebp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdfe0│+0x0000: "3xtr4t3rR3stR14L5_VS_hum4n5"	 ← $rax, $rsp, $rdi
0x00007fffffffdfe8│+0x0008: "R3stR14L5_VS_hum4n5"
0x00007fffffffdff0│+0x0010: "5_VS_hum4n5"
0x00007fffffffdff8│+0x0018: 0x0000555500356e34 ("4n5"?)
0x00007fffffffe000│+0x0020: "AAAAAAAA"	 ← $rdx, $rsi, $r8
0x00007fffffffe008│+0x0028: 0x0000000000000000
0x00007fffffffe010│+0x0030: 0x0000555555554b40  →  <__libc_csu_init+0> push r15
0x00007fffffffe018│+0x0038: 0x0000555555554860  →  <_start+0> xor ebp, ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555554ab6 <main+240>       lea    rax, [rbp-0x50]
   0x555555554aba <main+244>       mov    rsi, rdx
   0x555555554abd <main+247>       mov    rdi, rax
 → 0x555555554ac0 <main+250>       call   0x555555554820 <strcmp@plt>
   ↳  0x555555554820 <strcmp@plt+0>   jmp    QWORD PTR [rip+0x20179a]        # 0x555555755fc0 <strcmp@got.plt>
      0x555555554826 <strcmp@plt+6>   push   0x7
      0x55555555482b <strcmp@plt+11>  jmp    0x5555555547a0
      0x555555554830 <sleep@plt+0>    jmp    QWORD PTR [rip+0x201792]        # 0x555555755fc8 <sleep@got.plt>
      0x555555554836 <sleep@plt+6>    push   0x8
      0x55555555483b <sleep@plt+11>   jmp    0x5555555547a0
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
strcmp@plt (
   $rdi = 0x00007fffffffdfe0 → "3xtr4t3rR3stR14L5_VS_hum4n5",
   $rsi = 0x00007fffffffe000 → "AAAAAAAA",
   $rdx = 0x00007fffffffe000 → "AAAAAAAA"
)
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "passphrase", stopped 0x555555554ac0 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555554ac0 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rsi
0x7fffffffe000:	"AAAAAAAA"
gef➤  x/s $rdi
0x7fffffffdfe0:	"3xtr4t3rR3stR14L5_VS_hum4n5"
```

So we can simply see that ```rdi``` register contains the flag ```3xtr4t3rR3stR14L5_VS_hum4n5``` and ```rsi``` register contains our input ```AAAAAAAA```.

Let's change ```rsi``` register to contains the flag to make ```strcmp``` return 0:
```asm
gef➤  set $rsi="3xtr4t3rR3stR14L5_VS_hum4n5"
gef➤  c
Continuing.
✔

Sorry for suspecting you, please transfer this important message to the chief: CHTB{AAAAAAAA}

[Inferior 1 (process 908601) exited normally]
gef➤  

```

And we get the message that indicated we have the right flag.

The flag is: ```CHTB{3xtr4t3rR3stR14L5_VS_hum4n}```.