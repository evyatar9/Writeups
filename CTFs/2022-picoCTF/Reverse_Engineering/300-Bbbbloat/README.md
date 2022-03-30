# Bbbbloat - picoCTF 2022 - CMU Cybersecurity Competition
Reverse Engineering, 300 Points

## Description

![‏‏info.JPG](images/info.JPG)
 
## Bbbbloat Solution

By decompiling the [attched binary](./bbbbloat) using [Ghidra](https://github.com/NationalSecurityAgency/ghidra) we can see the following on ```FUN_00101307``` function:
```c

undefined8 FUN_00101307(void)

{
  char *__s;
  long in_FS_OFFSET;
  int local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0x4c75257240343a41;
  local_30 = 0x3062396630664634;
  local_28 = 0x35613066635f3d33;
  local_20 = 0x4e603234363266;
  printf("What\'s my favorite number? ");
  __isoc99_scanf();
  if (local_48 == 0x86187) {
    __s = (char *)FUN_00101249(0,&local_38);
    fputs(__s,stdout);
    putchar(10);
    free(__s);
  }
  else {
    puts("Sorry, that\'s not it!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

We can see the binary ask for the number ```0x86187``` (```549255```) as input, Let's run it and insert this input:
```console
┌─[evyatar@parrot]─[/pictoctf2022/reverse_engineering/Bbbbloat]
└──╼ $ ./bbbbloat 
What's my favorite number? 549255
picoCTF{cu7_7h3_bl047_2d7aeca1}
```

And we get the flag ```picoCTF{cu7_7h3_bl047_2d7aeca1}```.