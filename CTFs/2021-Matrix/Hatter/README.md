# Hatter - Matrix Cyber Labs CTF 2021
Reversing, 500 Points

## Description

*Hello agent!*

*According to our intelligence, the organization’s engineers are celebrating their evil inventions by having a party* *in which everyone is wearing the same crazy hat.*

*We must send agent to the party to find out what they’re up to. The only way for you to get in is by wearing the same* 
*hat as them. Our intelligence has located the store on which the organization bought the hats from, but the store was *empty and contained a note:*

*"Hello fellas, this is the hatter! I’m attending a special event and will be back in a few days. If you wish to talk* *to me, you can find me at… well.. check out this file".*

*Note: The flag does not adhere to the usual format.*

And attached file [hatter](hatter)

## Hatter Solution

Let's run the binary

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter]
└──╼ $ ./hatter
find_thE_hAttEr
```

Nothing intersting, Let's try to open it using Ghidra.

From ```entry``` function we can move to ```FUN_00401180``` which is the ```main``` function, I just change the function signature from ```undefined8 FUN_00401180(int param_1,undefined8 param_2)``` to ```int main(int argc, char* argv[])```:

```c
int main(int argc,char **argv)

{
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  char **local_18;
  int local_10;
  undefined4 local_c;
  
  local_c = 0;
  local_38 = 0x20206010701;
  local_30 = 0x405000206000104;
  local_28 = 0x600050000020104;
  local_20 = 0xffff050104050600;
  local_18 = argv;
  local_10 = argc;
  FUN_00401350(); //<----------
  if (DAT_004050c1 == '\x01') {
    FUN_00401440();
  }
  if (DAT_004050c2 == '\x01') {
    FUN_00401760();
  }
  else {
    if (DAT_004050c3 == '\x01') {
      FUN_00401940();
    }
    else {
      if (local_10 == 1) {
        FUN_00401260((long)&local_38);
      }
      else {
        FUN_00401320();
      }
    }
  }
  return 0;
}
```

We can see the function call ```FUN_00401350``` from ```main```, Let's look on ```FUN_00401350```:
```c
void FUN_00401350(void)

{
  char *pcVar1;
  
  pcVar1 = getenv("DEBUG");
  DAT_004050c4 = pcVar1 != (char *)0x0;
  pcVar1 = getenv("WHERE_IS_THE_HATTER");
  DAT_004050c2 = pcVar1 != (char *)0x0;
  pcVar1 = getenv("SHOW_PASSWORD");
  DAT_004050c1 = pcVar1 != (char *)0x0;
  pcVar1 = getenv("DUMP_DEBUG_DATA");
  DAT_004050c3 = pcVar1 != (char *)0x0;
  return;
}
```

```FUN_00401350``` function checks if the following enviorment variables: ```DEBUG```, ```WHERE_IS_THE_HATTER```, ```SHOW_PASSWORD``` and ```DUMP_DEBUG_DATA``` contains value != 0.


Let's change the names:
1. ```FUN_00401350``` to ```CheckEnviormentVairables```
2. ```DAT_004050c4``` to ```isDebugEnvExist```
3. ```DAT_004050c2``` to ```isWhereIsTheHatterEnvExist```
4. ```DAT_004050c1``` to ```isShowPwdEnvExist```
5. ```DAT_004050c3``` to ```isDmpDbgDataEnvExist```

```c
void CheckEnviormentVairables(void)

{
  char *pcVar1;
  
  pcVar1 = getenv("DEBUG");
  isDebugEnvExist = pcVar1 != (char *)0x0;
  pcVar1 = getenv("WHERE_IS_THE_HATTER");
  isWhereIsTheHatterEnvExist = pcVar1 != (char *)0x0;
  pcVar1 = getenv("SHOW_PASSWORD");
  isShowPwdEnvExist = pcVar1 != (char *)0x0;
  pcVar1 = getenv("DUMP_DEBUG_DATA");
  isDmpDbgDataEnvExist = pcVar1 != (char *)0x0;
  return;
}
```

Now ```main``` function looks like:
```c
int main(int argc,char **argv)

{
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  char **local_18;
  int local_10;
  undefined4 local_c;
  
  local_c = 0;
  local_38 = 0x20206010701;
  local_30 = 0x405000206000104;
  local_28 = 0x600050000020104;
  local_20 = 0xffff050104050600;
  local_18 = argv;
  local_10 = argc;
  CheckEnviormentVairables();
  if (isShowPwdEnvExist == '\x01') {
    FUN_00401440();
  }
  if (isWhereIsTheHatterEnvExist == '\x01') {
    FUN_00401760();
  }
  else {
    if (isDmpDbgDataEnvExist == '\x01') {
      FUN_00401940();
    }
    else {
      if (local_10 == 1) {
        FUN_00401260((long)&local_38);
      }
      else {
        FUN_00401320();
      }
    }
  }
  return 0;
}
```

Let's try to set ```SHOW_PASSWORD``` and ```WHERE_IS_THE_HATTER``` enviorment variables to make ```FUN_00401440()``` and ```FUN_00401760()``` call.

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter]
└──╼ $export SHOW_PASSWORD=1
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter]
└──╼ $export WHERE_IS_THE_HATTER=1
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter]
└──╼ $./hatter 
Enter "P_tr01l"
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMWWWWWNWWWWWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMWd,.....       .............',;cloxO0XWMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMWd..o00KKXXNNWN0kO0OOOOOOOkkkkOkxdoc,,.  .';lxNMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMX' dWMMMMMMMXkxx0WMWXXKXXNMWNX000000000Ok0Oxo;. ;OMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMK..KMMMMMMWOkOW0xxxkkO0K0OkkO0KKKKK0OOkkkO0XN0dW0: .xWMMMMMMMMMMMMMM
MMMMMMMMMMMK..XMMMMMKOONOxxxkk0KK0OOO0NMMMMMWNNNNWWWWMMMMMNWMMXc .kMMMMMMMMMMMMM
MMMMMMMMMMN..KMMMMK0XWxd00dxKWMMMMMMNoNMMMMMMMM0dxxkkOKXOxXMMMMMK' dMMMMMMMMMMMM
MMMMMMMMMM; OMMMMXKMOoOlxWMMMMMMMMMMMWoMMMMMMMMM0KMMMMMMMNlkMMMMMM.;MMMMMMMMMMMM
MMMMMMMMMx oMMMMMMMK0XoWMMWKOkkk0XMMMMkMMMMMMMMMdMMMMMMMMMMOMMMMMM.'MMMMMMMMMMMM
MMMMMMMMx ,WMMMMMMMMMWMNo.         ,oXMMMMMMMMMMxMMMWNXKXNMMMMMMMMl xMMMMMMMMMMM
MMMMMMX, .KWWMMMMMMMWMO ..      NNKd. cWMMMMMMMMX0c.      lNMMMMMMW; :NMMMMMMMMM
MMMMMd  ..ldxOKMMX:;OX  ..      ';xWW' :MMMMWO00'     .'.  oXddk0KkXx..xMMMMMMMM
MMMN, ,;NMWOl:;:o0WNkWkdx0NW0lX0x:. '. oMMMMN'    ':ldxkOKWMMMMMMNXxxX: lMMMMMMM
MMN..xoWMx..:odo, .:kNMMMWO, ;MMMMMXolXMMMMMMMN'.WMMMMMMMMMMXkkkkOkxOkO,.MMMMMMM
MM;.XxWMl oWMMd:MXd;. .... :0MMMMMMMMMMMMMMMMMM;.MMMMMMdkWXl .,;. ;NoMd;.MMMMMMM
MX oMkM0 cMMMM. dXMMMWX000NMMMMMMMMMMMMMMMMMMMMc ;KMMMMl    ;WkWM0kMdMx:.MMMMMMM
M0 kMkMk OMXk: .. 'dXMMMMMMMMMMMMx0:..;WMMMMMMMWk' ,0MMMWXKKN0 OMMMWkMx;.MMMMMMM
MK lMxW0 od .. OMXo. 'o0WMMNk000O0'.xOKNNWMMMMMMMMc  :WMMMMMMx ;XMKoKW:.,MMMMMMM
MM. XOOW. NMMN..NMMMKl  .,oONMMMMM;.0k    .XMMMMM0...,kOkNMMW:  lMW0kd  OMMMMMMM
MM0 .NxKXcNMMM' .oXMMM.'kl,. .;oOKO';NxWWKKWMdkKl ,NMMMMN0Wk.   'WkKMl oMMMMMMMM
MMM0.'XOxOWMMMW:   .cO. KMMMNOo;.  'cx0NMMMMMl. .xMMMMMMXd. .'   WMMk cMMMMMMMMM
MMMMX, .xWMMMMMM: :o'    lKMMMMMx cl;'.  .,:lodxxkxxoc;. ,d'.N.  XMM..WMMMMMMMMM
MMMMMWl ,NMMMMMMW, OMW.    .;o0W;.WMMMMN0o :oc,,  ,;cdd.,MMo N:  KMX lMMMMMMMMMM
MMMMMMMO..XMMMMMMW; kMl xl'      .0NMMMMMK kMMMM;.MMMMMc ON, .   KM0 oMMMMMMMMMM
MMMMMMMMO :MMMMMMMMo ..'WMMNx:.     .':cl; ,cccc. cl:;'.         XMO dMMMMMMMMMM
MMMMMMMMM: kMMMMMMMMK. oWMMMMMM: o:.                            .MM0 dMMMMMMMMMM
MMMMMMMMMW, OMMMMMMMMWx..oWMMMN.'MMMNOo:.                     . ;MMK oMMMMMMMMMM
MMMMMMMMMMW: oWMMMMMMMMWd..oKW' KMMMMMMM,.WKkdd:  :c; .;l .d .: kMMN cMMMMMMMMMM
MMMMMMMMMMMMx 'KMNXMMNWMMWx.   lMMMMMMMM'.MMMMMl XMMk cMo xO . ,MMMM.;MMMMMMMMMM
MMMMMMMMMMMMMX, lKdoON0ddKMMKo' .;oOXWMW..MMMMM''MMW'.N0  l:  :NMMMM''MMMMMMMMMM
MMMMMMMMMMMMMMMd  c00xxONOk0NMMNOl;.  ..  ;cc:: .c:.  .  .;oOWMMMMMM:.MMMMMMMMMM
MMMMMMMMMMMMMMMMWk; .cKKxxOXKkxxXMMMWNK0Okxddoooodxxk0KNMMMMM0MMMWMMl WMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWx' ;kXNOkO0KxxxONMMMMNKKK000OO00XWMMMMMNkOMMMxMMx XMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMO;. .:xNN0000xdOKXNNNXK0000000000000KXMMMNx0MMO 0MMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMNk:. ,xWMMWK00OOO0KNMMMMMWWNNWMMMMMMKxxWMMM0 OMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWO:  :OWMMMMMMWX00000000OOOO000OxOMMMMMW: 0MMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk; .l0XWMMMMMMMMMMMMMMMMMMMMMMMMMMMc cMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWk:.   .;lkXMMMMMMMMMMMMMMMMMMMO; dMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNKkl;. .,lx0NMMMMMMMMWKx:. cXMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNOd:'.  ...'... .'ckWMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXK0OOO0XNMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWKKNMMMMMNKKWMMMMMMMMMMMMMMMMMMMMMMMN0OKWMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK  oMMMMMc  KMMMMMMMMMMMMMMMMMMMMMMc    .0MMMMMMMM
MMMMMMMMxoOxcoXMKooOcxMKoclxNMK  :ocxWMc  KMNxlco0MMkokkll0KlckMK..oO  :MMMMMMMM
MMMMMMMM.  .. .Xx   .xo  ,. .KK   .  'Wc  KK. ,l. cM'  .   ..  dMMMk. .KMMMMMMMM
MMMMMMMM. 'M0  dx  dMW  ;MN  :K  lMo  Kc  Kc  ;:.  X' .Wo  OX  lMMK  cWMMMMMMMMM
MMMMMMMM. .0o  xx  OMM. 'NO  oK  ,K;  Nc  Ko  oklloW' .Md  0N  lMMK;;KMMMMMMMMMM
MMMMMMMM.     ;Wx  OMMK'    cWK  .   dMc  KW:  . .xM' .Md  0N  lMMk  kMMMMMMMMMM
MMMMMMMM. ,WKNMMWNNWMMMMNKKWMMMNNWNKWMMWNNMMMWKKXMMMNNNMWNNWMNNWMMWNNWMMMMMMMMMM
MMMMMMMM:'lMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
Enter "hinT"
Enter "pRnTE"
in ordEr to find thE hAttEr YoU hAvE to find ALL thE 6 LinE5
```

We can see output "in ordEr to find thE hAttEr YoU hAvE to find ALL thE 6 LinE5".
We have 3 lines:
1. P_tr01l
2. hinT
3. pRnTE

Let's try to unset ```WHERE_IS_THE_HATTER```,```SHOW_PASSWORD```  and set ```DUMP_DEBUG_DATA``` to make only ```FUN_00401940``` call.
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter/hatter]
└──╼ $unset WHERE_IS_THE_HATTER
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter/hatter]
└──╼ $unset SHOW_PASSWORD
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter/hatter]
└──╼ $export DUMP_DEBUG_DATA=1
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter/hatter]
└──╼ $./hatter 
d)=
   %55A(�sQe
            OVEAYU�sQj:T^l�sQj-pa'Gt
F/�sQT+B]lBm�sQu"<:Ex'rz
                        �sQ
```

Not something we can read yet.

We need to figure out how to get all 6 lines, Let's search for "Enter" string (because "Enter "hinT", Enter "pRnTE").

Result:
```c
void FUN_004014d0(uint param_1)

{
  char cVar1;
  undefined8 *puVar2;
  undefined8 local_18;
  uint local_c;
  
  local_c = param_1;
  memset(&local_18,0,0xc);
  puVar2 = (undefined8 *)FUN_00401550(local_c); //<------------- 
  if ((puVar2 != (undefined8 *)0x0) && (cVar1 = FUN_004015e0(puVar2,&local_18), cVar1 != '\0')) { //<-------------
    printf("Enter \"%s\"\n",&local_18); //<---------
  }
  return;
}
```
```FUN_004014d0``` called with the following argument:
```FUN_004014a0(0);``` , ```FUN_004014a0(1);```, ```FUN_004014a0(2);```, ```FUN_004014a0(3);```, ```FUN_004014a0(4);```, ```FUN_004014a0(5);```.

```FUN_004014d0``` called to ```FUN_00401550```.

Let's look at ```FUN_00401550``` where ```param_1=0 (local_c)```:

```c
undefined * FUN_00401550(uint param_1)

{
  ulong local_20;
  
  local_20 = 0;
  while( true ) {
    if (5 < local_20) {
      return (undefined *)0x0;
    }
    if (param_1 == (byte)(&DAT_0040506b)[local_20 * 0x10]) break; //<------------- case of param_1 equal to 0
    local_20 = local_20 + 1;
  }
  return &DAT_00405060 + local_20 * 0x10; //<-------------
}
```

When ```FUN_00401550``` called with ```0``` the return value is ```&DAT_00405060[0] ```
So we can change the name of ```FUN_00401550``` to ```get16BytesByIndex```.

```DAT_00405060``` buffer contains:

```asm
                             DAT_00405060                                    XREF[4]:     FUN_00401550:00401576 (*) , 
                                                                                          FUN_00401550:0040159a (*) , 
                                                                                          FUN_00401940:00401950 (*) , 
                                                                                          FUN_00401940:00401950 (*)   
        00405060 64              ??         64h    d
        00405061 29              ??         29h    )
        00405062 3d              ??         3Dh    =
        00405063 0c              ??         0Ch
        00405064 18              ??         18h
        00405065 25              ??         25h    %
        00405066 35              ??         35h    5
        00405067 35              ??         35h    5
        00405068 41              ??         41h    A
        00405069 28              ??         28h    (
        0040506a 01              ??         01h
                             DAT_0040506b                                    XREF[1]:     FUN_00401550:0040158e (R)   
        0040506b 00              ??         00h
        0040506c de              ??         DEh
        0040506d 73              ??         73h    s
        0040506e 13              ??         13h
        0040506f 51              ??         51h    Q
        00405070 65              ??         65h    e
        00405071 0b              ??         0Bh
        00405072 4f              ??         4Fh    O
        00405073 56              ??         56h    V
        00405074 45              ??         45h    E
        00405075 41              ??         41h    A
        00405076 1b              ??         1Bh
        00405077 0f              ??         0Fh
        00405078 3f              ??         3Fh    ?
        00405079 59              ??         59h    Y
        0040507a 55              ??         55h    U
        0040507b 01              ??         01h
        0040507c df              ??         DFh
        0040507d 73              ??         73h    s
        0040507e 13              ??         13h
        0040507f 51              ??         51h    Q
        00405080 6a              ??         6Ah    j
        00405081 01              ??         01h
        00405082 07              ??         07h
        00405083 3a              ??         3Ah    :
        00405084 54              ??         54h    T
        00405085 5e              ??         5Eh    ^
        00405086 6c              ??         6Ch    l
        00405087 04              ??         04h
        00405088 01              ??         01h
        00405089 0f              ??         0Fh
        0040508a 01              ??         01h
        0040508b 02              ??         02h
        0040508c dc              ??         DCh
        0040508d 73              ??         73h    s
        0040508e 13              ??         13h
        0040508f 51              ??         51h    Q
        00405090 6a              ??         6Ah    j
        00405091 2d              ??         2Dh    -
        00405092 70              ??         70h    p
        00405093 61              ??         61h    a
        00405094 27              ??         27h    '
        00405095 47              ??         47h    G
        00405096 74              ??         74h    t
        00405097 0d              ??         0Dh
        00405098 0a              ??         0Ah
        00405099 46              ??         46h    F
        0040509a 2f              ??         2Fh    /
        0040509b 03              ??         03h
        0040509c dd              ??         DDh
        0040509d 73              ??         73h    s
        0040509e 13              ??         13h
        0040509f 51              ??         51h    Q
        004050a0 54              ??         54h    T
        004050a1 0f              ??         0Fh
        004050a2 2b              ??         2Bh    +
        004050a3 06              ??         06h
        004050a4 42              ??         42h    B
        004050a5 01              ??         01h
        004050a6 5d              ??         5Dh    ]
        004050a7 6c              ??         6Ch    l
        004050a8 42              ??         42h    B
        004050a9 01              ??         01h
        004050aa 6d              ??         6Dh    m
        004050ab 04              ??         04h
        004050ac da              ??         DAh
        004050ad 73              ??         73h    s
        004050ae 13              ??         13h
        004050af 51              ??         51h    Q
        004050b0 75              ??         75h    u
        004050b1 22              ??         22h    "
        004050b2 3c              ??         3Ch    <
        004050b3 3a              ??         3Ah    :
        004050b4 11              ??         11h
        004050b5 45              ??         45h    E
        004050b6 78              ??         78h    x
        004050b7 27              ??         27h    '
        004050b8 72              ??         72h    r
        004050b9 7a              ??         7Ah    z
        004050ba 0b              ??         0Bh
        004050bb 05              ??         05h
        004050bc db              ??         DBh
        004050bd 73              ??         73h    s
        004050be 13              ??         13h
        004050bf 51              ??         51h    Q

```

After ```FUN_004014d0``` called to ```get16BytesByIndex``` (changed from ```FUN_00401550```) Its called to ```FUN_004015e0```:

```c
undefined FUN_004015e0(undefined8 *param_1,undefined8 *param_2)

{
  byte bVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined local_19;
  
  local_19 = 0;
  uVar2 = *param_1;
  uVar3 = param_1[1];
  bVar1 = *(byte *)((long)param_1 + 0xb);
  FUN_004016f0((long)param_1 + 0xc,4,bVar1); //<------------- 
  if ((((*(char *)((long)param_1 + 0xc) == -0x22) && (*(char *)((long)param_1 + 0xd) == -0x53)) &&
      (*(char *)((long)param_1 + 0xe) == -0x42)) && (*(char *)((long)param_1 + 0xf) == -0x11)) {
    FUN_004016f0((long)param_1,0xb,bVar1);
    local_19 = 1;
    *param_2 = *param_1;
    *(undefined2 *)(param_2 + 1) = *(undefined2 *)(param_1 + 1);
    *(undefined *)((long)param_2 + 10) = *(undefined *)((long)param_1 + 10);
    *param_1 = uVar2;
    param_1[1] = uVar3;
  }
  return local_19;
}
```

Where ```param_1``` is point to ```&DAT_00405060[0]``` and ```param_2``` It's the output string.

```FUN_004015e0``` called twice to ```FUN_004016f0```:
```c
byte FUN_004016f0(long param_1,ulong param_2,byte param_3)

{
  ulong local_28;
  byte local_19;
  
                    /* bVar1 = *(byte *)((long)param_1 + 0xb);
                       FUN_004016f0((long)param_1 + 0xc,4,bVar1); 
                        */
  local_28 = 0;
  local_19 = param_3;
  while (local_28 < param_2) {
    *(byte *)(param_1 + local_28) = *(byte *)(param_1 + local_28) ^ local_19;
    local_19 = *(byte *)(param_1 + local_28);
    local_28 = local_28 + 1;
  }
  return local_19;
}
```

The first call of ```FUN_004016f0``` from ```FUN_004015e0``` is with three arguments as follow:
```FUN_004016f0((long)param_1 + 0xc /*param_1*/,4 /*param_2*/,bVar1 /*param_3*/);```
					   
1. ```param_1 + 0xc``` is ```&DAT_00405060[12]```
2. ```param_2``` is ```4```
3. ```param3``` is ```bVar1 = *(byte *)((long)param_1 + 0xb)``` which is ```&DAT_00405060[11]```

And as we can see at the first call of ```FUN_004016f0``` from ```FUN_004015e0``` change the buffer to:
```c
param1[12] = param[12] ^ param1[11]
param1[13] = param[13] ^ param1[12]
param1[14] = param[14] ^ param1[13]
param1[15] = param[15] ^ param1[14]
```

The seconds call of ```FUN_004016f0``` from ```FUN_004015e0``` is with another three arguments as follow:
```FUN_004016f0((long)param_1,0xb,bVar1);```

1. ```param_1 + 0xc``` is ```&DAT_00405060[0]```
2. ```param_2``` is ```0xb```
3. ```param3``` is ```&DAT_00405060[11]```

So the result of the second call to ```FUN_004016f0``` is:
```c
param1[0] = param1[0] ^ param1[11]
param1[1] = param1[1] ^ param1[0]
param1[2] = param1[2] ^ param1[1]
param1[3] = param1[3] ^ param1[2]
param1[4] = param1[4] ^ param1[3]
param1[5] = param1[5] ^ param1[4]
param1[6] = param1[6] ^ param1[5]
param1[7] = param1[7] ^ param1[6]
param1[8] = param1[8] ^ param1[7]
param1[9] = param1[9] ^ param1[8]
param1[10] = param1[10] ^ param1[9]
```

So we can changed the name of ```FUN_004015e0``` to ```decrypt16Bytes``` and ```FUN_004016f0``` to ```decryptXBytes```.

So now, we know we need to split ```DAT_00405060``` to 16 bytes:
```python
64,29,3d,0c,18,25,35,35,41,28,01,00,de,73,13,51
65,0b,4f,56,45,41,1b,0f,3f,59,55,01,df,73,13,51
6a,01,07,3a,54,5e,6c,04,01,0f,01,02,dc,73,13,51
6a,2d,70,61,27,47,74,0d,0a,46,2f,03,dd,73,13,51
54,0f,2b,06,42,01,5d,6c,42,01,6d,04,da,73,13,51
75,22,3c,3a,11,45,78,27,72,7a,0b,05,db,73,13,51
```

And we know how to decrypt each 16 bytes, So let's write a simple python for that:
```python
encryptedArray=[]
encryptedArray.append([0x64,0x29,0x3d,0x0c,0x18,0x25,0x35,0x35,0x41,0x28,0x01,0x00,0xde,0x73,0x13,0x51])
encryptedArray.append([0x65,0x0b,0x4f,0x56,0x45,0x41,0x1b,0x0f,0x3f,0x59,0x55,0x01,0xdf,0x73,0x13,0x51]) 
encryptedArray.append([0x6a,0x01,0x07,0x3a,0x54,0x5e,0x6c,0x04,0x01,0x0f,0x01,0x02,0xdc,0x73,0x13,0x51]) 
encryptedArray.append([0x6a,0x2d,0x70,0x61,0x27,0x47,0x74,0x0d,0x0a,0x46,0x2f,0x03,0xdd,0x73,0x13,0x51]) 
encryptedArray.append([0x54,0x0f,0x2b,0x06,0x42,0x01,0x5d,0x6c,0x42,0x01,0x6d,0x04,0xda,0x73,0x13,0x51]) 
encryptedArray.append([0x75,0x22,0x3c,0x3a,0x11,0x45,0x78,0x27,0x72,0x7a,0x0b,0x05,0xdb,0x73,0x13,0x51])

def decrypt_16_bytes(encArr):
    encArr[12]^=encArr[11]
    encArr[13]^=encArr[12]
    encArr[14]^=encArr[13]
    encArr[15]^=encArr[14]

    encArr[0]^=encArr[11]
    encArr[1]^=encArr[0]
    encArr[2]^=encArr[1]
    encArr[3]^=encArr[2]
    encArr[4]^=encArr[3]
    encArr[5]^=encArr[4]
    encArr[6]^=encArr[5]
    encArr[7]^=encArr[6]
    encArr[8]^=encArr[7]
    encArr[9]^=encArr[8]
    encArr[10]^=encArr[9]

    print([chr(x) for x in encArr])

for encArray in encryptedArray:
	decrypt_16_bytes(encArray
```

Run it:

```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter]
└──╼ $python decHatter.py 
['d', 'M', 'p', '|', 'd', 'A', 't', 'A', '\x00', '(', ')', '\x00', '\xde', '\xad', '\xbe', '\xef']
['d', 'o', ' ', 'v', '3', 'r', 'i', 'f', 'Y', '\x00', 'U', '\x01', '\xde', '\xad', '\xbe', '\xef']
['h', 'i', 'n', 'T', '\x00', '^', '2', '6', '7', '8', '9', '\x02', '\xde', '\xad', '\xbe', '\xef']
['i', 'D', '4', 'U', 'r', '5', 'A', 'L', 'F', '\x00', '/', '\x03', '\xde', '\xad', '\xbe', '\xef']
['P', '_', 't', 'r', '0', '1', 'l', '\x00', 'B', 'C', '.', '\x04', '\xde', '\xad', '\xbe', '\xef']
['p', 'R', 'n', 'T', 'E', '\x00', 'x', '_', '-', 'W', '\\', '\x05', '\xde', '\xad', '\xbe', '\xef']
```

Or:

```
dMp|dAtA\x00()\x00\xde\xad\xbe\xef
do v3rifY\x00U\x01\xde\xad\xbe\xef
hinT\x00^26789\x02\xde\xad\xbe\xef
iD4Ur5ALF\x00/\x03\xde\xad\xbe\xef
P_tr01l\x00BC.\x04\xde\xad\xbe\xef
pRnTE\x00x_-W\\\x05\xde\xad\xbe\xef
```

So we have 6 lines with some hints, But it isn't enough - We need to find more.

If we look at the ```main``` function we can see the follow:
```c
...
  if (isWhereIsTheHatterEnvExist == '\x01') {
    FUN_00401760();
  }
...
```

Where ```FUN_00401760``` is:
```c

void FUN_00401760(void)

{
  undefined local_238 [128];
  undefined *local_1b8;
  undefined *local_1b0;
  undefined *local_1a8;
  undefined *local_1a0;
  undefined *local_198;
  undefined *local_190;
  undefined local_188 [64];
  undefined local_148 [64];
  undefined local_108 [64];
  undefined local_c8 [64];
  undefined local_88 [64];
  undefined local_48 [53];
  undefined local_13 [11];
  
  local_190 = local_188;
  local_198 = local_148;
  local_1a0 = local_108;
  local_1a8 = local_c8;
  local_1b0 = local_88;
  local_1b8 = local_48;
  memcpy(local_1b8,&DAT_00403210,0x28); // <---------
  memcpy(local_1b0,&DAT_00403240,0x38); // <---------
  memcpy(local_1a8,&DAT_00403280,0x40); // <---------
  memcpy(local_1a0,&DAT_004032c0,0x40); // <---------
  memcpy(local_198,&DAT_00403300,0x40); // <---------
  memcpy(local_190,&DAT_00403340,0x40); // <---------
  memcpy(local_238,&DAT_00403380,0x7a);
  memset(local_13,0xb,0xb);
  FUN_004014a0(2);
  FUN_00401260((long)local_238);
  return;
}
```
Seems like we have another 6 buffers
```c
&DAT_00403210
&DAT_00403240
&DAT_00403280
&DAT_004032c0
&DAT_00403300
&DAT_00403340
```

```FUN_00401760``` called to ```FUN_00401260```:
```c

void FUN_00401260(long param_1)

{
  char cVar1;
  int local_28;
  undefined8 local_24;
  undefined8 *local_18;
  long local_10;
  
  local_18 = (undefined8 *)0x0;
  local_10 = param_1;
  FUN_004014a0(5);
  local_28 = 0;
  while( true ) {
    if (*(char *)(local_10 + (long)local_28 * 2) == -1) {
      putchar(10);
      return;
    }
    local_18 = (undefined8 *)get16BytesByIndex((uint)*(byte *)(local_10 + (long)local_28 * 2));
    if (local_18 == (undefined8 *)0x0) break;
    cVar1 = decrypt16Bytes(local_18,&local_24);
    if (cVar1 != '\0') {
      putchar((int)*(char *)((long)&local_24 + (ulong)*(byte *)(local_10 + 1 + (long)local_28 *2)))
      ;
    }
    local_28 = local_28 + 1;
  }
  return;
}
```
It's look like ```decrypt16Bytes``` before but with diffrent logic.

Let's focus on this part from ```FUN_00401760```:
```c
memcpy(local_1b8,&DAT_00403210,0x28);
memcpy(local_1b0,&DAT_00403240,0x38);
memcpy(local_1a8,&DAT_00403280,0x40);
memcpy(local_1a0,&DAT_004032c0,0x40);
memcpy(local_198,&DAT_00403300,0x40);
memcpy(local_190,&DAT_00403340,0x40);
memcpy(local_238,&DAT_00403380,0x7a);
memset(local_13,0xb,0xb);
FUN_004014a0(2);
FUN_00401260((long)local_238);
 ```
 
```FUN_00401260``` called only with ```DAT_00403380 (local_238)```.
If we call ```FUN_00401260``` with:
```c
&DAT_00403210
&DAT_00403240
&DAT_00403280
&DAT_004032c0
&DAT_00403300
&DAT_00403340
```

We can print the buffers.

Let's do it by change ```$rdi``` register before  ```FUN_00401260``` called using ```gdb``` (If we want call ```FUN_00401760``` we need to set enviorment variables ```WHERE_IS_THE_HATTER``` to 1:
```console
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter/hatter]
└──╼ $export export WHERE_IS_THE_HATTER=1
┌─[evyatar@parrot]─[/media/shared/ctf/matrix/hatter/hatter]
└──╼ $gdb hatter 
GNU gdb (Debian 9.2-1) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from hatter...
(No debugging symbols found in hatter)
gdb-peda$ b getenv
```

First, I just break on ```getenv``` function to looking for ```WHERE_IS_THE_HATTER``` string.
Then I just follow the code and then I see the following (Or you can break on *0x4017b1):
```asm
gdb-peda$ display/100i $pc
7: x/100i $pc
=> 0x4017b1:	mov    rsi,r10
   0x4017b4:	mov    r10d,0x28
   0x4017ba:	mov    QWORD PTR [rbp-0x248],rdx
   0x4017c1:	mov    rdx,r10
   0x4017c4:	mov    QWORD PTR [rbp-0x250],rax
   0x4017cb:	mov    QWORD PTR [rbp-0x258],rcx
   0x4017d2:	mov    QWORD PTR [rbp-0x260],r8
   0x4017d9:	mov    QWORD PTR [rbp-0x268],r9
   0x4017e0:	call   0x401080 <memcpy@plt>
   0x4017e5:	mov    rax,QWORD PTR [rbp-0x260]
   0x4017ec:	mov    rdi,rax
   0x4017ef:	movabs rsi,0x403240
   0x4017f9:	mov    edx,0x38
   0x4017fe:	call   0x401080 <memcpy@plt>
   0x401803:	mov    rax,QWORD PTR [rbp-0x240]
   0x40180a:	mov    rdi,rax
   0x40180d:	movabs rsi,0x403280
   0x401817:	mov    eax,0x40
   0x40181c:	mov    rdx,rax
   0x40181f:	mov    QWORD PTR [rbp-0x270],rax
   0x401826:	call   0x401080 <memcpy@plt>
   0x40182b:	mov    rax,QWORD PTR [rbp-0x248]
   0x401832:	mov    rdi,rax
   0x401835:	movabs rsi,0x4032c0
   0x40183f:	mov    rdx,QWORD PTR [rbp-0x270]
   0x401846:	call   0x401080 <memcpy@plt>
   0x40184b:	mov    rax,QWORD PTR [rbp-0x258]
   0x401852:	mov    rdi,rax
   0x401855:	movabs rsi,0x403300
   0x40185f:	mov    rdx,QWORD PTR [rbp-0x270]
   0x401866:	call   0x401080 <memcpy@plt>
   0x40186b:	mov    rax,QWORD PTR [rbp-0x250]
   0x401872:	mov    rdi,rax
   0x401875:	movabs rsi,0x403340
   0x40187f:	mov    rdx,QWORD PTR [rbp-0x270]
   0x401886:	call   0x401080 <memcpy@plt>
   0x40188b:	mov    rax,QWORD PTR [rbp-0x268]
   0x401892:	mov    QWORD PTR [rbp-0x1b0],rax
   0x401899:	mov    rcx,QWORD PTR [rbp-0x260]
   0x4018a0:	mov    QWORD PTR [rbp-0x1a8],rcx
   0x4018a7:	mov    rdx,QWORD PTR [rbp-0x240]
   0x4018ae:	mov    QWORD PTR [rbp-0x1a0],rdx
   0x4018b5:	mov    rsi,QWORD PTR [rbp-0x248]
   0x4018bc:	mov    QWORD PTR [rbp-0x198],rsi
   0x4018c3:	mov    rdi,QWORD PTR [rbp-0x258]
   0x4018ca:	mov    QWORD PTR [rbp-0x190],rdi
   0x4018d1:	mov    r8,QWORD PTR [rbp-0x250]
   0x4018d8:	mov    QWORD PTR [rbp-0x188],r8
   0x4018df:	lea    r9,[rbp-0x230]
   0x4018e6:	mov    rdi,r9
   0x4018e9:	movabs rsi,0x403380
   0x4018f3:	mov    edx,0x7a
   0x4018f8:	call   0x401080 <memcpy@plt>
   0x4018fd:	mov    rdi,QWORD PTR [rbp-0x238]
   0x401904:	mov    esi,0xb
   0x401909:	mov    edx,0xb
   0x40190e:	call   0x401070 <memset@plt>
   0x401913:	mov    edi,0x2
   0x401918:	call   0x4014a0
   0x40191d:	lea    rdi,[rbp-0x230]
   0x401924:	call   0x401260 // <-----------  FUN_00401260((long)local_238)
   0x401929:	add    rsp,0x270
   0x401930:	pop    rbp
   0x401931:	ret    
   0x401932:	nop    WORD PTR cs:[rax+rax*1+0x0]
   0x40193c:	nop    DWORD PTR [rax+0x0]
   0x401940:	push   rbp
   0x401941:	mov    rbp,rsp
   0x401944:	xor    edi,edi
   0x401946:	call   0x4014a0
   0x40194b:	mov    edi,0x1
   0x401950:	movabs rsi,0x405060
   0x40195a:	mov    edx,0x60
   0x40195f:	call   0x401050 <write@plt>
   0x401964:	pop    rbp
   0x401965:	ret    
```

So the code above is ```FUN_00401760``` function.

We need to break on ```0x401924``` and change the ```$rdi``` register.

From Ghidra (```FUN_00401760```) we can see:
```asm
        0040176f 48  8d  85       LEA        RAX =>local_188 , [RBP  + -0x180 ]
        00401776 48  8d  8d       LEA        RCX =>local_148 , [RBP  + -0x140 ]
        0040177d 48  8d  95       LEA        RDX =>local_108 , [RBP  + -0x100 ]
        00401784 48  8d  b5       LEA        RSI =>local_c8 , [RBP  + -0xc0 ]
        0040178b 4c  8d  45  80    LEA        R8=>local_88 , [RBP  + -0x80 ]
        0040178f 4c  8d  4d  c0    LEA        R9=>local_48 , [RBP  + -0x40 ]
```

So It's mean we need to change ```$rdi``` to ```$rbp-0x180, $rbp-0x140, $rbp-0x100, $rbp-0xc0, $rbp-0x80, $rbp-0x40```.

We can change register using ```set``` command in ```gdb```.

```asm
gdb-peda$ b *0x401924 //Will break on call FUN_00401260((long)local_238) from FUN_00401760
Breakpoint 1 at 0x401924
gdb-peda$ r
Starting program: /media/shared/ctf/matrix/hatter
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x0 
RCX: 0x1 
RDX: 0xb ('\x0b')
RSI: 0xb ('\x0b')
RDI: 0x7fffffffdc70 --> 0x101020102020601 
RBP: 0x7fffffffdea0 --> 0x7fffffffdee0 --> 0x401970 (endbr64)
RSP: 0x7fffffffdc30 --> 0x40 ('@')
RIP: 0x401924 (call   0x401260)
R8 : 0x7fffffffdd20 --> 0xa040a0405000a04 
R9 : 0x7fffffffdc70 --> 0x101020102020601 
R10: 0x40041a --> 0x6d007465736d656d ('memset')
R11: 0x7ffff7f48e90 (<__memset_avx2_unaligned>:	vmovd  xmm0,esi)
R12: 0x401090 (endbr64)
R13: 0x0 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x401913:	mov    edi,0x2
   0x401918:	call   0x4014a0
   0x40191d:	lea    rdi,[rbp-0x230]
=> 0x401924:	call   0x401260
   0x401929:	add    rsp,0x270
   0x401930:	pop    rbp
   0x401931:	ret    
   0x401932:	nop    WORD PTR cs:[rax+rax*1+0x0]
Guessed arguments:
arg[0]: 0x7fffffffdc70 --> 0x101020102020601 
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdc30 --> 0x40 ('@')
0008| 0x7fffffffdc38 --> 0x7fffffffde60 --> 0xa04090204040a04 
0016| 0x7fffffffdc40 --> 0x7fffffffde20 --> 0xa040a040a040a04 
0024| 0x7fffffffdc48 --> 0x7fffffffdd60 --> 0xa040a0408020a04 
0032| 0x7fffffffdc50 --> 0x7fffffffdd20 --> 0xa040a0405000a04 
0040| 0x7fffffffdc58 --> 0x7fffffffdda0 --> 0xa0407020a040a04 
0048| 0x7fffffffdc60 --> 0x7fffffffdde0 --> 0x2030a040a040a04 
0056| 0x7fffffffdc68 --> 0x7fffffffde95 ('\v' <repeats 11 times>, "\340\336\377\377\377\177")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0000000000401924 in ?? ()
gdb-peda$ set $rdi=$rbp-0x180 // Change $rdi before function call
gdb-peda$ c
.A.....3... 05
```

Great, From ```$rbp-0x180``` we get ```.A.....3... 05```, Let's continue with ```$rbp-0x140, $rbp-0x100, $rbp-0xc0, $rbp-0x80, $rbp-0x40```

```asm
gdb-peda$ set $rdi=$rbp-0x140
gdb-peda$ c
Continuing.
.7...B...1. 04     ||     || 
gdb-peda$ r
gdb-peda$ set $rdi=$rbp-0x100
gdb-peda$ c
..6....2... 03  U  ||--WWW |
gdb-peda$ r
gdb-peda$ set $rdi=$rbp-0xc0
gdb-peda$ c
...4....... 02 (__)\       )\/\
gdb-peda$ r
gdb-peda$ set $rdi=$rbp-0x80
gdb-peda$ c
....5...C.. 01 (xx)\_______
gdb-peda$ r
gdb-peda$ set $rdi=$rbp-0x40
gdb-peda$ c
.08....9... 00 ^__^
```

So we have (What is it? :D):

```
.08....9... 00 ^__^
....5...C.. 01 (xx)\_______
...4....... 02 (__)\       )\/\
..6....2... 03  U  ||--WWW |
.7...B...1. 04     ||     || 
.A.....3... 05
```

And total we have 12 lines:
```
dMp|dAtA\x00()\x00\xde\xad\xbe\xef
do v3rifY\x00U\x01\xde\xad\xbe\xef
hinT\x00^26789\x02\xde\xad\xbe\xef
iD4Ur5ALF\x00/\x03xde\xad\xbe\xef
P_tr01l\x00BC.\x04xde\xad\xbe\xef
pRnTE\x00x_-W\\\x05\xde\xad\xbe\xef
```

So If we just write it together as follow (replace ```\x00``` with ```0``` - dMp|dAtA\x00() => dMp|dAtA0()):
```
.08....9... 00
dMp|dAtA0() 00
....5...C.. 01
do v3rifY0U 01
...4....... 02
hinT0^26789 02
..6....2... 03
iD4Ur5ALF0/ 03
.7...B...1. 04
P_tr01l0BC. 04
.A.....3... 05
pRnTE0x_-W\\ 05
```

We can see the first row contains the flag index from the second row, example:
```
.08....9... 00
dMp|dAtA0() 00
```
Index 0 is M

Index 8 is p

Index 9 is A

...

So we have can get the flag:
```
0123456789ABC
MCL_T34_pAR1Y
```