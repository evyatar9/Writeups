# Anti - ICHSA CTF 2021 - Hardware and Side-chanel Attacks
Category: Reverse Engineering, 450 Points

## Description


![‏‏image.JPG](images/image.JPG)
 
And attached file [anti](anti)

## Anti Solution

Let's try to run the binary
```console
┌─[evyatar@parrot]─[/ichsa2021/reversing/anti] 
└──╼ $ ./anti
Enter flag here: anti
Nope

```
Let's try to run in using ```gdb```:
```console
┌─[evyatar@parrot]─[/ichsa2021/reversing/anti] 
└──╼ $
"/ichsa2021/reversing/anti/anti": not in executable format: File format not recognized
gef➤  r
Starting program:  
No executable file specified.
Use the "file" or "exec-file" command.
gef➤  

```

It isn't working, Ghidra also fail to read the elf.


If we are trying to read the elf headers we see the elf headers are broken
```console
┌─[evyatar@parrot]─[/ichsa2021/reversing/anti] 
└──╼ $ readelf -h anti
ELF Header:
  Magic:   7f 45 4c 46 02 5c 78 30 32 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              <unknown: 5c>
  Version:                           120 <unknown: %lx>
  OS/ABI:                            <unknown: 30>
  ABI Version:                       50
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401b40
  Start of program headers:          64 (bytes into file)
  Start of section headers:          18656 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         4
  Section header string table index: 3
readelf: Error: no .dynamic section in the dynamic segment
readelf: Error: Reading 18935 bytes extends past end of file for dynamic string table

```

As we can see ```Data```, ```Version``` and ```OS/ABI``` contains unknown bytes.

By reading about Data header on [https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/#data](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/#data) and we can see Data header contains ```01``` for LSB and ```02``` for MSB.

[Version](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/#version) should contains ```01``` and [OS/ABI](https://linux-audit.com/elf-binaries-on-linux-understanding-and-analysis/#os/abi) should contains also ```01``` in our case.

So we can fix the ELF header using [hexedit](https://linux.die.net/man/1/hexedit) to:
```console
┌─[evyatar@parrot]─[/ichsa2021/reversing/anti] 
└──╼ $ readelf -h anti.fix 
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401b40
  Start of program headers:          64 (bytes into file)
  Start of section headers:          18656 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         4
  Section header string table index: 3
readelf: Error: no .dynamic section in the dynamic segment
readelf: Error: Reading 18935 bytes extends past end of file for dynamic string table
```

Now we can use binary with ```gdb``` and Ghidra.