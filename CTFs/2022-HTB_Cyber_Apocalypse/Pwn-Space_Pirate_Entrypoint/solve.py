from pwn import *

elf = ELF('./sp_entrypoint')
libc = elf.libc

if args.REMOTE:
    p = remote('46.101.27.51', 30797)
else:
    p = process(elf.path)

p.recvuntil('>')
p.sendline("2")
print(p.recvuntil(':'))
p.sendline("306e6c7954683330723167316e346c437233774d336d6233723543346e50343535")
p.interactive()