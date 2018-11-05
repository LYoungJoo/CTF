dont_panic 200 (rev)
=============

### 1. Introduction

분기문만 정확히 찾아내면 바로 스크립트짜서 돌릴 수 있었다.

### 2. Solve

```python
import gdb
import string

# flag len >= 0x2a

flag = ''
chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_{}-*+'"

gdb.Breakpoint('*0x47b96e')
for i in range(0,100):
	if flag.find('}') > -1:
		print("YEAH!! GET FLAG!")
		break

	for char in chars:
		gdb.execute('r "' + (flag + char).ljust(100,'A') + '"')
		for j in range(0,i):
			gdb.execute('c')

		al = int(gdb.execute('p $eax',True,True).split()[2])
		cl = int(gdb.execute('p $ecx',True,True).split()[2])

		if al == cl:
			flag += char
			print("[+] FOUND : " + flag)
			break
		else :
			print("[-] NONO : " + flag+char)
      
 # FLAG : hxp{k3eP_C4lM_AnD_D0n't_P4n1c__G0_i5_S4F3}
```
