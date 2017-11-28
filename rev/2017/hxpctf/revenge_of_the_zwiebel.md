revenge_of_the_zwiebel 100 (rev)
=============

### 1. Introduction

hxp ctf에서 나온 문제인데 100점짜리로 나와놓고 포너블보다 훨씬 어려웠다.. 리버싱을 못해서 그런지 엄청 힘들게 풀었다. 

### 2. Idea

일단 바이너리는 elf x64였는데, 그냥 실행하면 바로 꺼졌다. 그 이유를 보면 elf에 걸려있는 ptrace anti debugging때문인데 이걸 gdb script를 짜서 무시해주었다.
그리고 mmap으로 할당하고 뭔가 하는데 사람이 보기 힘든코드이다. 다만 입력을 받고 mmap으로 할당받은 영역으로 뛰어서 입력값에 비교연산을 하였다. 종류는 not, and 여서 잘 맞춰서 gdb 스크립트를 작성하였다.

### 3. Solve
``` python

import gdb
import time

index = 0
flag = dict()

def init():
	global flag

	for i in range(80):
		flag[str(i)] = 0x0

	return

def bypass_anti_debugging():
	gdb.Breakpoint('*0x400571')
	gdb.Breakpoint('*0x4006a3') # call rcx
	gdb.execute("r < <(python -c 'print \"A\" * 8')")
	gdb.execute('set $rax=0x0')
	gdb.execute('c')
	gdb.execute('si')

	return

def calc():
	global index
	global flag

	disasm = gdb.execute('x/6i $rip-0xa',True,True).split()

	for i in range(len(disasm)):
		if disasm[i] == 'and':
			print("AND")
			flag[str(index)] = flag[str(index)] | int(disasm[i+1].replace('cl,',''),16)
		if disasm[i] == 'not':
			print("NOT")
			break

	return

def printflag():
	global flag

	for i in range(80):
		if flag[str(i)] > 0:
			print(chr(flag[str(i)]), end=" ")
	print()
	return


def solve():
	global index
	global flag

	while True:
		gdb.execute('ni')
		disasm = gdb.execute('x/i $rip',True,True).split()

		if disasm[-1].find('[rax') > -1:
			index = int(disasm[-1].replace('[rax','').replace(']',''),16)
			print(index)

		if disasm[2] == 'jecxz':
			calc()
			gdb.execute('set $rcx=0x1')

		if disasm[2] == 'loop':
			jmp = gdb.execute('x/2i $rip',True,True).split()[4].replace(':','')
			gdb.execute('b *' + jmp)
			gdb.execute('c')
		pintflag()
		break
	return


def main():
	init()
	bypass_anti_debugging()
	solve()

	return

if __name__ == "__main__":
    main()


```

