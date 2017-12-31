go_solveMe 200 (rev)
=============

### 1. Introduction

어셈이 엄청 헷갈려서 어셈 기초도 안되있다는걸 느꼈다..

### 2. Solve

```asm
cqo
idiv    rbp
mov     rax, rdx
```

cqo와 idiv는 항상 같이 사용된다.
``` asm
idiv reg or memory
```
위와 같은 경우에는 아래와 같이 동작한다.
```asm
rax = rax / reg or memory 
```
또한 idiv는 부호있는 나눗셈을, div는 부호없는 나눗셈을 뜻한다. 
```asm
cqo
idiv    rbp
mov     rax, rdx ; 나머지

or

cqo
idiv    rbp
mov     rcx, rax ; 몫
```

나눗셈이 끝나면 몫은 rax에 나머지는 rdx에 들어가는간다. 즉 실제 바이너리에서는 이런식으로 바이너리에서 몫을 사용할지, 나머지를 사용할지 선택한다.

풀이는 바이너리에서 main_calc를 읽고 어셈을 이해하여 다음과같은 z3식을 만들면 된다.
```python
z3.solve((((x/1000000) % 10) * 10) + (x%10) == 38,x > 9999999)
```

값은 13000008이다.

FLAG : inctf{tH3_h|Gh3r_y@U_Cl|mB_tH3_Be??eR_Th3_v|3w}

