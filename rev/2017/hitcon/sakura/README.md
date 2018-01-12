Sakura 218 (rev)
=============

### 1. Review

hitcon에서 출제된 ELF Reversing 문제이다. Solver가 50명인 만큼 어렵지 않은 문제인데, 리버싱지식이 없어서 그런지 엄청 어렵게 풀었다. 요세 리버싱을 조금 해보면서 느끼는점이 몇가지 있는데 따로 정리하기 귀찮아서 여기다가 적어보려고 한다.

1. 포너블 vs 리버싱 : 리버싱을 조금밖에 안해봤지만 몇 문제들을 풀다 보니 두 분야는 문제를 접근하는 방식자체가 다른것 같다. 먼저 포너블에 경우에는, 일반적인 바이너리가 주어졌을때 보통은 취약점발견 -> 익스플로잇으로 문제를 해결하는 경우가 많다. 그래서 문제푸는 속도를 빠르게 하려면 바이너리를 대충 보더라도 실행흐름을 짐작하여 취약한 부분을 빠르게 찾아낼 수 있고, 빠르게 가장 최적화된 익스플로잇을 생각하여 권한을 획득해야 한다. 이를 위해서는 많은 문제들을 풀어보며 익스플로잇 센스를 늘리고, 지속적인 바이너리 리버싱을 통하여 빠르게 그 바이너리에대해 파악하는게 중요하다. 하지만 리버싱에 경우에는 그런식으로 생각해서는 안된다. 가장먼저 바이너리를 봤을때 이 바이너리가 어떤 바이너리인지 파악하는게 우선이다. 이 바이너리가 어떤 환경에서 돌아가는지 정확히 이해하고 그에 맞는 디컴파일러와 디버거를 준비하여 리버싱을 진행한다. 포너블에 경우에는 목적이 확실하지만 리버싱은 이 바이너리가 어떤 동작을 할지 예측할 수 없기 때문에 출제자의 의도를 생각하여 리버서가 어떤식으로 이 프로그램을 풀어나가야 할지부터 생각해야한다. 그걸 가장 빠르게 할 수 있는 방법중 하나가 Flag 문자열을 검색하는것이다. 최종 목적을 빠르게 확인하여 어떤식으로 내가 이부분까지 도달할 수 있는지를 체크해 문제의도를 빠르게 확인하는 것이다. 다만 이 문자열이 검색되지 않는경우에는 하나하나 리버싱을 해보는수밖에 없고 이는 아직 내 리버싱 실력이 부족해서 그런것 같다. 즉 리버싱은 포너블과 다르게 바이너리의 의도부터 파악하는게 가장 먼저고 이걸 우습게 알다가는 괜히 엄청 삽질하고 포기하게된다. 아마 내가 포너블문제만 풀다보니 이런 발상자체가 어색해서 적응하기 매우 힘들었다.
2. 코드분석 : 포너블의 경우 코드분석을 ida hex-ray에 의존한다. 또한 빠르게 프로그램의 동작 흐름을 알아내기 위하여 어떤 함수의 역할이 익스플로잇에 중요하지 않다고 판단되면 동적분석을 통해 그 함수가 어떤 역할을 하는지 대충 짐작하여 자세히 보지 않고 넘어간다. 이게 리버싱에서 통할줄 알았는데 전혀 아니다. 리버싱의 경우 어셈블리어 하나하나가 의미가 있는게 많아서 문제의도를 정확히 파악하지 못했을 경우에는 이런식의 대충보고 넘어가는 방식은 매우 위험한 생각이다. 만약 문제의도에 대해서 파악했다면 중요한 부분의 코드를 hex-ray를 통하여 분석하는게 아니라 차라리 어셈블리어를 통해 분석하는게 더 좋다. 그 이유는 리버싱문제들은 포너블과 다르게 분석자체를 많이 꼬아놨다. 그러므로 hex-ray가 이해하기 힘들게 나오는 경우가 매우 많다. 이것을 ida 동적디버깅을 이용하여 커버치려고 해도 정확한 코드 한줄한줄의 의미를 알아낼 수 없기 때문에 자칫하면 영원히 해답에 갈 수 없다. 그러므로 차라리 어셈블리어를 보면서 동적디버깅을 하게되면 더 빠르게 코드를 이해할 수 있다. hex-ray에 의존도를 더 줄여야할 필요성이 있는것 같다.

(요약 : 리버싱은 바이너리의 실행의도를 파악하는게 중요하며 hex-ray에 의존도를 줄이고 어셈블리어를 빠르게 읽는 연습을 하자)

사실 글만 많고 별 내용은 없다. 그냥 내가 포너블만하다가 리버싱으로 넘어오니까 여러가지 헷갈리는 부분이 많아서 그 느낌자체를 기록하고 싶었다. 누구 읽으라고 쓴글은 아니니 혹시라도 읽게된다면 그냥 그런가보다 해주길 바란다.

### 2. Solve
이 문제는 의도하는게 바로 main함수에 나타난다.
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    a2 = (char **)((char *)&unk_2121E0 + 20 * i);
    read(0, a2, 0x14uLL);
  }
  if ( (unsigned __int8)sub_850(&unk_2121E0, a2, a3) )
  {
    printf("hitcon{");
    sub_10FF6();
    puts("}");
  }
  return 0LL;
}
```
20 * 20의 입력을 받고 그 입력을 sub_850를 통해 검증한뒤 정상 입력이면 flag를 출력한다.

```c
LODWORD(v2) = sub_110F4(&v1055, 48LL);
v905 = v2;
LODWORD(v3) = sub_1110E(&v1055);
while ( v905 != v3 )
{
  v4 = *v905;
  v1 = (unsigned int)*v905;
  *(&byte_212040[20 * (signed int)v4] + SHIDWORD(v4)) = *(_BYTE *)(a1 + 20LL * (signed int)v4 + SHIDWORD(v4));
  v755 = *(_BYTE *)(a1 + 20LL * (signed int)v4 + SHIDWORD(v4)) - 48;
  if ( v755 <= 0 || v755 > 9 )
    v454 = 0;
  if ( (v605 >> v755) & 1 )
    v454 = 0;
  v605 |= 1 << v755;
  v455 += v755;
  ++v905;
}
if ( v455 != 17 )
  v454 = 0;
v456 = 0;
v606 = 0;
```
sub_850 함수는 위와같은 형태의 구문이 계속 반복하여 v454이 0이되면 flag 출력을 하지 않는 방식으로 진행된다.
```c
LODWORD(v2) = sub_110F4(&v1055, 48LL);
```
위 함수는 별의미없는 함수이다. v1055의 주소값을 바로 리턴한다.

```c
LODWORD(v3) = sub_1110E(&v1055);

signed __int64 sub_1110E()
{
  __int64 v0; // rax@1

  LODWORD(v0) = sub_11252();
  return v0 + 16;
}
```
sub_1110E는 인자로받은 주소값에 0x10을 더하여 return 한다.

```c
while ( v905 != v3 )
```
그렇게 v905와 v3의 주소값을 비교하는데 여기서는 16을 더했으므로 아래에서 1씩 증가한다고 가정했을때 두번 반복하게 된다.

```asm
.text:00000000000028DD                 mov     esi, dword ptr [rbp+var_DD8]
.text:00000000000028E3                 mov     ecx, dword ptr [rbp+var_DD8+4]
.text:00000000000028E9                 mov     eax, dword ptr [rbp+var_DD8]
.text:00000000000028EF                 movsxd  rdx, eax
.text:00000000000028F2                 mov     rax, rdx
.text:00000000000028F5                 shl     rax, 2
.text:00000000000028F9                 add     rax, rdx
.text:00000000000028FC                 shl     rax, 2
.text:0000000000002900                 mov     rdx, rax
.text:0000000000002903                 mov     rax, [rbp+var_1E58]
.text:000000000000290A                 add     rdx, rax
.text:000000000000290D                 mov     eax, dword ptr [rbp+var_DD8+4]
.text:0000000000002913                 cdqe
.text:0000000000002915                 movzx   eax, byte ptr [rdx+rax]
.text:0000000000002919                 mov     edi, eax
.text:000000000000291B                 movsxd  rcx, ecx
.text:000000000000291E                 movsxd  rdx, esi
.text:0000000000002921                 mov     rax, rdx
.text:0000000000002924                 shl     rax, 2
.text:0000000000002928                 add     rax, rdx
.text:000000000000292B                 shl     rax, 2
.text:000000000000292F                 lea     rdx, [rax+rcx]
.text:0000000000002933                 lea     rax, byte_212040
.text:000000000000293A                 add     rax, rdx
.text:000000000000293D                 mov     [rax], dil
.text:0000000000002940                 mov     eax, dword ptr [rbp+var_DD8]
.text:0000000000002946                 movsxd  rdx, eax
.text:0000000000002949                 mov     rax, rdx
.text:000000000000294C                 shl     rax, 2
.text:0000000000002950                 add     rax, rdx
.text:0000000000002953                 shl     rax, 2
.text:0000000000002957                 mov     rdx, rax
.text:000000000000295A                 mov     rax, [rbp+var_1E58]
.text:0000000000002961                 add     rdx, rax
.text:0000000000002964                 mov     eax, dword ptr [rbp+var_DD8+4]
.text:000000000000296A                 cdqe
.text:000000000000296C                 movzx   eax, byte ptr [rdx+rax]
```
그 아래 루틴은 어셈으로 보는게 더 편한데, 어셈은 아래와 같다. 위 루틴을 분석해보면 input_data[i][j]에 있는 값을 어떤 변수에 더해주고 이것을 두번 반복한다.

```c
  v755 = *(_BYTE *)(a1 + 20LL * (signed int)v4 + SHIDWORD(v4)) - 48;
  if ( v755 <= 0 || v755 > 9 )
    v454 = 0;
```
그리고 각 input_data[i][j]는 1~9의 문자열인지 검사한다.

```c
  if ( (v605 >> v755) & 1 )
    v454 = 0;
  v605 |= 1 << v755;
```
또한 여기서는 하나의 반복문에서 같은값을 가지고있는 input_data[i][j]가 있는지 판단하는데 이는 어셈으로 보면 더 정확하다.

```c
if ( v455 != 17 )
  v454 = 0;
```
그리고 최종적으로 더한값을 특정값과 비교한다.

위 모든 과정을 z3 Solver를 이용하여 반복해 풀어주면 된다.

```python
from z3 import *
import re

p_g = re.compile("plus_0x[0-9]+")
p_c = re.compile("v[0-9]+ != [0-9]+")

read_data = open('./sakura_de.c','rb').read()
find_data_1 = p_g.findall(read_data)
find_data_2 = p_c.findall(read_data)
condition_groups = list()
cmp_list = list()

# Make condition groups
for data in find_data_1:
	condition_groups.append(int(data.replace('plus_0x',''),16)/8)

# Make cmp list
for data in find_data_2:
	cmp_list.append(int(re.sub('v[0-9]+','',data).replace(' != ',''),10))

read_data = open('./array','rb').read()
conditions = read_data.split()
condition_list = list()

# Make condition list
for i,condition in enumerate(conditions):
	if i & 1:
		a.append(condition)
		condition_list.append(a)
	else:
		a = list()
		a.append(condition)

# Make conditions
conditions = list()
total = 0
for condition_group in condition_groups:
	a = list()
	for i in range(condition_group):
		a.append(condition_list[total + i])
	conditions.append(a)
	total += condition_group

s = Solver()
V = [[z3.Int('V{}_{}'.format(i,j)) for j in range(20)] for i in range(20)]
s.add([And(0 < V[i][j],V[i][j] <= 9) for j in range(20) for i in range(20)])

for condition,cmp_value in zip(conditions,cmp_list):
	s.add(Sum([V[int(i)][int(j)] for i,j in condition]) == cmp_value)
	s.add(Distinct([V[int(i)][int(j)] for i,j in condition]))


assert s.check() == sat
m = s.model()

print "".join(str(m.evaluate(V[i][j])) for i in range(20) for j in range(20))

# input : 1111111111111111111111111192111141111191117137819211638146831296181181171198371111891921111936191511111811121118216128431111311121111498193113711293411113792162119283711217128117211111911111192111191111111111111111111111111114165111271149111141835792118964127511251131731911153137176172186118611126111194815121115311136111571181861115211151148149153818516911851178632941173615284111311741111113511231

# FLAG : hitcon{6c0d62189adfd27a12289890d5b89c0dc8098bc976ecc3f6d61ec0429cccae61}
```

간단하게 설명하자면 가장 먼저 변수값들을 python list로 옮기고 아까 특정값을 더해주는 함수들도 전부다 파싱해서 조건 list를 만들어준다.

그리고 위에서 설명한것을 그대로 자동화해서 z3 Solver에 조건으로 넣어주면 풀 수 있다.
