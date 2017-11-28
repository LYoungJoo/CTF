unknown 200 (rev)
=============

### 1. Introduction

gdb script를 처음짜봤는데 재미있었다.

### 2. Solve

```c
signed __int64 __fastcall main(int a1, char **a2, char **a3)
{
  signed __int64 result; // rax
  unsigned int i; // [rsp+14h] [rbp-Ch]
  char *v5; // [rsp+18h] [rbp-8h]

  if ( a1 == 2 )
  {
    if ( strlen(a2[1]) == 56 )
    {
      v5 = a2[1];
      for ( i = 0; i < 0x38; ++i )
      {
        if ( (unsigned int)sub_401E90(v5, i) )
          dword_603084 = 1;
      }
      if ( dword_603084 )
        puts("Nope.");
      else
        printf("Congraz the flag is: %s\n", v5, a2);
      result = 0LL;
    }
    else
    {
      puts("Still nope.");
      result = 4294967294LL;
    }
  }
  else
  {
    puts("Try again.");
    result = 0xFFFFFFFFLL;
  }
  return result;
}
```

main만 보고 한글자씩 비교해서 틀리면 dword_603084를 1로 만들어주길래 이 점을 이용하여 gdb script를 작성하였다.

```python
import gdb
import string

chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + '-_{}!'
flag = ''
b = gdb.Breakpoint('*0x401c82',internal=True)

for i in range(0,56):
    for char in chars:
        gdb.execute('r ' + (flag + char).ljust(56,'A'), from_tty = False)
        for j in range(i):
            gdb.execute('c',from_tty = False)

        rax = int(gdb.execute('p $rax',from_tty=True,to_string=True).split()[2])

        if rax == 1:
            print("[-] NoNo " + flag + char)
        if rax == 0:
            flag += char
            print("[+] Good")
            print("FLAG : " + flag)
            break
            
# TUCTF{w3lc0m3_70_7uc7f_4nd_7h4nk_y0u_f0r_p4r71c1p471n6!}
```
