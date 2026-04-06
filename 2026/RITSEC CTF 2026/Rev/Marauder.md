# CTF Writeup: Marauder (Reverse Engineering - Hard)

## 1. Thông tin bài thi
* **Tên thử thách:** Marauder
* **Thể loại:** Reverse Engineering
* **Mô tả:** There's an opposing ship that just snuck up on us! They seem to have gotten a head start one before us. Can you find their pid and kill it before they do us in? We'll reward you handsomely.
* **Mục tiêu:** Tìm Process ID (PID) của tiến trình đối thủ (kẻ địch) và gửi tín hiệu `kill` để tiêu diệt nó. Gợi ý "head start one before us" cho biết PID của kẻ địch chính là `PID của chúng ta - 1`.

## 2. Phân tích tĩnh (Static Analysis)

Khi ném file thực thi vào Ghidra và phân tích hàm `entry`, ta dễ dàng bị lừa bởi đoạn mã khởi tạo boilerplate của thư viện C (`__libc_start_main`). Tuy nhiên, logic thực sự của chương trình nằm tại địa chỉ được truyền vào, cụ thể là `LAB_00108ff4`, tương ứng với hàm `UndefinedFunction_00108ff4`.

Hàm này gọi trực tiếp đến `FUN_00108e00()` - đây chính là hàm `main` thực sự của chương trình.

### 2.1. Cấu trúc chương trình: Custom Virtual Machine (Máy ảo)
Bên trong hàm `FUN_00108e00`, ta thấy chương trình hoạt động dựa trên một vòng lặp vô hạn, liên tục nhận dữ liệu đầu vào và thực thi thông qua hàm `FUN_001091a4`:

```c
undefined8 FUN_00108e00(void) {
    // ... setup ...
    while (iVar1 = FUN_00109740(auStack_48,0), iVar1 == 0) {
        DAT_001b1900 = auStack_48;
        FUN_001091a4(); // Trình thông dịch (Interpreter) thực thi Bytecode
        FUN_00109870(auStack_48); // Dọn dẹp
    }
    // ...
}
```

Dựa vào các chuỗi debug bị rò rỉ và luồng điều khiển, ta khẳng định đây là một Custom VM (Máy ảo tùy chỉnh). Quá trình thực thi gồm 2 phần:
1. **Đọc Payload (`FUN_00109740`):** Hàm này parse payload của chúng ta thành 2 phần: Mảng hằng số (Constants) dạng số thực `double` (8 bytes) và Chuỗi lệnh (Bytecode). Payload bắt đầu bằng 4 bytes quy định số lượng hằng số.
2. **Thực thi Bytecode (`FUN_001091a4`):** Đây là "trái tim" của VM, nơi các Opcodes được giải mã và thực thi.

### 2.2. Dịch ngược tập lệnh (Instruction Set)
Phân tích hàm `FUN_001091a4`, ta có thể ánh xạ được các byte điều khiển thành các Opcode cụ thể thông qua các câu lệnh in debug của tác giả:

```c
bVar1 = FUN_00109100(); // Đọc 1 byte từ bytecode
if (bVar1 != 2) break;
cVar2 = FUN_00109100(); // Đọc tham số phụ của OP_SVC
if (cVar2 == '\x01') {
    FUN_00110a20("OP_SVC          kill");
    pdVar5 = DAT_001b2110 + -1; // Lấy giá trị trên cùng của VM Stack
    DAT_001b2110 = DAT_001b2110 + -1; // Pop stack
    FUN_0010a480((int)*pdVar5,9); // Gọi kill(PID, 9)
//...
} else if (cVar2 == '\0') {
    FUN_00110a20("OP_SVC          getpid");
    iVar3 = FUN_00122880(); // Gọi syscall getpid()
    *DAT_001b2110 = (double)iVar3; // Push PID vào VM Stack
//...
```

Và một đoạn rẽ nhánh khác xử lý việc push hằng số vào stack:
```c
bVar1 = FUN_00109100();
// ...
dVar8 = *(double *)(*(long *)(DAT_001b1900 + 0x18) + (ulong)bVar1 * 8);
FUN_0010aac0("OP_CONSTANT      %4d \'",bVar1);
*DAT_001b2110 = dVar8; // Push hằng số vào ngăn xếp
DAT_001b2110 = DAT_001b2110 + 1;
```

**Tổng hợp lại các Opcodes quan trọng:**
* `0x00 [index]`: `OP_CONSTANT` - Đẩy (push) hằng số thứ `index` vào VM Stack.
* `0x02 0x00`: `OP_SVC getpid` - Lấy PID của chương trình và đẩy vào VM Stack.
* `0x02 0x01`: `OP_SVC kill` - Rút (pop) PID từ đỉnh stack và tiêu diệt nó bằng tín hiệu 9 (`SIGKILL`).
* `0x01` (hoặc các opcode không khớp khiến thoát vòng lặp): `OP_RETURN` - Trình thông dịch sẽ pop giá trị cuối cùng trên stack, in nó ra màn hình và thoát vòng lặp hiện tại một cách an toàn.

## 3. Lỗ hổng và Chiến lược khai thác

**Vấn đề:** Máy ảo không cung cấp cho chúng ta các lệnh toán học cơ bản như `ADD` hay `SUB`. Ta không thể lấy PID, trừ đi 1 và gọi `kill` hoàn toàn bên trong 1 kịch bản bytecode.

**Điểm yếu:** 
1. Hàm `main` (`FUN_00108e00`) đặt trình thông dịch bên trong một vòng lặp `while`. Máy ảo sẽ không tắt ngay sau khi chạy xong 1 chuỗi lệnh, cho phép ta gửi nhiều payload liên tiếp trên cùng 1 kết nối TCP.
2. Lệnh `OP_RETURN` sẽ in kết quả ra `stdout`.

**Chiến lược (2 Giai đoạn):**
* **Giai đoạn 1 (Recon):** Gửi payload gồm bytecode `0x02 0x00` (`getpid`), sau đó gọi `0x01` (`return`). Chương trình sẽ in PID hiện tại trả về qua đường mạng cho chúng ta.
* **Tính toán (Local):** Script Python cục bộ nhận PID, tính `Enemy_PID = PID - 1`.
* **Giai đoạn 2 (Exploit):** Gửi payload thứ hai với 1 hằng số là `Enemy_PID` (định dạng `double`). Bytecode tương ứng sẽ là `0x00 0x00` (Push `Enemy_PID` vào stack) và `0x02 0x01` (`kill`). Cuối cùng là đẩy một rác liệu và gọi `return` để chương trình thoát sạch sẽ.

## 4. Mã khai thác (Exploit Script)

Sử dụng thư viện `pwntools` trong Python 3 để tự động hóa quá trình race condition này:

```python
#!/usr/bin/env python3
from pwn import *
import struct

def get_pid_payload():
    """ Payload 1: Lấy PID của chúng ta """
    # 0 hằng số
    payload = struct.pack('<I', 0)
    
    # Bytecode
    bytecode = b''
    bytecode += b'\x02\x00' # OP_SVC getpid (Lấy PID đẩy vào ngăn xếp)
    bytecode += b'\x01'     # OP_RETURN (Lấy giá trị trên cùng ngăn xếp và in ra)
    
    return payload + bytecode

def kill_enemy_payload(enemy_pid):
    """ Payload 2: Tiêu diệt PID của kẻ địch """
    # 1 hằng số
    payload = struct.pack('<I', 1)
    # Hằng số là PID của kẻ địch (kiểu double)
    payload += struct.pack('<d', float(enemy_pid))
    
    # Bytecode
    bytecode = b''
    bytecode += b'\x00\x00' # OP_CONSTANT 0 (Đẩy PID của kẻ địch vào ngăn xếp)
    bytecode += b'\x02\x01' # OP_SVC kill (Bắn tín hiệu tiêu diệt)
    bytecode += b'\x00\x00' # Đẩy thêm 1 giá trị rác (để OP_RETURN có thứ để in ra mà không bị lỗi)
    bytecode += b'\x01'     # OP_RETURN (Kết thúc an toàn)
    
    return payload + bytecode

def main():
    print("[*] Đang kết nối tới server...")
    # Khởi tạo kết nối tới server
    r = remote('marauder.ctf.ritsec.club', 1112)
    
    # --- BƯỚC 1: Lấy PID của chúng ta ---
    print("[*] Gửi Payload 1: Đọc PID...")
    r.send(get_pid_payload())
    
    # Đọc đầu ra từ server để tìm dòng chứa PID
    r.recvuntil(b"OP_RETURN\n") # Bỏ qua các dòng log cho đến khi thấy chữ OP_RETURN
    output = r.recvline().decode().strip()
    
    my_pid = int(float(output))
    print(f"[+] Tuyệt vời! PID của chúng ta là: {my_pid}")
    
    # --- BƯỚC 2: Tính toán và tiêu diệt ---
    enemy_pid = my_pid - 1
    print(f"[+] Xác định PID kẻ địch là: {enemy_pid}")
    
    print("[*] Gửi Payload 2: Tiêu diệt kẻ địch...")
    r.send(kill_enemy_payload(enemy_pid))
    
    # --- BƯỚC 3: Nhận cờ ---
    print("[*] Chuyển sang chế độ tương tác để nhận thưởng!")
    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ python3 solve.py                                        
[*] Đang kết nối tới server...
[+] Opening connection to marauder.ctf.ritsec.club on port 1112: Done
[*] Gửi Payload 1: Đọc PID...
[+] Tuyệt vời! PID của chúng ta là: 4
[+] Xác định PID kẻ địch là: 3
[*] Gửi Payload 2: Tiêu diệt kẻ địch...
[*] Chuyển sang chế độ tương tác để nhận thưởng!
[*] Switching to interactive mode
        
0000 OP_CONSTANT         0 '3'
        [ 3 ]
0002 OP_SVC           kill
        
0004 OP_CONSTANT         0 '3'
        [ 3 ]
0006 OP_RETURN
3
RS{gr4pp1ing_m4r4ud3r5}
[*] Got EOF while reading in interactive
$  

