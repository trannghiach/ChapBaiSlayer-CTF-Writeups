# Sunshine CTF 2025 — Numbers Game

**Thể loại:** Reverse Engineering / Pwn

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách yêu cầu người chơi kết nối đến một dịch vụ mạng và chơi một trò chơi đoán số. Server sẽ tạo ra một con số "ngẫu nhiên" 64-bit cực lớn và yêu cầu người chơi đoán đúng để nhận được flag. Thử thách cung cấp một file thực thi ELF 64-bit để người chơi phân tích và tìm ra lỗ hổng trong logic sinh số.

---

## Mục tiêu

Mục tiêu chính là phân tích ngược file thực thi, tái tạo lại thuật toán sinh số của server, dự đoán chính xác con số bí mật và gửi nó đi để lấy flag.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Reverse Engineering:** Sử dụng các công cụ như Ghidra hoặc IDA để dịch ngược file thực thi và đọc hiểu mã C/C++ đã được decompile.
- **Lập trình C:** Hiểu rõ về các kiểu dữ liệu (`time_t`, `unsigned int`), cơ chế ép kiểu (type casting), các phép toán bitwise (`<<`, `|`), và các hàm thư viện chuẩn (`time`, `srand`, `rand`).
- **Lập trình Python:** Sử dụng Python để viết kịch bản tự động hóa, tương tác với dịch vụ mạng (ví dụ qua thư viện `pwntools`) và gọi các tiến trình con (`subprocess`).
- **Độ trễ mạng (Network Latency):** Hiểu rằng thời gian trên máy client và server không bao giờ đồng bộ hoàn hảo, dẫn đến sự cần thiết phải thử trong một khoảng thời gian nhỏ.

---

## Phân tích và hướng tiếp cận

Sau khi dịch ngược file thực thi bằng Ghidra, chúng ta có được hàm `main` chứa logic cốt lõi. Phân tích kỹ đoạn mã này sẽ hé lộ hai lỗ hổng tinh vi được ẩn giấu sau một logic có vẻ phức tạp.

```c
// Mã C đã được dịch ngược và làm gọn từ Ghidra
undefined8 main(void) {
  // ...
  time_t tVar4;
  ulong local_20; // Số bí mật của server
  ulong local_28; // Số của người chơi

  // ...
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4); // Lỗ hổng #1

  iVar1 = rand();
  iVar2 = rand();
  iVar3 = rand();

  local_20 = (long)iVar3 << 0x3e | (long)iVar1 | (long)iVar2 << 0x1f; // Lỗ hổng #2
  // ...
}

```

1. **Lỗ hổng #1: Ép kiểu Seed thời gian (Seed Truncation)**
    - Hàm `time(0)` trả về một giá trị kiểu `time_t`, là một số nguyên 64-bit trên hệ thống của server.
    - Tuy nhiên, hàm `srand()` nhận vào một tham số kiểu `unsigned int`, là một kiểu 32-bit.
    - Dòng `srand((uint)tVar4)` ép kiểu một cách tường minh giá trị timestamp 64-bit xuống còn 32-bit. Điều này có nghĩa là chỉ có 32 bit cuối của timestamp được dùng làm seed. Một kịch bản giải mã bỏ qua chi tiết này sẽ luôn tính sai seed.
2. **Lỗ hổng #2: Phép toán dịch bit vô nghĩa (Meaningless Bit Shift)**
    - Công thức tính toán là `(long)iVar3 << 62 | (long)iVar1 | (long)iVar2 << 31`.
    - Hàm `rand()` trả về một số nguyên 32-bit.
    - Khi dịch trái (`<<`) một số 32-bit đi 62 vị trí, tất cả các bit có nghĩa của nó sẽ bị đẩy ra ngoài và kết quả của phép toán `(long)iVar3 << 62` **luôn luôn bằng 0**.
    - Do đó, công thức phức tạp trên thực chất được rút gọn thành: `local_20 = (long)iVar1 | ((long)iVar2 << 31)`. Lần gọi `rand()` thứ ba là hoàn toàn không cần thiết.
3. **Vấn đề thực tế: Độ trễ mạng**
    - Ngay cả khi tái tạo lại logic một cách hoàn hảo, việc chạy script trên máy client và server diễn ra ở hai thời điểm khác nhau. Do có độ trễ mạng, `time(0)` của client gần như luôn trễ hơn `time(0)` của server một hoặc hai giây.
    - Vì vậy, một lần chạy duy nhất có xác suất thành công thấp. Giải pháp là chạy lại kịch bản vài lần liên tiếp. Kinh nghiệm thực tế cho thấy việc này thường thành công trong vòng 3-4 lần thử.

---

## Kịch bản giải mã (Exploit)

Cách tiếp cận đáng tin cậy nhất là viết một chương trình C nhỏ để tái tạo chính xác 100% logic sinh số, sau đó dùng một script Python để biên dịch, chạy và gửi kết quả.

**1. Chương trình C (`solver.c`)**

Đoạn mã này sao chép trung thực logic đã được phân tích từ file binary.

```c
// solver.c
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

int main() {
    // Lỗ hổng #1: Lấy thời gian và ép kiểu về 32-bit unsigned int
    unsigned int seed = time(0);
    srand(seed);

    // Lỗ hổng #2: Chỉ cần 2 lần gọi rand()
    int iVar1 = rand();
    int iVar2 = rand();
    int iVar3 = rand(); // Vẫn gọi để giống 100%, dù kết quả không dùng

    // Áp dụng công thức gốc, không rút gọn để đảm bảo tính trung thực
    unsigned long long final_number = ((unsigned long long)iVar3 << 62) |
                                      (unsigned long long)iVar1         |
                                      ((unsigned long long)iVar2 << 31);

    printf("%llu\\n", final_number);
    return 0;
}

```

**2. Kịch bản Python (`solve.py`)**

Script này tự động hóa toàn bộ quá trình: biên dịch, chạy file C, kết nối và gửi kết quả.

```python
# solve.py
#!/usr/bin/env python3

from pwn import *
import subprocess

# --- Cấu hình ---
host = 'chal.sunshinectf.games'
port = 25101
C_SOLVER_PATH = './solver'
C_SOURCE_FILE = 'solver.c'
# -----------------

log.info(f"Biên dịch mã C '{C_SOURCE_FILE}'...")
try:
    subprocess.run(['gcc', C_SOURCE_FILE, '-o', C_SOLVER_PATH], check=True)
    log.success(f"Biên dịch thành công ra file '{C_SOLVER_PATH}'.")
except (subprocess.CalledProcessError, FileNotFoundError):
    log.failure(f"Biên dịch thất bại. Hãy chắc chắn bạn đã có 'gcc' và file '{C_SOURCE_FILE}'.")
    exit(1)

log.info("Chạy C helper để tính toán con số...")

try:
    result_bytes = subprocess.check_output([C_SOLVER_PATH])
    correct_number_str = result_bytes.decode().strip()
except subprocess.CalledProcessError as e:
    log.failure(f"Chương trình C helper bị lỗi: {e}")
    exit(1)

log.info(f"Đã tính toán được số: {correct_number_str}. Kết nối và gửi...")

try:
    r = remote(host, port)
    r.recvuntil(b"fingers.\\x1b[0m\\n")
    r.sendline(correct_number_str.encode())

    log.success("Đã gửi! Đang chờ phản hồi...")
    response = r.recvall(timeout=2).decode()
    print("\\n" + "="*50)
    print("PHẢN HỒI TỪ SERVER:")
    print(response.strip())
    print("="*50 + "\\n")
    r.close()
except PwnlibException as e:
    log.failure(f"Lỗi kết nối hoặc tương tác: {e}")

```

---

## Kết quả (Flag)

Sau khi chạy script `solve.py` vài lần, một trong các lần thử sẽ khớp với thời gian của server và trả về flag.

`sun{I_KNOW_YOU_PLACED_A_MIRROR_BEHIND_ME}`

---

## Ghi chú và mẹo

- Đây là một bài tập reverse engineering kinh điển, dạy người chơi phải chú ý đến những chi tiết cực nhỏ như việc ép kiểu dữ liệu và giới hạn của các phép toán.
- Khi đối mặt với các thử thách `pwn` hoặc `rev` dựa trên `rand()` và `time(0)`, hãy luôn kiểm tra xem `time_t` (64-bit) có bị ép kiểu xuống `unsigned int` (32-bit) hay không. Đây là một lỗi phổ biến và là một "pattern" thường gặp trong CTF.
- Đừng vội từ bỏ nếu lần thử đầu tiên thất bại. Do độ trễ mạng, việc phải thử lại 2-3 lần là điều hoàn toàn bình thường.

---

# ENGLISH VERSION

**Category:** Reverse Engineering / Pwn

**Difficulty:** Easy

---

## Challenge Overview

The challenge requires players to connect to a network service and play a number guessing game. The server generates a very large 64-bit "random" number and asks the player to guess it correctly to receive the flag. The challenge provides a 64-bit ELF executable for players to analyze and find the flaw in the number generation logic.

---

## Objective

The main goal is to reverse engineer the executable, replicate the server's number generation algorithm, predict the exact secret number, and send it to retrieve the flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Reverse Engineering:** Using tools like Ghidra or IDA to decompile an executable and understand the resulting C/C++ code.
- **C Programming:** A solid grasp of data types (`time_t`, `unsigned int`), type casting, bitwise operations (`<<`, `|`), and standard library functions (`time`, `srand`, `rand`).
- **Python Scripting:** Using Python for automation, interacting with network services (e.g., via the `pwntools` library), and calling subprocesses.
- **Network Latency:** Understanding that client and server clocks are never perfectly synchronized, which necessitates trying a small window of time.

---

## Analysis and Approach

After decompiling the executable with Ghidra, we obtain the `main` function containing the core logic. A close analysis of this code reveals two subtle vulnerabilities hidden behind a seemingly complex logic.

```c
// Cleaned-up C code decompiled from Ghidra
undefined8 main(void) {
  // ...
  time_t tVar4;
  ulong local_20; // Server's secret number
  ulong local_28; // Player's number

  // ...
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4); // Vulnerability #1

  iVar1 = rand();
  iVar2 = rand();
  iVar3 = rand();

  local_20 = (long)iVar3 << 0x3e | (long)iVar1 | (long)iVar2 << 0x1f; // Vulnerability #2
  // ...
}

```

1. **Vulnerability #1: Time Seed Truncation**
    - The `time(0)` function returns a `time_t` value, which is a 64-bit integer on the server's system.
    - However, the `srand()` function accepts an `unsigned int` parameter, which is a 32-bit data type.
    - The line `srand((uint)tVar4)` explicitly casts the 64-bit timestamp down to 32 bits. This means only the lower 32 bits of the timestamp are used as the seed. An exploit script that ignores this detail will always calculate the wrong seed.
2. **Vulnerability #2: Meaningless Bit Shift**
    - The calculation formula is `(long)iVar3 << 62 | (long)iVar1 | (long)iVar2 << 31`.
    - The `rand()` function returns a 32-bit integer.
    - When you left-shift (`<<`) a 32-bit number by 62 places, all of its significant bits are shifted out, and the result of `(long)iVar3 << 62` is **always zero**.
    - Therefore, the complex formula effectively simplifies to: `local_20 = (long)iVar1 | ((long)iVar2 << 31)`. The third call to `rand()` is completely irrelevant.
3. **The Real-World Problem: Network Latency**
    - Even with a perfect replication of the logic, the client script and the server run at slightly different times. Due to network delay, the client's `time(0)` is almost always one or two seconds behind the server's `time(0)`.
    - Therefore, a single attempt has a low probability of success. The solution is to run the script a few times in quick succession. Real-world experience shows this usually succeeds within 3-4 tries.

---

## Exploit Script

The most reliable approach is to write a small C program to perfectly replicate the number generation logic, then use a Python script to compile, run, and send the result.

**1. C Program (`solver.c`)**

This code faithfully replicates the logic analyzed from the binary.

```c
// solver.c
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>

int main() {
    // Vulnerability #1: Get time and cast to 32-bit unsigned int
    unsigned int seed = time(0);
    srand(seed);

    // Vulnerability #2: Only the first 2 rand() calls matter
    int iVar1 = rand();
    int iVar2 = rand();
    int iVar3 = rand(); // Still call it to be 100% faithful, though its result is unused

    // Apply the original, non-simplified formula to ensure fidelity
    unsigned long long final_number = ((unsigned long long)iVar3 << 62) |
                                      (unsigned long long)iVar1         |
                                      ((unsigned long long)iVar2 << 31);

    printf("%llu\\n", final_number);
    return 0;
}

```

**2. Python Script (`solve.py`)**

This script automates the entire process: compiling, running the C file, connecting, and sending the result.

```python
# solve.py
#!/usr/bin/env python3

from pwn import *
import subprocess

# --- Configuration ---
host = 'chal.sunshinectf.games'
port = 25101
C_SOLVER_PATH = './solver'
C_SOURCE_FILE = 'solver.c'
# -----------------

log.info(f"Compiling C code '{C_SOURCE_FILE}'...")
try:
    subprocess.run(['gcc', C_SOURCE_FILE, '-o', C_SOLVER_PATH], check=True)
    log.success(f"Successfully compiled to '{C_SOLVER_PATH}'.")
except (subprocess.CalledProcessError, FileNotFoundError):
    log.failure(f"Compilation failed. Make sure you have 'gcc' and the file '{C_SOURCE_FILE}'.")
    exit(1)

log.info("Running C helper to calculate the number...")

try:
    result_bytes = subprocess.check_output([C_SOLVER_PATH])
    correct_number_str = result_bytes.decode().strip()
except subprocess.CalledProcessError as e:
    log.failure(f"C helper failed to run: {e}")
    exit(1)

log.info(f"Calculated number: {correct_number_str}. Connecting and sending...")

try:
    r = remote(host, port)
    r.recvuntil(b"fingers.\\x1b[0m\\n")
    r.sendline(correct_number_str.encode())

    log.success("Sent! Awaiting response...")
    response = r.recvall(timeout=2).decode()
    print("\\n" + "="*50)
    print("RESPONSE FROM SERVER:")
    print(response.strip())
    print("="*50 + "\\n")
    r.close()
except PwnlibException as e:
    log.failure(f"Connection or interaction error: {e}")

```

---

## Result (Flag)

After running the `solve.py` script a few times, one of the attempts will match the server's timing and return the flag.

`sun{I_KNOW_YOU_PLACED_A_MIRROR_BEHIND_ME}`

---

## Postmortem / Tips

- This is a classic reverse engineering challenge that teaches players to pay close attention to the smallest details, such as data type casting and the limits of mathematical operations.
- When facing `pwn` or `rev` challenges based on `rand()` and `time(0)`, always check if the 64-bit `time_t` is being cast down to a 32-bit `unsigned int`. This is a common flaw and a recurring pattern in CTFs.
- Don't give up if the first attempt fails. Due to network latency, needing 2-3 retries is completely normal. to network latency, needing 2-3 retries is completely normal.
