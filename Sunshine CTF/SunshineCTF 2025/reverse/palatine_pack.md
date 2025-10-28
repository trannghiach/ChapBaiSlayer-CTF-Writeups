# Sunshine CTF 2025 — Palatine Pack

---

**Thể loại:** Reverse Engineering

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một file thực thi ELF 64-bit tên là `palatinepack` và một file `flag.txt` chứa dữ liệu bị hỏng, không thể đọc được. Khi chạy file thực thi, chương trình sẽ in ra một đoạn thông báo rồi gặp lỗi "Segmentation fault". Nhiệm vụ của người chơi là dịch ngược file thực thi để hiểu thuật toán mã hóa của nó, từ đó viết một kịch bản để giải mã file `flag.txt` và khôi phục lại flag ban đầu.

---

## Mục tiêu

Mục tiêu chính là phân tích tĩnh file `palatinepack` để tìm ra chuỗi các phép biến đổi dữ liệu mà nó thực hiện. Sau đó, đảo ngược thuật toán này để giải mã nội dung của `flag.txt` và tìm ra flag cuối cùng.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Công cụ dòng lệnh Linux:** Sử dụng các lệnh như `file`, `strings` để thực hiện phân tích ban đầu.
- **Dịch ngược (Reverse Engineering):** Sử dụng các công cụ phân tích tĩnh như Ghidra hoặc IDA Pro để dịch ngược file thực thi và hiểu logic hoạt động của nó.
- **Lập trình và xử lý bit:** Hiểu và làm việc với các phép toán trên bit (bitwise operations) như `NOT`, `XOR`, và dịch chuyển bit.
- **Viết kịch bản (Scripting):** Sử dụng một ngôn ngữ lập trình như Python để tái tạo lại thuật toán giải mã và tự động hóa quá trình khôi phục flag.

---

## Phân tích và hướng tiếp cận

1. **Phân tích ban đầu:**
    - `file palatinepack`: Xác định đây là một file thực thi ELF 64-bit, không bị strip, điều này rất thuận lợi cho việc dịch ngược vì tên các hàm được giữ lại.
    - `strings palatinepack`: Lệnh này tiết lộ nhiều thông tin quan trọng, bao gồm tên các hàm tự định nghĩa như `flipBits`, `expand`, và `anti_debug`, cũng như tên các file mà chương trình có thể tương tác là `palatinepackflag.txt` và `flag.txt`.
    - Chạy `./palatinepack` gây ra lỗi segfault, có thể do hàm `anti_debug` hoặc một lỗi logic khác. Điều này cho thấy phân tích tĩnh sẽ hiệu quả hơn phân tích động.
2. **Phân tích tĩnh với Ghidra:**
    - Mở file `palatinepack` trong Ghidra, ta tập trung vào hàm `main`.
    - Phân tích hàm `main` cho thấy một quy trình rõ ràng:
        1. Chương trình mở và đọc nội dung từ một file tên là `palatinepackflag.txt`.
        2. Dữ liệu đọc được sau đó được xử lý tuần tự qua các hàm: `flipBits`, `expand`, `expand`, và `expand` một lần nữa.
        3. Kết quả cuối cùng sau 3 lần `expand` được ghi vào file `flag.txt`.
    - **Phát hiện mấu chốt:** File `flag.txt` được cung cấp chính là **đầu ra** đã bị mã hóa, không phải là đầu vào. Để có được flag, chúng ta phải đảo ngược toàn bộ quy trình này, bắt đầu từ `flag.txt`.
3. **Dịch ngược thuật toán:**
    - **Hàm `expand`**: Hàm này nhận 1 byte đầu vào và tạo ra 2 byte đầu ra. Nó tách 1 byte thành hai nửa (4 bit cao và 4 bit thấp), sau đó kết hợp chúng với một khóa thay đổi theo từng vòng lặp. Để đảo ngược, ta cần viết một hàm `reverse_expand` nhận 2 byte và tái tạo lại 1 byte ban đầu.
    - **Hàm `flipBits`**: Hàm này lặp qua từng byte của dữ liệu. Với các byte ở vị trí chẵn, nó thực hiện phép toán `NOT` (`~`). Với các byte ở vị trí lẻ, nó thực hiện phép `XOR` với một khóa thay đổi. Cả hai phép toán này đều là phép toán đối xứng (involutory), nghĩa là áp dụng chúng một lần nữa sẽ khôi phục lại giá trị ban đầu. Do đó, hàm `reverse_flipBits` sẽ có logic giống hệt như hàm `flipBits`.
4. **Quy trình giải mã:**
    - Đọc nội dung của file `flag.txt`.
    - Áp dụng hàm `reverse_expand` 3 lần.
    - Áp dụng hàm `reverse_flipBits` 1 lần cho kết quả thu được.
    - Chuỗi kết quả cuối cùng chính là flag cần tìm.

---

## Kịch bản giải mã (Exploit)

Kịch bản Python dưới đây thực hiện quá trình giải mã ngược dựa trên những phân tích từ Ghidra.

```python
# solve.py
import os

def reverse_expand(data: bytes) -> bytes:
    """Đảo ngược hoạt động của hàm expand."""
    output = bytearray()
    # Xử lý từng cặp byte một để tái tạo lại byte gốc
    for i in range(len(data) // 2):
        byte1 = data[i * 2]
        byte2 = data[i * 2 + 1]

        original_byte = 0
        if i % 2 == 0:  # Chỉ số chẵn của byte gốc
            original_byte = (byte2 & 0xF0) | (byte1 & 0x0F)
        else:  # Chỉ số lẻ của byte gốc
            original_byte = (byte1 & 0xF0) | (byte2 & 0x0F)

        output.append(original_byte)

    return bytes(output)

def reverse_flipBits(data: bytes) -> bytes:
    """Đảo ngược hoạt động của hàm flipBits. Logic giống hệt hàm gốc."""
    key = 0x69
    output = bytearray()

    for i, byte in enumerate(data):
        new_byte = 0
        if i % 2 == 0: # Chỉ số chẵn
            new_byte = (~byte) & 0xFF  # NOT bitwise
        else: # Chỉ số lẻ
            new_byte = byte ^ key
            key = (key + 0x20) & 0xFF # Cập nhật khóa
        output.append(new_byte)

    return bytes(output)

# Đọc file flag.txt
with open("flag.txt", "rb") as f:
    encrypted_data = f.read()

# 1. Đảo ngược 3 lần expand
data_after_expand1 = reverse_expand(encrypted_data)
data_after_expand2 = reverse_expand(data_after_expand1)
data_after_expand3 = reverse_expand(data_after_expand2)

# 2. Đảo ngược 1 lần flipBits
decrypted_data = reverse_flipBits(data_after_expand3)

# 3. In kết quả
print("Decoded Flag:", decrypted_data.decode())

```

**Kết quả (Flag)**

Khi thực thi kịch bản với file `flag.txt`, kết quả thu được chính là flag của thử thách.

`sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}`

---

## Ghi chú và mẹo

- Đây là một bài tập dịch ngược cơ bản, rất tốt để luyện tập kỹ năng phân tích chương trình và đảo ngược thuật toán.
- Điểm mấu chốt trong thử thách này là nhận ra luồng dữ liệu chính xác: `input -> process -> output`, và `flag.txt` chính là `output`.
- Sự hiện diện của hàm `anti_debug` là một dấu hiệu mạnh mẽ cho thấy phân tích tĩnh sẽ là hướng đi chính, giúp tiết kiệm thời gian so với việc cố gắng vượt qua các kỹ thuật chống gỡ lỗi.
- Luôn chú ý đến các phép toán bit. Nhiều phép toán (như `NOT`, `XOR`) là đối xứng, giúp cho việc đảo ngược chúng trở nên tầm thường.

---

# ENGLISH VERSION

**Category:** Reverse Engineering

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a 64-bit ELF executable named `palatinepack` and a corrupted, unreadable file named `flag.txt`. Running the executable prints a message and then results in a "Segmentation fault". The player's task is to reverse engineer the executable to understand its encryption algorithm, then write a script to decrypt `flag.txt` and recover the original flag.

---

## Objective

The main goal is to statically analyze the `palatinepack` binary to figure out the series of data transformations it performs. Then, reverse this algorithm to decrypt the contents of `flag.txt` and find the final flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Linux Command-Line Tools:** Using commands like `file` and `strings` for initial reconnaissance.
- **Reverse Engineering:** Using static analysis tools like Ghidra or IDA Pro to decompile the executable and understand its logic.
- **Programming and Bit Manipulation:** Understanding and working with bitwise operations such as `NOT`, `XOR`, and bit shifting.
- **Scripting:** Using a programming language like Python to re-implement the decryption algorithm and automate the flag recovery process.

---

## Analysis and Approach

1. **Initial Reconnaissance:**
    - `file palatinepack`: Identifies the file as a 64-bit ELF executable that is not stripped, which is great for reversing as function names are preserved.
    - `strings palatinepack`: This command reveals crucial information, including custom function names like `flipBits`, `expand`, and `anti_debug`, as well as file names the program might interact with: `palatinepackflag.txt` and `flag.txt`.
    - Running `./palatinepack` causes a segfault, possibly due to the `anti_debug` function or another logical error. This suggests that static analysis will be more effective than dynamic analysis.
2. **Static Analysis with Ghidra:**
    - Opening `palatinepack` in Ghidra, we focus on the `main` function.
    - The analysis of `main` reveals a clear process:
        1. The program opens and reads content from a file named `palatinepackflag.txt`.
        2. The read data is then processed sequentially through the functions: `flipBits`, `expand`, `expand`, and `expand` one more time.
        3. The final result, after three `expand` calls, is written to the file `flag.txt`.
    - **Key Discovery:** The provided `flag.txt` file is the encrypted **output**, not the input. To get the flag, we must reverse this entire process, starting from `flag.txt`.
3. **Reversing the Algorithm:**
    - **`expand` function**: This function takes 1 byte of input and produces 2 bytes of output. It splits the byte into two nibbles (4 high bits and 4 low bits) and mixes them with a key that changes in each iteration. To reverse this, we need to write a `reverse_expand` function that takes 2 bytes and reconstructs the original byte.
    - **`flipBits` function**: This function iterates through each byte of the data. For bytes at even indices, it performs a bitwise `NOT` (`~`). For bytes at odd indices, it performs an `XOR` with a changing key. Both of these operations are involutory, meaning applying them a second time restores the original value. Therefore, the `reverse_flipBits` function will have the exact same logic as the original `flipBits` function.
4. **Decoding Process:**
    - Read the contents of the `flag.txt` file.
    - Apply the `reverse_expand` function three times.
    - Apply the `reverse_flipBits` function once to the resulting data.
    - The final resulting string is the flag.

---

## Exploit Script

The Python script below implements the reverse decryption process based on the analysis from Ghidra.

```python
# solve.py
import os

def reverse_expand(data: bytes) -> bytes:
    """Reverses the expand function's operation."""
    output = bytearray()
    # Process every pair of bytes to reconstruct the original byte
    for i in range(len(data) // 2):
        byte1 = data[i * 2]
        byte2 = data[i * 2 + 1]

        original_byte = 0
        if i % 2 == 0:  # Even index of the original byte
            original_byte = (byte2 & 0xF0) | (byte1 & 0x0F)
        else:  # Odd index of the original byte
            original_byte = (byte1 & 0xF0) | (byte2 & 0x0F)

        output.append(original_byte)

    return bytes(output)

def reverse_flipBits(data: bytes) -> bytes:
    """Reverses the flipBits function's operation. Logic is identical."""
    key = 0x69
    output = bytearray()

    for i, byte in enumerate(data):
        new_byte = 0
        if i % 2 == 0: # Even index
            new_byte = (~byte) & 0xFF  # Bitwise NOT
        else: # Odd index
            new_byte = byte ^ key
            key = (key + 0x20) & 0xFF # Update key
        output.append(new_byte)

    return bytes(output)

# Read the flag.txt file
with open("flag.txt", "rb") as f:
    encrypted_data = f.read()

# 1. Reverse the 3 expand calls
data_after_expand1 = reverse_expand(encrypted_data)
data_after_expand2 = reverse_expand(data_after_expand1)
data_after_expand3 = reverse_expand(data_after_expand2)

# 2. Reverse the 1 flipBits call
decrypted_data = reverse_flipBits(data_after_expand3)

# 3. Print the result
print("Decoded Flag:", decrypted_data.decode())

```

**Result (Flag)**

Executing the script with the `flag.txt` file yields the challenge flag.

`sunshine{C3A5ER_CR055ED_TH3_RUB1C0N}`

---

## Postmortem / Tips

- This is a classic introductory reverse engineering challenge, great for practicing program analysis and algorithm reversal.
- The key breakthrough in this challenge was understanding the correct data flow (`input -> process -> output`) and realizing that `flag.txt` was the `output`.
- The presence of an `anti_debug` function is a strong hint that static analysis is the intended path, saving time that might be spent trying to bypass anti-debugging techniques.
- Always pay close attention to bitwise operations. Many (like `NOT` and `XOR`) are involutory, making their reversal trivial.
