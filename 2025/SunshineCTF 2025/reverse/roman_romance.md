# Sunshine CTF 2025 — Roman Romance

**Thể loại:** Reverse Engineering

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp cho người chơi hai file: một file thực thi ELF 64-bit tên là `romanromance` và một file văn bản chứa dữ liệu đã mã hóa là `enc.txt`. Khi chạy file thực thi, chương trình bị lỗi "Segmentation fault". Nhiệm vụ của người chơi là dịch ngược file `romanromance` để tìm ra thuật toán mã hóa, từ đó giải mã file `enc.txt` để lấy được flag.

---

## Mục tiêu

Mục tiêu chính là phân tích tĩnh file thực thi `romanromance` để hiểu logic hoạt động của nó. Sau khi xác định được phương thức mã hóa, người chơi cần viết một kịch bản để đảo ngược quá trình này và khôi phục lại nội dung gốc (flag) từ file `enc.txt`.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Phân tích file ELF:** Sử dụng các công cụ dòng lệnh như `file` để xác định loại file và `strings` để tìm các chuỗi ký tự đáng chú ý trong file nhị phân.
- **Dịch ngược (Decompilation):** Sử dụng các công cụ như Ghidra hoặc IDA Pro để chuyển đổi mã máy thành mã C giả (pseudo-code) có thể đọc được.
- **Mã hóa Caesar Cipher:** Nhận biết và hiểu cách hoạt động của thuật toán mã hóa dịch chuyển đơn giản, trong đó mỗi ký tự được thay thế bằng một ký tự khác cách nó một khoảng cố định trong bảng chữ cái (hoặc bảng mã ASCII).
- **Lập trình và xử lý file:** Sử dụng một ngôn ngữ lập trình như Python để đọc nội dung từ file, thực hiện các thao tác trên từng byte và ghi kết quả ra file mới hoặc màn hình.

---

## Phân tích và hướng tiếp cận

Quá trình giải quyết thử thách có thể được chia thành các bước logic sau:

1. **Phân tích ban đầu (Initial Triage):**
    - Sử dụng lệnh `file romanromance` để xác nhận đây là một file thực thi ELF 64-bit.
    - Chạy lệnh `strings romanromance` để trích xuất các chuỗi ký tự. Các chuỗi đáng chú ý bao gồm `flag.txt`, `enc.txt`, và một thông điệp hài hước từ "ATTILA THE HUN", gợi ý rằng chương trình có liên quan đến việc đọc và ghi file.
    - Chạy thử file `./romanromance` gây ra lỗi `Segmentation fault`, điều này cho thấy chương trình có thể mong đợi một file đầu vào (như `flag.txt`) tồn tại, nhưng không tìm thấy.
2. **Phân tích tĩnh với Ghidra (Static Analysis):**
    - Mở file `romanromance` trong Ghidra và phân tích hàm `main`.
    - Mã C được dịch ngược cho thấy một quy trình rõ ràng:
        - Chương trình cố gắng mở một file có tên `flag.txt`.
        - Nó đọc toàn bộ nội dung của `flag.txt` vào bộ nhớ.
        - Sau đó, nó đi qua từng byte của nội dung này trong một vòng lặp và **cộng 1** (`+ '\\x01'`) vào giá trị của mỗi byte. Đây chính là thuật toán mã hóa: một mã Caesar đơn giản với độ dịch chuyển là +1.
        - Cuối cùng, nội dung đã được mã hóa sẽ được ghi vào một file mới có tên `enc.txt`.
3. **Xây dựng logic giải mã:**
    - Vì quá trình mã hóa là cộng 1 vào mỗi byte, quá trình giải mã sẽ là thao tác ngược lại: **trừ 1** khỏi mỗi byte trong file `enc.txt`.
    - Chúng ta sẽ đọc nội dung của `enc.txt` và áp dụng phép toán này cho từng ký tự để khôi phục lại flag ban đầu.

---

## Kịch bản giải mã (Exploit)

Một kịch bản Python là công cụ hiệu quả để tự động hóa quá trình giải mã. Đoạn mã dưới đây đọc file `enc.txt` và thực hiện các bước đã phân tích ở trên.

```python
# solve.py
# Để chạy: python3 solve.py

# Tên file chứa nội dung đã mã hóa
encrypted_file = "enc.txt"

def solve_roman_romance():
    """
    Đọc file đã mã hóa, giải mã nội dung và in ra flag.
    """
    try:
        # Mở và đọc nội dung từ file enc.txt
        with open(encrypted_file, 'r') as f:
            encrypted_content = f.read()

        decrypted_flag = ""
        # Vòng lặp để duyệt qua từng ký tự trong nội dung mã hóa
        for char in encrypted_content:
            # Trừ 1 khỏi giá trị ASCII của mỗi ký tự để giải mã
            decrypted_char = chr(ord(char) - 1)
            decrypted_flag += decrypted_char

        return decrypted_flag

    except FileNotFoundError:
        return f"Lỗi: Không tìm thấy file '{encrypted_file}'."
    except Exception as e:
        return f"Đã xảy ra lỗi không mong muốn: {e}"

if __name__ == "__main__":
    flag = solve_roman_romance()
    print("Decoded Flag:", flag)

```

**Kết quả (Flag)**

Khi thực thi kịch bản với file `enc.txt` được cung cấp, kết quả thu được là flag của thử thách.

`sunshine{kN0w_y0u4_r0m@n_hI5t0rY}`

---

## Ghi chú và mẹo

- Đây là một bài tập Reverse Engineering cơ bản, rất tốt để làm quen với quy trình phân tích một file nhị phân đơn giản.
- Luôn bắt đầu với các công cụ cơ bản như `file` và `strings`. Chúng thường cung cấp những manh mối quan trọng về chức năng của chương trình trước khi cần đến các công cụ phức tạp hơn như decompiler.
- Khi phân tích mã dịch ngược, hãy chú ý đến các vòng lặp và các phép toán số học thực hiện trên dữ liệu. Đây thường là nơi chứa logic mã hóa hoặc xử lý chính.

---

# ENGLISH VERSION

**Category:** Reverse Engineering

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides two files: a 64-bit ELF executable named `romanromance` and a text file containing encrypted data, `enc.txt`. Attempting to run the executable results in a "Segmentation fault". The player's task is to reverse engineer the `romanromance` binary to discover the encryption algorithm and subsequently decrypt the `enc.txt` file to retrieve the flag.

---

## Objective

The main goal is to statically analyze the `romanromance` executable to understand its logic. After identifying the encryption method, the player must write a script to reverse this process and recover the original content (the flag) from the `enc.txt` file.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **ELF File Analysis:** Using command-line tools like `file` to identify the file type and `strings` to find interesting character sequences within the binary.
- **Decompilation:** Using tools like Ghidra or IDA Pro to convert machine code into readable C pseudo-code.
- **Caesar Cipher:** Recognizing and understanding the simple substitution cipher where each character is shifted by a fixed number of positions down the alphabet (or ASCII table).
- **Scripting and File Handling:** Using a programming language like Python to read content from a file, perform byte-wise manipulations, and write the output to a new file or the console.

---

## Analysis and Approach

The solving process can be broken down into the following logical steps:

1. **Initial Triage:**
    - Use the `file romanromance` command to confirm it is a 64-bit ELF executable.
    - Run `strings romanromance` to extract literal strings. Noteworthy strings include `flag.txt`, `enc.txt`, and a humorous message from "ATTILA THE HUN," suggesting the program involves file I/O.
    - Executing `./romanromance` causes a `Segmentation fault`, which indicates that the program likely expects an input file (such as `flag.txt`) to exist and fails when it is not found.
2. **Static Analysis with Ghidra:**
    - Open the `romanromance` binary in Ghidra and analyze the `main` function.
    - The decompiled C code reveals a clear procedure:
        - The program attempts to open a file named `flag.txt`.
        - It reads the entire content of `flag.txt` into memory.
        - It then iterates through each byte of this content in a loop and **adds 1** (`+ '\\x01'`) to the value of each byte. This is the encryption algorithm: a simple Caesar cipher with a shift of +1.
        - Finally, the modified (encrypted) content is written to a new file named `enc.txt`.
3. **Formulating the Decryption Logic:**
    - Since the encryption process is to add 1 to each byte, the decryption process must be the reverse operation: **subtract 1** from each byte in the `enc.txt` file.
    - We will read the content of `enc.txt` and apply this operation to every character to recover the original flag.

---

## Exploit Script

A Python script is an effective tool to automate this decryption process. The code below reads the `enc.txt` file and implements the steps outlined in the analysis.

```python
# solve.py
# To run: python3 solve.py

# The name of the file containing the encrypted content
encrypted_file = "enc.txt"

def solve_roman_romance():
    """
    Reads the encrypted file, decrypts its content, and prints the flag.
    """
    try:
        # Open and read the content from enc.txt
        with open(encrypted_file, 'r') as f:
            encrypted_content = f.read()

        decrypted_flag = ""
        # Loop through each character in the encrypted content
        for char in encrypted_content:
            # Subtract 1 from the ASCII value of each character to decrypt
            decrypted_char = chr(ord(char) - 1)
            decrypted_flag += decrypted_char

        return decrypted_flag

    except FileNotFoundError:
        return f"Error: File '{encrypted_file}' not found."
    except Exception as e:
        return f"An unexpected error occurred: {e}"

if __name__ == "__main__":
    flag = solve_roman_romance()
    print("Decoded Flag:", flag)

```

**Result (Flag)**

When the script is executed with the provided `enc.txt` file, the output is the challenge flag.

`sunshine{kN0w_y0u4_r0m@n_hI5t0rY}`

---

## Postmortem / Tips

- This is a fundamental Reverse Engineering challenge, excellent for getting acquainted with the workflow of analyzing a simple binary.
- Always start with basic tools like `file` and `strings`. They often provide crucial clues about a program's functionality before diving into more complex tools like decompilers.
- When analyzing decompiled code, pay close attention to loops and any arithmetic operations performed on data. This is often where the core encryption or processing logic resides.
