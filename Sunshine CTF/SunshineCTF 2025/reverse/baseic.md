# Sunshine CTF 2025 — BASEic

---

**Thể loại:** Reverse Engineering

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một file thực thi ELF 64-bit cho Linux đã bị stripped. Khi chạy, chương trình yêu cầu người dùng nhập một flag. Mục tiêu của người chơi là phân tích (reverse) file thực thi này để tìm ra flag chính xác mà chương trình đang mong đợi.

---

## Mục tiêu

Mục tiêu chính là tìm ra chuỗi ký tự chính xác (flag) mà chương trình sử dụng để xác thực đầu vào của người dùng. Điều này đòi hỏi phải phân tích logic bên trong file thực thi.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Công cụ dòng lệnh Linux:** Sử dụng các lệnh như `file`, `strings`, `chmod`.
- **Phân tích tĩnh (Static Analysis):** Khả năng sử dụng một công cụ decompiler như Ghidra để dịch ngược mã máy thành mã C giả, giúp việc đọc hiểu logic trở nên dễ dàng hơn.
- **Mã hóa Base64:** Nhận biết được các chuỗi ký tự đã được mã hóa bằng Base64 và biết cách giải mã chúng.
- **Luồng hoạt động của chương trình C:** Hiểu cách một chương trình C đơn giản nhận đầu vào và so sánh chuỗi.

---

## Phân tích và hướng tiếp cận

1. **Phân tích ban đầu (Reconnaissance):**
    - Lệnh `file BASEic` xác nhận đây là một file thực thi ELF 64-bit, đã bị **stripped**. Điều này có nghĩa là bảng ký hiệu (tên hàm như `main`) đã bị xóa, làm cho việc phân tích động với GDB trở nên khó khăn hơn.
    - Chạy thử chương trình cho thấy nó yêu cầu nhập flag và đưa ra các phản hồi khác nhau (`You don't get the flag that easily`, `Soo Close`, `Closer`), gợi ý rằng có một logic so sánh chi tiết bên trong.
    - Lệnh `strings BASEic` là bước đột phá. Nó tiết lộ nhiều chuỗi ký tự đáng chú ý:
        - Bảng chữ cái Base64: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`.
        - Các mảnh chuỗi trông giống Base64: `c3Vue2MwdjNyMW5nX3V` và `yX0I0NTM1fQ==`.
        - Sự hiện diện của hàm `strncmp`, mặc dù sau này được phát hiện là một cái bẫy (red herring).
2. **Giả thuyết và Phân tích sâu:**
    - Giả thuyết ban đầu là chương trình ghép các mảnh chuỗi lại, giải mã Base64 và so sánh với đầu vào của người dùng.
    - Tuy nhiên, việc debug với GDB gặp nhiều khó khăn do file bị stripped và PIE. Thêm vào đó, breakpoint trên `strncmp` không được kích hoạt, cho thấy chương trình sử dụng một phương pháp so sánh khác.
    - Hướng tiếp cận hiệu quả nhất là sử dụng **phân tích tĩnh với Ghidra**.
3. **Quy trình giải quyết với Ghidra:**
    - Nạp file `BASEic` vào Ghidra và cho phép nó tự động phân tích.
    - Vì không có hàm `main`, chúng ta bắt đầu từ hàm `entry`. Mã C giả của `entry` sẽ chứa một lời gọi đến `__libc_start_main`. Tham số đầu tiên của hàm này chính là địa chỉ của hàm logic chính.
    - Nhấp vào địa chỉ đó (ví dụ `FUN_001014d1`) để đến hàm chính.
    - Đọc mã C giả của hàm chính. Logic của chương trình được phơi bày một cách rõ ràng: chương trình không hề biến đổi chuỗi sau khi giải mã. Nó chỉ đơn giản là so sánh đầu vào của người dùng với hai mảnh Base64 được ghép lại.
    
    <img width="482" height="604" alt="image" src="https://github.com/user-attachments/assets/2cc5135f-3b8c-46af-9336-1c51bbaaf5eb" />

    

---

## Kịch bản giải mã (Exploit)

Không có một "exploit" thực sự dưới dạng mã. Quá trình giải mã là sự kết hợp giữa phân tích và giải mã thủ công.

1. **Trích xuất các mảnh Base64 từ Ghidra:**
Từ mã C giả, chúng ta xác định được hai chuỗi chính xác mà chương trình sử dụng để so sánh:
    - Chuỗi 1: `c3Vue2MwdjNyMW5nX3V`
    - Chuỗi 2: `yX0I0NTM1fQ==`
2. **Ghép và giải mã:**
Nối hai chuỗi này lại để tạo thành một chuỗi Base64 hoàn chỉnh:
`c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ==`
3. **Sử dụng một công cụ giải mã Base64 (trực tuyến hoặc dòng lệnh):**
    
    ```bash
    echo "c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ==" | base64 -d
    
    ```
    

**Kết quả (Flag)**

Thực hiện lệnh trên sẽ cho ra flag cuối cùng.

`sun{c0v3r1ng_ur_B4535}`

---

## Ghi chú và mẹo

- Đây là một bài reverse engineering kinh điển, dạy người chơi tầm quan trọng của việc phân tích tĩnh trước khi nhảy vào debug.
- Lệnh `strings` là một công cụ cực kỳ mạnh mẽ để trinh sát ban đầu, nhưng không phải lúc nào cũng tin được 100% (ví dụ về `strncmp`).
- Khi đối mặt với file bị stripped và PIE, việc sử dụng decompiler như Ghidra thường hiệu quả và tiết kiệm thời gian hơn nhiều so với việc vật lộn với debugger dòng lệnh như GDB.
- Chú ý đến từng chi tiết nhỏ. Sự khác biệt giữa `B453s` và `B4535` hoàn toàn phụ thuộc vào chuỗi Base64 chính xác được sử dụng trong chương trình.

---

# ENGLISH VERSION

**Category:** Reverse Engineering

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a stripped 64-bit ELF executable for Linux. When run, the program prompts the user for a flag. The player's objective is to reverse-engineer this executable to find the correct flag the program expects.

---

## Objective

The main goal is to find the exact string (the flag) that the program uses to validate the user's input. This requires analyzing the logic embedded within the executable file.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Linux Command-Line Tools:** Using commands like `file`, `strings`, and `chmod`.
- **Static Analysis:** The ability to use a decompiler like Ghidra to reverse-engineer machine code into pseudo-C code, making the logic much easier to understand.
- **Base64 Encoding:** Recognizing Base64-encoded strings and knowing how to decode them.
- **C Program Flow:** Understanding how a simple C program takes input and performs string comparisons.

---

## Analysis and Approach

1. **Initial Reconnaissance:**
    - The `file BASEic` command confirms it's a 64-bit ELF executable that has been **stripped**. This means the symbol table (function names like `main`) has been removed, making dynamic analysis with GDB more challenging.
    - Running the program shows it asks for a flag and provides different responses (`You don't get the flag that easily`, `Soo Close`, `Closer`), suggesting a detailed comparison logic.
    - The `strings BASEic` command is the breakthrough. It reveals several noteworthy strings:
        - The Base64 alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`.
        - Base64-like string fragments: `c3Vue2MwdjNyMW5nX3V` and `yX0I0NTM1fQ==`.
        - The presence of the `strncmp` function, which was later discovered to be a red herring.
2. **Hypothesis and Deeper Analysis:**
    - The initial hypothesis was that the program concatenates the string fragments, decodes them from Base64, and compares the result against the user's input.
    - However, debugging with GDB proved difficult due to the stripped binary and PIE. Furthermore, a breakpoint on `strncmp` was never triggered, indicating the program uses a different comparison method.
    - The most effective approach is **static analysis with Ghidra**.
3. **Solving with Ghidra:**
    - Load the `BASEic` file into Ghidra and let it perform auto-analysis.
    - Since there's no `main` function, we start at the `entry` function. The pseudo-C code for `entry` will contain a call to `__libc_start_main`. The first argument to this function is the address of the actual main logic function.
    - Double-click on that address (e.g., `FUN_001014d1`) to navigate to the main function.
    - Read the pseudo-C code of this function. The program's logic is clearly laid out: the program does not perform any transformations after decoding. It simply compares the user's input against the two concatenated Base64 fragments.

---

## Exploit Script

There is no "exploit" in the traditional sense. The solution is a manual process of analysis and decoding.

1. **Extract Base64 Fragments from Ghidra:**
From the pseudo-C code, we identify the exact two strings the program uses for comparison:
    - String 1: `c3Vue2MwdjNyMW5nX3V`
    - String 2: `yX0I0NTM1fQ==`
2. **Concatenate and Decode:**
Join these two strings to form the complete Base64 string:
`c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ==`
3. **Use a Base64 Decoder (online tool or command-line):**
    
    ```bash
    echo "c3Vue2MwdjNyMW5nX3VyX0I0NTM1fQ==" | base64 -d
    
    ```
    

**Result (Flag)**

Executing the command above will produce the final flag.

`sun{c0v3r1ng_ur_B4535}`

---

## Postmortem / Tips

- This is a classic reverse-engineering challenge that teaches the importance of performing static analysis before diving into a debugger.
- The `strings` command is an incredibly powerful tool for initial reconnaissance, but its output isn't always 100% trustworthy (as seen with the `strncmp` red herring).
- When faced with a stripped binary with PIE enabled, using a decompiler like Ghidra is often far more efficient and time-saving than struggling with a command-line debugger like GDB.
- Pay attention to small details. The difference between `B453s` and `B4535` depended entirely on the exact Base64 string used in the program.
