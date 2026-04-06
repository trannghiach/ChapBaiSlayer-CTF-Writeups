# Sunshine CTF 2025 — Missioncritical1

**Thể loại:** Reverse Engineering

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một tệp thực thi ELF 64-bit có tên `chall`. Khi chạy, chương trình mô phỏng một giao diện điều khiển vệ tinh và yêu cầu người dùng nhập một "lệnh vệ tinh". Nếu lệnh không chính xác, nó sẽ trả về "Access Denied!". Nhiệm vụ của người chơi là dịch ngược tệp nhị phân này để tìm ra chuỗi lệnh chính xác nhằm có được quyền truy cập.

---

## Mục tiêu

Mục tiêu chính là phân tích tĩnh tệp thực thi để hiểu logic xác thực của nó và tìm ra chuỗi đầu vào bí mật sẽ khiến chương trình in ra thông báo "Access Granted!".

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Các lệnh cơ bản trên Linux:** Sử dụng các công cụ dòng lệnh như `file` (để xác định loại tệp) và `strings` (để trích xuất các chuỗi có thể in được từ tệp nhị phân).
- **Phân tích tĩnh (Static Analysis):** Khả năng sử dụng một công cụ dịch ngược (decompiler) như Ghidra hoặc IDA Pro để xem mã nguồn giả (pseudocode) của chương trình.
- **Đọc mã C cơ bản:** Hiểu logic của các hàm thư viện tiêu chuẩn như `sprintf`, `fgets`, và `strcmp`.

---

## Phân tích và hướng tiếp cận

Quá trình giải quyết thử thách có thể được chia thành ba bước chính: do thám ban đầu, phân tích chuỗi và dịch ngược mã.

1. **Do thám ban đầu:**
    - Sử dụng lệnh `file chall` để xác nhận rằng đây là một tệp thực thi ELF 64-bit và đã bị `stripped` (loại bỏ các ký hiệu gỡ lỗi).
    - Chạy chương trình (`./chall`) để hiểu hành vi của nó: nó in một thông báo trạng thái và yêu cầu nhập lệnh. Bất kỳ đầu vào nào cũng dẫn đến "Access Denied!".
2. **Phân tích chuỗi:**
    - Lệnh `strings chall` là một bước cực kỳ hữu ích. Nó tiết lộ nhiều thông tin quan trọng:
        - Các thông báo đầu ra: `Access Granted!`, `Access Denied!`, `Enter satellite command:`.
        - Một chuỗi định dạng rất đáng ngờ: `sun{%s_%s_%s}`. Đây rõ ràng là định dạng của flag.
        - Ba chuỗi trông giống như các thành phần của flag: `3131`, `s4t3ll1t3`, `e4sy`.
        - Các tên hàm được sử dụng: `strcmp`, `sprintf`, `fgets`. Sự kết hợp này gợi ý rằng chương trình xây dựng một chuỗi, nhận đầu vào từ người dùng và sau đó so sánh chúng.
3. **Dịch ngược mã với Ghidra:**
    - Mở tệp `chall` trong Ghidra và phân tích hàm chính (được xác định là `FUN_001010a0`).
    - Mã giả (pseudocode) cho thấy rõ ràng logic của chương trình:
        - Một lệnh gọi đến `sprintf` sử dụng chuỗi định dạng `sun{%s_%s_%s}` để xây dựng một chuỗi hoàn chỉnh. Các đối số được truyền vào là các chuỗi mà chúng ta đã tìm thấy trước đó bằng lệnh `strings`.
        - Dựa trên phân tích mã, chuỗi được tạo ra là `sun{e4sy_s4t3ll1t3_3131}\\n`.
        - Chương trình sau đó gọi `fgets` để đọc đầu vào của người dùng. Một điểm quan trọng cần lưu ý là `fgets` giữ lại ký tự xuống dòng (`\\n`) trong bộ đệm đầu vào.
        - Cuối cùng, một lệnh gọi đến `strcmp` so sánh trực tiếp đầu vào của người dùng (bao gồm cả ký tự `\\n`) với chuỗi được tạo bởi `sprintf`.
        - Nếu `strcmp` trả về 0 (nghĩa là các chuỗi khớp nhau hoàn toàn), chương trình sẽ in "Access Granted!".

---

## Hướng dẫn giải chi tiết

Dựa trên phân tích, chúng ta không cần bất kỳ kịch bản phức tạp nào. Lời giải đơn giản là cung cấp cho chương trình chuỗi chính xác mà nó mong đợi.

1. **Xây dựng chuỗi lệnh:**
Từ phân tích `sprintf` và `strings`, chúng ta ghép các mảnh lại với nhau:
    - Định dạng: `sun{%s_%s_%s}`
    - Thành phần 1: `e4sy`
    - Thành phần 2: `s4t3ll1t3`
    - Thành phần 3: `3131`
    - Chuỗi cuối cùng: `sun{e4sy_s4t3ll1t3_3131}`
2. **Cung cấp đầu vào:**
Chạy chương trình và nhập chuỗi đã xây dựng khi được nhắc.
    
    ```bash
    $ ./chall
    Satellite Status: Battery=80%, Orbit=32, Temp=-25C
    Enter satellite command: sun{e4sy_s4t3ll1t3_3131}
    Access Granted!
    
    ```
    

**Kết quả (Flag)**

Flag được tiết lộ chính là chuỗi lệnh đã cấp quyền truy cập.

`sun{e4sy_s4t3ll1t3_3131}`

---

## Ghi chú và mẹo

- Đây là một bài tập dịch ngược nhập môn cổ điển, tập trung vào việc tìm và diễn giải các chuỗi được mã hóa cứng (hardcoded).
- Luôn chạy lệnh `strings` trước tiên trên một tệp nhị phân. Nó thường có thể tiết lộ flag hoặc các gợi ý quan trọng, giúp tiết kiệm rất nhiều thời gian.
- Hiểu cách các hàm thư viện C phổ biến (như `fgets`, `gets`, `strcmp`, `strcpy`) hoạt động là điều cần thiết trong việc dịch ngược, vì các hành vi tinh vi của chúng (ví dụ: `fgets` giữ lại `\\n`) thường là chìa khóa để giải quyết thử thách.

---

# ENGLISH VERSION

**Category:** Reverse Engineering

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a 64-bit ELF executable named `chall`. When run, the program simulates a satellite control interface and prompts the user for a "satellite command." If the command is incorrect, it returns "Access Denied!". The player's task is to reverse engineer this binary to find the correct command string to gain access.

---

## Objective

The main goal is to statically analyze the executable to understand its authentication logic and discover the secret input string that will cause the program to print the "Access Granted!" message.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Basic Linux Commands:** Using command-line tools like `file` (to identify file types) and `strings` (to extract printable strings from a binary).
- **Static Analysis:** The ability to use a decompiler like Ghidra or IDA Pro to view the program's pseudocode.
- **Basic C Code Reading:** Understanding the logic of standard library functions like `sprintf`, `fgets`, and `strcmp`.

---

## Analysis and Approach

The process of solving the challenge can be broken down into three main steps: initial reconnaissance, string analysis, and code decompilation.

1. **Initial Reconnaissance:**
    - Use the `file chall` command to confirm that it is a 64-bit ELF executable that has been `stripped` of its debug symbols.
    - Run the program (`./chall`) to understand its behavior: it prints a status message and asks for a command. Any input results in "Access Denied!".
2. **String Analysis:**
    - The `strings chall` command is an extremely helpful step. It reveals several key pieces of information:
        - The output messages: `Access Granted!`, `Access Denied!`, `Enter satellite command:`.
        - A very suspicious format string: `sun{%s_%s_%s}`. This is clearly the format of the flag.
        - Three strings that look like flag components: `3131`, `s4t3ll1t3`, `e4sy`.
        - The names of functions used: `strcmp`, `sprintf`, `fgets`. This combination suggests the program builds a string, gets input from the user, and then compares them.
3. **Code Decompilation with Ghidra:**
    - Open the `chall` binary in Ghidra and analyze the main function (identified as `FUN_001010a0`).
    - The pseudocode clearly shows the program's logic:
        - A call to `sprintf` uses the `sun{%s_%s_%s}` format string to construct a complete string. The arguments passed are the strings we previously found with the `strings` command.
        - Based on the code analysis, the resulting string created is `sun{e4sy_s4t3ll1t3_3131}\\n`.
        - The program then calls `fgets` to read the user's input. A critical point to note is that `fgets` retains the trailing newline character (`\\n`) in the input buffer.
        - Finally, a call to `strcmp` directly compares the user's input (including the `\\n`) with the string constructed by `sprintf`.
        - If `strcmp` returns 0 (meaning the strings are identical), the program prints "Access Granted!".

---

## Detailed Solution

Based on the analysis, no complex scripting is needed. The solution is simply to provide the program with the exact string it expects.

1. **Construct the Command String:**
From the `sprintf` and `strings` analysis, we piece together the components:
    - Format: `sun{%s_%s_%s}`
    - Component 1: `e4sy`
    - Component 2: `s4t3ll1t3`
    - Component 3: `3131`
    - Final String: `sun{e4sy_s4t3ll1t3_3131}`
2. **Provide the Input:**
Run the program and enter the constructed string at the prompt.
    
    ```bash
    $ ./chall
    Satellite Status: Battery=80%, Orbit=32, Temp=-25C
    Enter satellite command: sun{e4sy_s4t3ll1t3_3131}
    Access Granted!
    
    ```
    

**Result (Flag)**

The flag is revealed to be the same command string that grants access.

`sun{e4sy_s4t3ll1t3_3131}`

---

## Postmortem / Tips

- This is a classic introductory reverse engineering challenge focused on finding and interpreting hardcoded strings.
- Always run `strings` on a binary first. It can often reveal the flag or major hints outright, saving a significant amount of time.
- Understanding how common C library functions (like `fgets`, `gets`, `strcmp`, `strcpy`) work is essential in reversing, as their subtle behaviors (e.g., `fgets` retaining the `\\n`) are often the key to solving a challenge.
