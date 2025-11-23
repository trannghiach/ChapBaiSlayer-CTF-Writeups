### Author: Kim Dokja

### Vietnamese Version: 
### Mô tả

Đề bài cung cấp một mã băm (hash) `3a52fc83037bd2cb81c5a04e49c048a2` và gợi ý rằng mật khẩu của quản trị viên đã bị lộ trong một vụ rò rỉ dữ liệu lớn ("popular password breach"), nhưng có thêm 2 chữ số ngẫu nhiên được nối vào phía sau (ví dụ: `password13`).

### Phân tích

1. **Nhận diện Hash:** Mã hash có độ dài 32 ký tự hex $\rightarrow$ Khả năng cao là **MD5**.
2. **Phân tích gợi ý:**
    - "Popular password breach" $\rightarrow$ Sử dụng wordlist kinh điển **`rockyou.txt`**.
    - "Two random digits following" $\rightarrow$ Cấu trúc mật khẩu là `[WORD]` + `[00-99]`.
3. **Chiến thuật:** Sử dụng **Hashcat** với chế độ tấn công Hybrid (kết hợp Wordlist và Mask).

### Lời giải (Solution)

Sử dụng công cụ Hashcat trên Kali Linux.

**Câu lệnh:**

Bash

`hashcat -m 0 -a 6 3a52fc83037bd2cb81c5a04e49c048a2 /usr/share/wordlists/rockyou.txt ?d?d`

**Giải thích tham số:**

- `m 0`: Chế độ MD5.
- `a 6`: Chế độ Hybrid (Wordlist + Mask).
- `rockyou.txt`: Từ điển gốc.
- `?d?d`: Mask đại diện cho 2 chữ số (00-99) được nối vào sau mỗi từ trong từ điển.

Kết quả:

Hashcat tìm ra kết quả: mr.krabbs57

### Flag

Plaintext

`pctf{mr.krabbs57}`

--------------------------------------

### English Version: 
### Description

We are given a password hash: 3a52fc83037bd2cb81c5a04e49c048a2.

The challenge description provides two critical hints:

1. The password was found in a "popular password breach."
2. The password consists of the leaked word followed by **two random digits** (e.g., `password13`).

### Analysis

1. **Hash Identification:** The hash is 32 hexadecimal characters long, which strongly suggests **MD5**.
2. **Pattern Recognition:**
    - "Popular password breach" $\rightarrow$ References the standard **`rockyou.txt`** wordlist.
    - "Two random digits" $\rightarrow$ Indicates a pattern of `[WORD]` + `[00-99]`.
3. **Strategy:** Perform a **Hybrid Attack** (Wordlist + Mask) using **Hashcat**.

### Solution

I used Hashcat on Kali Linux to crack the hash.

**Command:**

Bash

`hashcat -m 0 -a 6 3a52fc83037bd2cb81c5a04e49c048a2 /usr/share/wordlists/rockyou.txt ?d?d`

**Command Breakdown:**

- `m 0`: Specifies the hash type as **MD5**.
- `a 6`: Specifies **Hybrid Mode** (Wordlist + Mask).
- `rockyou.txt`: The base dictionary.
- `?d?d`: The mask representing two numeric digits appended to each word.

Result:

Hashcat successfully recovered the password: mr.krabbs57

### Flag

Plaintext

`pctf{mr.krabbs57}`
