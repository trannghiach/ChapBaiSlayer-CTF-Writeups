### Author: Kim Dokja

### Vietnamese and English Version:
Đề bài cung cấp một đoạn mã Python (`chall.py`) và một file `encrypted`. Đoạn mã nhắc đến "Eighth circle of Hell" và ngôn ngữ Malbolge, nhưng logic thực tế nằm ở thuật toán mã hóa hệ cơ số 3 (Ternary base).

### Phân tích Source Code

Đoạn code thực hiện các bước sau:

1. Chuyển Flag sang dạng số nguyên lớn `s`.
2. Xử lý `s` dưới dạng hệ cơ số 3 (trits).
3. Sử dụng vòng lặp để lấy cặp số:
    - **Đầu:** `s // 3**c` (Most Significant Trit).
    - **Cuối:** `s % 3` (Least Significant Trit).
4. Tra bảng ma trận 3x3 `o` để lấy ra một giá trị duy nhất (0-8).
5. Giá trị này được tích lũy vào biến kết quả `ss` (theo hệ cơ số 9).
6. Loại bỏ 2 trit vừa xử lý khỏi `s` và lặp lại cho đến hết.

$\rightarrow$ **Bản chất:** Đây là thuật toán "bóc vỏ hành" từ ngoài vào trong, nén 2 trits thành 1 digit hệ 9.

### Lời giải (Solution)

Vì bảng `o` là ma trận không trùng lặp giá trị, ta có thể đảo ngược quá trình (Reverse Lookup).

**Script giải mã (Python):**

### Description

The challenge provided a Python script (`chall.py`) and an `encrypted` file. The description references the "Eighth circle of Hell" (alluding to the Malbolge programming language), but the actual logic is a custom encryption scheme based on **Ternary (Base-3)** arithmetic.

### Source Code Analysis

The encryption script performs the following steps:

1. Converts the input flag into a large integer `s`.
2. Treats `s` as a sequence of Base-3 digits (trits).
3. Enters a loop that:
    - Extracts the **Most Significant Trit** (Head) and the **Least Significant Trit** (Tail).
    - Maps this pair using a specific 3x3 matrix (`o`) to a single value (0-8).
    - Accumulates this value into a result variable `ss` (effectively converting the pair into a Base-9 digit).
    - Removes the head and tail trits from `s` and repeats the process "peeling the onion" from the outside in.

### Solution

Since the 3x3 matrix `o` contains unique values (0-8), the mapping is bijective and fully reversible.

```html
import math

# 1. Cấu hình bảng tra cứu ngược (Reverse Lookup Table)
# Bảng gốc trong đề bài
o = (
    (6, 0, 7),
    (8, 2, 1),
    (5, 4, 3)
)

# Tạo từ điển để tra ngược: Giá trị -> (Hàng, Cột)
# Hàng (Row) tương ứng với số bên trái (Left Trit)
# Cột (Col) tương ứng với số bên phải (Right Trit)
inv_o = {}
for r in range(3):
    for c in range(3):
        val = o[r][c]
        inv_o[val] = (r, c)

def solve():
    try:
        # 2. Đọc file encrypted
        with open("encrypted", "rb") as f:
            data = f.read()
            # Chuyển bytes thành số nguyên lớn
            ss = int.from_bytes(data, byteorder='big')
    except FileNotFoundError:
        print("[-] Không tìm thấy file 'encrypted'. Hãy chắc chắn bạn đã có file này.")
        return

    print(f"[+] Đã đọc encrypted value. Đang giải mã...")

    # 3. Phân tích ss (Hệ cơ số 9)
    # Vì thuật toán mã hóa nhân 9 rồi cộng dồn (ss *= 9; ss += val),
    # Ta dùng chia lấy dư cho 9 để lấy lại các giá trị theo thứ tự ngược (từ trong ra ngoài).
    
    digits = []
    temp_ss = ss
    while temp_ss > 0:
        digits.append(temp_ss % 9)
        temp_ss //= 9
    
    # Lúc này 'digits' chứa các giá trị của cặp trits từ LỚP TRONG CÙNG ra LỚP NGOÀI CÙNG.
    
    # 4. Tái tạo lại chuỗi Trits ban đầu
    # Ta sẽ dùng một mảng (list), mỗi lần lấy được 1 cặp (Left, Right),
    # ta chèn Left vào đầu và Right vào cuối mảng.
    
    recovered_trits = []
    
    for val in digits:
        left, right = inv_o[val]
        recovered_trits.insert(0, left)  # Chèn vào đầu
        recovered_trits.append(right)    # Chèn vào cuối

    # 5. Chuyển từ hệ cơ số 3 (List of trits) về số nguyên (Integer)
    s_recovered = 0
    for t in recovered_trits:
        s_recovered = s_recovered * 3 + t

    # 6. Chuyển số nguyên thành text (Flag)
    try:
        # Tính số byte cần thiết
        byte_len = (s_recovered.bit_length() + 7) // 8
        flag = s_recovered.to_bytes(byte_len, 'big')
        print(f"\n[SUCCESS] Flag found:\n{flag.decode()}")
    except Exception as e:
        print(f"\n[ERROR] Có lỗi khi convert sang text (có thể sai logic hoặc file lỗi): {e}")

if __name__ == "__main__":
    solve()
```

```html
──(kimdokja㉿kimdokja)-[~/Downloads]
└─$ python3 crypt2.py 
[+] Đã đọc encrypted value. Đang giải mã...

[SUCCESS] Flag found:
pctf{a_l3ss_cr4zy_tr1tw1s3_op3r4ti0n_f37d4b}

```

