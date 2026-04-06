Đây là một bài phân tích chi tiết về cách giải quyết thử thách crypto dựa trên một chuỗi mã hóa RSA lồng nhau, với một lỗ hổng nghiêm trọng trong khâu tạo khóa.

### **1. Mô Tả Bài Toán**

Chúng ta được cung cấp hai thứ:

1. **Một đoạn code Python (program.py)**: Chương trình này lấy một chuỗi FLAG, chuyển nó thành số nguyên, và sau đó mã hóa nó lặp đi lặp lại 1024 lần. Ở mỗi vòng lặp, một cặp khóa RSA mới được tạo ra, và kết quả mã hóa (ciphertext) của vòng lặp hiện tại sẽ trở thành đầu vào (plaintext) cho vòng lặp tiếp theo.
2. **Một file output (output.txt)**: File này chứa tất cả các giá trị modulus n được tạo ra trong 1024 vòng lặp và giá trị ciphertext cuối cùng (ct của vòng lặp 1023).

**Mục tiêu**: Tìm lại giá trị FLAG ban đầu.

<img width="438" height="324" alt="image" src="https://github.com/user-attachments/assets/adb2fba7-f210-479f-961c-32208d144e70" />


### **2. Phân Tích Lỗ Hổng**

Khi xem xét file program.py, chúng ta có thể thấy ngay hai điểm mấu chốt:

- **Cấu trúc chuỗi (Chained Encryption)**: ct của vòng lặp i trở thành pt cho vòng lặp i+1. Điều này có nghĩa là để tìm lại flag gốc, chúng ta phải thực hiện quy trình ngược lại: giải mã 1024 lần, bắt đầu từ ciphertext cuối cùng và đi ngược về 0.
- **Lỗ hổng tạo khóa**: Đây là điểm yếu chí mạng của thuật toán. Hãy nhìn vào cách p và q được tạo ra:codePython
    
    `p = getPrime(keysize)
    q = nextprime(p) # q là số nguyên tố ngay sau p
    n = p*q`
    
    Việc chọn q là số nguyên tố liền kề ngay sau p khiến chúng có giá trị **cực kỳ gần nhau**. Trong RSA, bảo mật của modulus n phụ thuộc vào độ khó của việc phân tích n thành hai thừa số nguyên tố p và q. Khi p và q quá gần nhau, n có thể bị phân tích một cách nhanh chóng bằng **Phương pháp Phân tích nhân tử của Fermat (Fermat's Factorization)**.
    

**Phương pháp Fermat hoạt động như thế nào?**

Phương pháp này hiệu quả khi n = p*q và |p - q| nhỏ. Nó dựa trên việc biểu diễn n dưới dạng hiệu của hai số chính phương:

n = a² - b²

Từ đó, ta có thể phân tích thành:

n = (a - b)(a + b)

Vậy p = a - b và q = a + b.

Vì p và q gần nhau, chúng sẽ gần với √n. Do đó, giá trị a cũng sẽ rất gần √n. Thuật toán sẽ bắt đầu với a = ceil(√n) và thử tăng dần a cho đến khi a² - n là một số chính phương hoàn hảo (b²).

### **3. Hướng Giải Quyết**

Dựa trên phân tích trên, chiến lược giải quyết của chúng ta như sau:

1. **Đọc dữ liệu**: Viết một hàm để đọc file output.txt và lưu tất cả 1024 giá trị n vào một danh sách, đồng thời lấy ra ciphertext cuối cùng.
2. **Lặp ngược**: Bắt đầu một vòng lặp từ i = 1023 xuống 0.
3. **Trong mỗi vòng lặp i**:
    
    a. Lấy ra modulus n_i tương ứng.
    
    b. Sử dụng **Phương pháp Fermat** để phân tích n_i thành p_i và q_i.
    
    c. Tính phi_i = (p_i - 1) * (q_i - 1).
    
    d. Tính khóa bí mật d_i = pow(E, -1, phi_i), với E = 65537.
    
    e. Giải mã ciphertext của vòng lặp này: plaintext_i = pow(ciphertext_i, d_i, n_i).
    
4. **Chuyển tiếp**: plaintext_i vừa tìm được chính là ciphertext cho vòng lặp trước đó (ciphertext_{i-1}). Gán nó làm đầu vào cho vòng lặp tiếp theo.
5. **Lấy Flag**: Sau khi vòng lặp kết thúc (tại i = 0), plaintext_0 thu được chính là giá trị số nguyên của flag ban đầu. Chuyển số này ngược lại thành dạng bytes/string để có được flag.

### **4. Code Thực Thi**

Dưới đây là đoạn code Python hoàn chỉnh để giải bài toán.

```html
import math
from Cryptodome.Util.number import long_to_bytes

def parse_output(filename="outputloopprime.txt"):
    """
    Parses the provided output file to extract the modulus (n) values
    and the final ciphertext (ct).
    """
    ns = {}
    ct = 0
    with open(filename, 'r') as f:
        for line in f:
            parts = line.strip().split(': ')
            key = parts[0]
            value = int(parts[1])
            
            if key.startswith('n'):
                index = int(key.split(' ')[1])
                ns[index] = value
            elif key.startswith('ct'):
                ct = value
                
    # The dictionary is converted to a list to ensure order.
    # It assumes indices are continuous from 0 to 1023.
    return [ns[i] for i in range(len(ns))], ct

def is_perfect_square(n):
    """
    Checks if a number is a perfect square.
    Returns (is_square, sqrt_val).
    """
    if n < 0:
        return False, 0
    h = n & 0xF # last hexadecimal digit
    if h > 9 and h not in {0, 1, 4, 9}:
        return False, 0

    sqrt_n = math.isqrt(n)
    return sqrt_n * sqrt_n == n, sqrt_n

def fermat_factor(n):
    """
    Factors a number n into two primes p and q using Fermat's
    Factorization method. This is efficient when p and q are close.
    """
    if n % 2 == 0:
        return 2, n // 2
        
    a = math.isqrt(n)
    if a * a == n:
        return a, a
        
    a += 1
    
    while True:
        b_squared = a * a - n
        is_sq, b = is_perfect_square(b_squared)
        if is_sq:
            p = a - b
            q = a + b
            return p, q
        a += 1

def main():
    """
    Main function to orchestrate the decryption process.
    """
    E = 65537
    LOOPS = 1024
    
    print("Parsing the output file...")
    try:
        ns, final_ct = parse_output()
    except FileNotFoundError:
        print("Error: output.txt not found. Please place it in the same directory.")
        return
    except Exception as e:
        print(f"An error occurred while parsing the file: {e}")
        return

    print(f"Successfully parsed {len(ns)} modulus values and the final ciphertext.")
    
    # The final ciphertext from the file is the starting point for decryption.
    current_pt = final_ct
    
    # We must decrypt backwards from the last loop (1023) to the first (0).
    for i in range(LOOPS - 1, -1, -1):
        print(f"--- Decrypting loop {i} ---")
        
        n = ns[i]
        
        # 1. Factor n to find p and q
        print(f"Factoring n_{i}...")
        p, q = fermat_factor(n)
        
        if p * q != n:
            print(f"Error: Factorization failed for n_{i}")
            return
            
        # 2. Calculate Euler's totient function, phi(n)
        phi = (p - 1) * (q - 1)
        
        # 3. Calculate the private key d
        d = pow(E, -1, phi)
        
        # 4. Decrypt the ciphertext for this loop
        current_pt = pow(current_pt, d, n)
        
        # --- THIS LINE IS CORRECTED ---
        # Convert the large integer to a string to preview it
        pt_preview = str(current_pt)
        print(f"Decrypted plaintext (ct for loop {i-1}): {pt_preview[:40]}...")

    # 5. Convert the final plaintext (integer) back to bytes to get the flag
    try:
        flag = long_to_bytes(current_pt)
        print("\n" + "="*40)
        print("🎉 Successfully recovered the flag! 🎉")
        print(f"Flag: {flag.decode()}")
        print("="*40)
    except Exception as e:
        print(f"\nCould not decode the final plaintext to a string: {e}")
        print(f"Final plaintext integer: {current_pt}")
        # 3. Calculate the private key d
        d = pow(E, -1, phi)
        
        # 4. Decrypt the ciphertext for this loop
        current_pt = pow(current_pt, d, n)
        print(f"Decrypted plaintext (ciphertext for loop {i-1}): {current_pt:.20s}...")

    # 5. Convert the final plaintext (integer) back to bytes to get the flag
    try:
        flag = long_to_bytes(current_pt)
        print("\n" + "="*40)
        print("🎉 Successfully recovered the flag! 🎉")
        print(f"Flag: {flag.decode()}")
        print("="*40)
    except Exception as e:
        print(f"\nCould not decode the final plaintext to a string: {e}")
        print(f"Final plaintext integer: {current_pt}")

if __name__ == "__main__":
    main()
```

<img width="561" height="221" alt="image" src="https://github.com/user-attachments/assets/285a0fac-7822-4765-b3d9-6c8a2248d192" />
