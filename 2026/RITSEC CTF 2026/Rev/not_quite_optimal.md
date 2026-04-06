# CTF Writeup: Reverse Engineering - `not_quite_optimal`

## Tổng Quan
* **Tên tệp:** `not_quite_optimal`
* **Thể loại:** Reverse Engineering (Dịch ngược mã nhị phân C)
* **Mục tiêu:** Vượt qua các lớp kiểm tra chuỗi đầu vào đầu chương trình, phân tích thuật toán giải mã bị cố tình làm chậm/ngốn tài nguyên, và viết lại một thuật toán tối ưu để lấy cờ (flag) thành công.

---

## Phân Tích Chi Tiết Hành Trình

### Bước 1: Mở Khóa Cuộc Trò Chuyện (Magic Strings)
Khi mở tệp nhị phân bằng công cụ dịch ngược, ta thấy hàm khởi chạy (`main`/entry) hoạt động như một cuộc hội thoại. Để chương trình tiến vào phần in flag, ta phải thỏa mãn 3 lần kiểm tra đầu vào. 

**Dẫn chứng từ mã C (Hàm Main):**
```c
// Lần 1: Kiểm tra mã Hex
if (((local_230 == 0x2065687420726f66 && local_238 == 0x20676e696b6f6f6c) &&
    (local_228 == 0x67616c66)) && (local_224 == '\0')) {
    // ...
    // Lần 2: So sánh trực tiếp
    iVar2 = strcmp((char *)&local_238,"please");
    if (iVar2 == 0) {
        // ...
        // Lần 3: So sánh trực tiếp để nhận cờ thật
        iVar2 = strcmp((char *)&local_238,"PLEASE MAY I HAVE THE FLAG");
```

1. **Lần 1 - So sánh mã Hex:** Chương trình kiểm tra 3 hằng số nguyên. Vì kiến trúc máy tính là Little-Endian, ta dịch các giá trị hex này ra ký tự ASCII và đọc ngược lại, thu được chuỗi: `looking for the flag`.
2. **Lần 2 & 3 - So sánh trực tiếp (`strcmp`):** Chương trình so sánh đầu vào tiếp theo với chuỗi `please` và `PLEASE MAY I HAVE THE FLAG`. Nếu nhập sai ở bước 3, chương trình sẽ nhả ra một flag giả đánh lừa người chơi.

### Bước 2: Bẫy Thời Gian (`nanosleep`)
Sau khi nhập đúng 3 chuỗi, chương trình tiến vào vòng lặp 84 lần (`while (iVar4 != 0x54)`) gọi hàm `FUN_00101800` để sinh ra từng ký tự của flag. Tuy nhiên, nó chạy cực kỳ chậm.

**Dẫn chứng từ mã C (Hàm `FUN_00101800`):**
```c
// param_1 là thứ tự của ký tự đang được in (từ 0 đến 83)
local_58.tv_sec = 0;
local_58.tv_nsec = (long)(param_1 * 300) * 1000000;
nanosleep(&local_58,&local_48);
```
* Thời gian delay được tính bằng: `chỉ số ký tự * 300ms` (300,000,000 nano giây).
* Điều này khiến việc in toàn bộ flag mất tới hơn 17 phút, dễ làm cạn kiệt timeout của máy chủ.
* *Thử nghiệm:* Có thể dùng thủ thuật `LD_PRELOAD` để đè một hàm `nanosleep` rỗng nhằm bỏ qua thời gian chờ, nhưng hệ thống vẫn báo lỗi (`zsh: killed`) ở ký tự `u`. Điều này chứng tỏ vẫn còn một cái bẫy thứ hai.

### Bước 3: Bẫy Toán Học (Tháp Lũy Thừa & Tràn RAM)
Nguyên nhân gây tràn RAM nằm ở hàm giải mã cốt lõi `FUN_001015f0`. Hàm này sử dụng thư viện **GMP** chuyên tính toán số cực lớn (BigInt).

**Dẫn chứng từ mã C (Hàm `FUN_001015f0`):**
```c
// 1. Gọi đệ quy chính nó để tính tầng lũy thừa tiếp theo
FUN_001015f0(auStack_78,param_2,param_3 + -1); 

// ...
// 2. Vòng lặp lũy thừa nhanh (Exponentiation by squaring)
while (0 < local_44) {
    if ((*local_40 & 1) != 0) {
        __gmpz_mul(param_1,param_1,local_58);
    }
    __gmpz_fdiv_q_2exp(local_48,local_48,1); // Chia 2 số mũ
    if (local_44 < 1) break;
    __gmpz_mul(local_58,local_58,local_58);
}

// ...
// 3. Phép Toán Lấy Ký Tự
lVar2 = __gmpz_fdiv_ui(param_1,0x100); // Lấy modulo 256 (0x100)
uVar3 = lVar2 + 1U >> 1;               // Cộng 1 và dịch phải 1 bit (chia 2)
```

* Thuật toán bên trong sử dụng đệ quy lồng ghép với vòng lặp thuật toán lũy thừa nhanh. Bản chất toán học của nó là tính **Tetration (Tháp lũy thừa)**: `Cơ số ^ Cơ số ^ ... (Chiều cao lần)`.
* Máy tính sẽ cố gắng sinh ra một con số dài hàng triệu chữ số và lưu vào RAM, dẫn đến cạn kiệt bộ nhớ (OOM - Out of Memory) ở ký tự thứ 21.
* Sau khi tính xong con số khổng lồ, nó chỉ làm một việc đơn giản là `Modulo 256` (`__gmpz_fdiv_ui`) và áp dụng công thức dịch bit để ra mã ASCII thật: `char = (Kết_quả_Mod_256 + 1) >> 1`.

### Bước 4: Giải Pháp Tối Ưu (Định Lý Euler)
Do chương trình chỉ cần lấy phần dư cho 256, ta không cần bắt máy tính tính ra con số khổng lồ kia. Ta có thể áp dụng **Định lý Euler** kết hợp hàm Totient (Phi Euler) để thu nhỏ số mũ trong phép tháp lũy thừa Modulo. Thuật toán này giúp tính ra kết quả chỉ trong tích tắc mà không tốn dung lượng RAM.

Thông số đầu vào (Cơ số và Chiều cao) của từng ký tự được lưu trữ dưới dạng mảng 16-byte tại địa chỉ `DAT_001022a0`. Ta chỉ cần trích xuất khối dữ liệu này từ Ghidra và dùng script Python để giải.

---

## Mã Nguồn Giải Quyết (Solver Script)

Dưới đây là mã Python đọc trực tiếp dữ liệu thô từ phần mềm dịch ngược và áp dụng thuật toán Tetration Modulo:

```python
import re
import math

# 1. Dán toàn bộ khối dữ liệu Hex copy từ Ghidra (DAT_001022a0 - 001027df)
raw_data = """
        001022a0 3b              ??         3Bh    ;
        001022a1 c8              ??         C8h
        ... [Dữ liệu bị rút gọn trong writeup] ...
        001027df 00              ??         00h
"""

# 2. Trích xuất và định dạng dữ liệu byte (Little-Endian)
byte_hexes = re.findall(r'[0-9a-fA-F]{8}\s+([0-9a-fA-F]{2})\s+\?\?', raw_data)
byte_vals = [int(b, 16) for b in byte_hexes]

long_ints = []
for i in range(0, len(byte_vals), 8):
    val = sum(byte_vals[i+j] << (j * 8) for j in range(8))
    long_ints.append(val)

data_pairs = [(long_ints[i], long_ints[i+1]) for i in range(0, len(long_ints), 2)]

# 3. Thuật toán tối ưu tính Tháp lũy thừa Modulo
def phi(n):
    amount = 0
    for k in range(1, n + 1):
        if math.gcd(n, k) == 1:
            amount += 1
    return amount

def tetration_mod(a, n, m):
    if m == 1: return 0
    if n == 0: return 1
    if n == 1: return a % m
    if n == 2: return pow(a, a, m)
    
    # Áp dụng định lý Euler
    phi_m = phi(m)
    exponent = tetration_mod(a, n - 1, phi_m) + phi_m
    return pow(a, exponent, m)

# 4. In cờ bằng công thức: (Modulo_256 + 1) >> 1
flag = ""
for base, height in data_pairs:
    raw_mod = tetration_mod(base, height, 256)
    char_code = (raw_mod + 1) >> 1
    flag += chr(char_code)

print("\nFlag:", flag)
```

```bash
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ python3 solve.py                                        
Flag: RS{4_littl3_bi7_0f_numb3r_th30ry_n3v3r_hur7_4ny0n3_19b3369a25c78095689a38f81aa3f5e3}
```