## TL;DR

- **Phần 1:** Khôi phục seed của một “LCG kiểu RSA” từ vài tham số rò rỉ → tạo khóa AES-ECB → giải mã ra tiền tố flag: `v1t{Pseud0_R4nd0m_G3ner4t0r`.
- **Phần 2:** Đảo một phép biến đổi byte (prefix-XOR + bit-scramble tuyến tính) → lấy hậu tố: `_1s_n0t_th4t_h4rd}`.
- Ghép lại được **flag hoàn chỉnh**.

---

## Cho sẵn (từ mã đề)

- `part1.py` in ra:
    - `enc` (ciphertext AES-ECB),
    - các tham số `a, c, m`,
    - và một giá trị từ `lcg.next()` (đã bị cắt bớt bit thấp).
- `part2.py` mã hóa chuỗi bằng:
    1. **prefix-XOR**: `x[i] ^= x[i-1]` (với `i>0`),
    2. **bit-scramble**:
        
        ```
        v ^= (v >> 4); v ^= (v >> 3); v ^= (v >> 2); v ^= (v >> 1)
        ```
        
    - Code của đề in ra chuỗi hex cuối.

---

## Phần 1 — “LCG kiểu RSA” + AES

### Ý tưởng

Bộ phát sinh `LCG` không phải dạng tuyến tính chuẩn `a*s + c`, mà cập nhật theo **lũy thừa** (dùng số mũ 65537 giống RSA):

```
new_state ≡ a * seed^65537 + c   (mod m)
```

- `m` là số nguyên tố lớn ⇒ nhóm nhân modulo `m` có bậc `m-1`.
- Hàm mũ `seed ↦ seed^65537` **nghịch đảo được** vì `gcd(65537, m-1) = 1`.

Đề **rò rỉ** `lcg.next()` nhưng **cắt mất 20 bit thấp** (hoặc tương đương: nó là `new_state >> 20`).

⇒ Biết được toàn bộ **phần cao** của `new_state`, chỉ **20 bit thấp** chưa biết. Ta vét cạn 2^20 khả năng.

### Khôi phục seed

Với mỗi ứng viên `new_state`:

```
X  = (new_state - c) * a^{-1} mod m
d  = 65537^{-1} mod (m-1)
seed = X^d mod m
```

- Ràng buộc hợp lệ: seed do đề sinh là 50-bit ⇒ `seed < 2^50`.
- Kiểm tra ngược: tính lại `check = (a*seed^65537 + c) % m` phải **đúng bằng** `new_state`.

Khi tìm được `seed`, đề dùng `key = SHA256(seed)` để **AES-ECB decrypt** `enc`.

Kết quả thu được **tiền tố flag**:

```
v1t{Pseud0_R4nd0m_G3ner4t0r
```

> (Bạn có log chạy của mình: AES-ECB(dec(enc)) = b'v1t{Pseud0_R4nd0m_G3ner4t0r'.)
> 

### Mã mẫu (khôi phục seed + giải AES)

```python
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import binascii

def invmod(a, m): return pow(a, -1, m)

def recover_seed(a, c, m, leak_hi):  # leak_hi = new_state >> 20
    a_inv = invmod(a, m)
    d = invmod(65537, m-1)
    base = leak_hi << 20
    for low in range(1<<20):
        new_state = base | low
        X = ((new_state - c) * a_inv) % m
        seed = pow(X, d, m)
        if seed < (1<<50):
            if (a * pow(seed, 65537, m) + c) % m == new_state:
                return seed
    return None

def aes_ecb_decrypt(enc_hex, key_bytes):
    ct = binascii.unhexlify(enc_hex)
    return unpad(AES.new(key_bytes, AES.MODE_ECB).decrypt(ct), 16)

# DỮ LIỆU ví dụ in trong part1.py
enc_hex = "e6979fb9c93ede1e85bbeb51224969da271fae19054d01e16b7a538f69f48c7a"
a = 958181900694223
c = 1044984108221161
m = 675709840048419795804542182249
leak_hi = 176787694147066159797379  # lcg.next()

seed = recover_seed(a,c,m,leak_hi)
key  = sha256(long_to_bytes(seed)).digest()
pt   = aes_ecb_decrypt(enc_hex, key)
print(pt.decode())  # -> v1t{Pseud0_R4nd0m_G3ner4t0r
```

---

## Phần 2 — Đảo prefix-XOR + bit-scramble

### Ý tưởng

Mã hóa mỗi byte gồm 2 bước:

1. **Prefix-XOR**: `t[0]=p[0]`, `t[i]=p[i]^p[i-1]`.
2. **Bit-scramble**: một ánh xạ tuyến tính trên 8 bit:
    
    ```
    f(v) = v ^ (v>>4) ^ (v>>3) ^ (v>>2) ^ (v>>1)
    ```
    
    Vì là tuyến tính (GF(2)) trên không gian 8-bit, `f` **song ánh** ⇒ có **nghịch đảo**.
    
    Ta có thể **tiền tính** `inv_f` bằng brute-force 0..255.
    

### Giải mã

- Gọi `y[i] = f(t[i])` là byte mã (đọc từ chuỗi hex đề cho).
- Lấy `z[i] = inv_f(y[i])`.
- Khôi phục:
    - `p[0] = z[0]`
    - `p[i] = z[i] ^ p[i-1]` (đảo lại prefix-XOR).

Kết quả là **hậu tố**: `"_1s_n0t_th4t_h4rd}"`.

### Mã mẫu (đảo part2)

```python
import binascii

def f(v):
    v &= 0xFF
    v ^= (v >> 4); v &= 0xFF
    v ^= (v >> 3); v &= 0xFF
    v ^= (v >> 2); v &= 0xFF
    v ^= (v >> 1); v &= 0xFF
    return v

# tiền tính nghịch đảo
INV = {f(x): x for x in range(256)}

def decrypt_part2(hexstr):
    data = binascii.unhexlify(hexstr)
    z = [INV[b] for b in data]       # đảo f
    p = bytearray(len(z))
    for i, w in enumerate(z):
        p[i] = w if i == 0 else (w ^ p[i-1])  # đảo prefix-XOR
    return bytes(p)

# ví dụ: hex do đề in trong part2.py (của bạn là phần đuôi của flag)
hex_enc = "6768107b1a357132741539783d6a661b5f3b"
print(decrypt_part2(hex_enc).decode())  # -> _1s_n0t_th4t_h4rd
```

---

## Ghép flag

Tiền tố (Phần 1) + hậu tố (Phần 2):
```
v1t{Pseud0_R4nd0m_G3ner4t0r_1s_n0t_th4t_h4rd}

```
