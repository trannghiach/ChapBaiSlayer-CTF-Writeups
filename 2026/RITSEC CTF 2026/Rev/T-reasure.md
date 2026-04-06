Challenge này thuộc dạng "reverse" cổ điển, cụ thể là phân tích tĩnh thuật toán mã hóa **TEA (Tiny Encryption Algorithm)** và trích xuất khóa (key), dữ liệu mã hóa (ciphertext) từ memory.

### Bước 1: Phân tích ban đầu (Reconnaissance)

Đầu tiên, chúng ta kiểm tra các chuỗi (strings) có trong file binary `treasure`:

```bash
┌──(kali㉿kali)-[~/Downloads]
└─$ strings treasure
...
tiny_encH
rypt_keyH
Try to open the chest!
Maybe try saying the magic word: 
input: %s
result: 0x
%02X
Congrats! Here's your treasure:
Hmmmm.... didn't open...
...
```

Chúng ta ngay lập tức thấy các thông tin quan trọng:

1. **`Congrats!...`**: Dấu hiệu báo thành công nếu nhập đúng flag.
2. **`Hmmmm.... didn't open...`**: Dấu hiệu thất bại.
3. **`tiny_encH rypt_keyH`**: Một chuỗi rất đáng ngờ, có thể là khóa (key) dùng để mã hóa đầu vào.

### Bước 2: Phân tích luồng thực thi (Static Analysis)

Dùng Ghidra/IDA để decompile hàm `main`, chúng ta quan sát cách chương trình xử lý input:

Đoạn mã

```c
  sVar2 = strlen(local_138);
  local_10 = (int)sVar2;
  local_14 = local_10 % 8;
  local_20 = malloc((long)(local_14 + local_10));
  memcpy(local_20,local_138,(long)local_10);
  memset((void *)((long)local_10 + (long)local_20),0,(long)local_14);
  local_10 = local_10 + local_14;
  FUN_004012a9(local_20,local_10,&local_38);
  ...
  if ((local_10 == 0x22) && (iVar1 = memcmp(local_20,&DAT_00404080,0x22), iVar1 == 0)) {
    puts("Congrats! Here\'s your treasure: ");
  }
```

Đây là logic của chương trình:

- **Padding**: Chương trình tính độ dài input, sau đó thêm các byte `0x00` (padding) sao cho tổng độ dài chia hết cho 8 (`local_10 % 8`).
- **Mã hóa**: Gọi hàm mã hóa `FUN_004012a9`.
- **Kiểm tra**: Độ dài tổng sau padding phải bằng **`0x22`** (**34 bytes**). Sau đó dùng `memcmp` để so sánh chuỗi đã mã hóa với vùng nhớ tại `DAT_00404080`.

**Kết luận**: Input (Magic word/Flag) của chúng ta phải dài chính xác **33 ký tự** (33 + 1 byte padding = 34 bytes).

### Bước 3: Xác định thuật toán, Ciphertext và Key

### 1. Thuật toán mã hóa

Kiểm tra sâu vào hàm `FUN_004011c6` (được gọi bên trong `FUN_004012a9`):

Đoạn mã

```c
  for (local_10 = 0; local_10 < 0x20; local_10 = local_10 + 1) {
    local_c = local_c + -0x61c88647;
    local_18 = local_18 + (local_1c * 0x10 + *param_2 ^ local_c + local_1c ^ param_2[1] + (local_1c >> 5));
    local_1c = local_1c + (local_18 * 0x10 + param_2[2] ^ local_c + local_18 ^ param_2[3] + (local_18 >> 5));
  }
```

- Đây chính là thuật toán **TEA (Tiny Encryption Algorithm)**. 
- Vòng lặp chạy `0x20` (32 rounds). Hằng số `-0x61c88647` thực chất là biểu diễn bù 2 của **`0x9E3779B9`** (Delta của thuật toán TEA).

### 2. Ciphertext và Key

- **Ciphertext**: Nhảy đến địa chỉ `DAT_00404080`, chúng ta lấy được 34 bytes dữ liệu:
  `38 75 5b cb 44 d2 be 5d 96 9c 56 43 ea 98 06 75 4a 48 13 e6 d4 e8 8e 4f 72 70 8b ff dc 99 f8 76 c5 c9`
- **Key**: Khóa được truyền vào qua tham số `&local_38`. Ghidra hiển thị `local_38 = 0x636e655f796e6974`. Convert sang dạng Little-Endian ta được chuỗi `"tiny_enc"`. Dựa vào memory và kết hợp với string ban đầu, toàn bộ khóa 128-bit (16 bytes) chính là: **`"tiny_encrypt_key"`**.

### Bước 4: Viết script giải mã (Solve Script)

Chúng ta đã có đủ mảnh ghép. Sử dụng Python để viết script giải mã TEA, đệm thêm byte `0x00` để 34 bytes chia hết cho block 8 bytes (thành 40 bytes).

```python
#!/usr/bin/env python3
import struct

# --- THÔNG TIN ĐÃ XÁC ĐỊNH ---

# 1. 128-bit Key: "tiny_encrypt_key"
KEY = [
    struct.unpack("<I", b"tiny")[0],
    struct.unpack("<I", b"_enc")[0],
    struct.unpack("<I", b"rypt")[0],
    struct.unpack("<I", b"_key")[0]
]

# 2. Ciphertext (34 bytes) + 6 bytes padding
CIPHER_HEX = [
    0x38, 0x75, 0x5b, 0xcb, 0x44, 0xd2, 0xbe, 0x5d,
    0x96, 0x9c, 0x56, 0x43, 0xea, 0x98, 0x06, 0x75,
    0x4a, 0x48, 0x13, 0xe6, 0xd4, 0xe8, 0x8e, 0x4f,
    0x72, 0x70, 0x8b, 0xff, 0xdc, 0x99, 0xf8, 0x76,
    0xc5, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 
]

# --- HÀM GIẢI MÃ TEA ---
def decrypt_tea(v, k):
    v0, v1 = v
    delta = 0x9e3779b9
    sum_val = (delta * 32) & 0xFFFFFFFF
    
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k[2]) ^ (v0 + sum_val) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - (((v1 << 4) + k[0]) ^ (v1 + sum_val) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum_val = (sum_val - delta) & 0xFFFFFFFF
        
    return v0, v1

# --- THỰC THI ---
print("[*] Bắt đầu giải mã...")

cipher_blocks = []
for i in range(0, len(CIPHER_HEX), 8):
    if i + 8 <= len(CIPHER_HEX):
        block_bytes = bytes(CIPHER_HEX[i:i+8])
        cipher_blocks.append(struct.unpack("<II", block_bytes))

decrypted_bytes = bytearray()
for block in cipher_blocks:
    v0, v1 = decrypt_tea(block, KEY)
    decrypted_bytes.extend(struct.pack("<II", v0, v1))

flag = decrypted_bytes.split(b'\x00')[0].decode('ascii', errors='ignore')

print("\n[+] --- KẾT QUẢ ---")
print(f"FLAG/MAGIC WORD: {flag}")
```

```bash
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ python3 solve.py                                        
[*] Bắt đầu giải mã...

[+] --- KẾT QUẢ ---
FLAG/MAGIC WORD: RS{oh_its_a_TEAreasure_chest}
```
