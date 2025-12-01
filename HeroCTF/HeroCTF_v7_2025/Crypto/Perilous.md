<img width="586" height="726" alt="image" src="https://github.com/user-attachments/assets/552539a0-5707-4ff7-9f96-6e8f78d2b5ee" />

# English Write-Up

## Challenge Analysis

We are provided with the source code `chall.py`1. The server exposes an RC4 encryption service running on port 9001.

Upon inspecting the `encrypt` function in `chall.py`, we see the following operations performed on the input message `m` (which is the Flag)2:

```html
m = xor(m, MASK)            # 1. XOR with Mask
m = encryptor.update(m)     # 2. RC4 Encrypt (XOR with Keystream)
m = xor(m, MASK)            # 3. XOR with Mask again
```

The variable `MASK` is a random byte string generated at the start3.

## Vulnerability: The Canceling Mask

RC4 is a stream cipher, which means encryption is essentially XORing the plaintext with a generated keystream. Let's represent the operations mathematically:

- $P$: Plaintext (Flag)
- $M$: Mask
- $K$: RC4 Keystream (derived from the user-provided key)
- $\oplus$: XOR operation

The encryption flow is:

1. $Temp = P \oplus M$
2. $Cipher_{internal} = Temp \oplus K = (P \oplus M) \oplus K$
3. $Cipher_{final} = Cipher_{internal} \oplus M = (P \oplus M \oplus K) \oplus M$

Since XOR is commutative ($A \oplus B = B \oplus A$) and self-inverse ($A \oplus A = 0$), we can rearrange the equation:

$$Cipher_{final} = P \oplus K \oplus (M \oplus M)$$

$$Cipher_{final} = P \oplus K \oplus 0$$

$$Cipher_{final} = P \oplus K$$

**Conclusion:** The `MASK` operations cancel each other out completely. The server effectively returns the Flag encrypted with standard RC4 using the key we provide.

## Solution

1. Connect to the server.
2. When asked for `flag k`, send a known key (e.g., `00000000`).
3. Receive the hex-encoded ciphertext.
4. Decrypt the ciphertext locally using standard RC4 and the same key `00000000`.

---

# 🇻🇳 Vietnamese Write-Up

## Phân tích

Chúng ta được cung cấp mã nguồn `chall.py`4. Server chạy một dịch vụ mã hóa RC4 trên cổng 9001.

Khi xem xét hàm `encrypt`, ta thấy quy trình xử lý tin nhắn `m` (chính là Flag) như sau5:

1. XOR Flag với một `MASK` ngẫu nhiên.
2. Mã hóa kết quả bằng thuật toán RC4 (thực chất là XOR với Keystream).
3. XOR kết quả một lần nữa với `MASK`.

## Lỗ hổng: MASK tự triệt tiêu

RC4 là một stream cipher, nghĩa là việc mã hóa chỉ đơn giản là XOR bản rõ với một luồng key (Keystream). Hãy viết lại quy trình dưới dạng toán học:

- $P$: Flag (Plaintext)
- $M$: Biến Mask
- $K$: RC4 Keystream (sinh ra từ key người dùng nhập)

Quy trình của server:

$$Cipher = ((P \oplus M) \oplus K) \oplus M$$

Vì phép XOR có tính giao hoán và một số XOR với chính nó bằng 0 ($M \oplus M = 0$), ta có:

$$Cipher = P \oplus K \oplus (M \oplus M)$$

$$Cipher = P \oplus K$$

**Kết luận:** Biến `MASK` hoàn toàn vô dụng. Server thực tế chỉ đang trả về Flag được mã hóa RC4 chuẩn với key do chính chúng ta cung cấp.

## Giải pháp

1. Kết nối tới server.
2. Gửi một key bất kỳ (ví dụ: `00000000`).
3. Nhận chuỗi mã hóa (ciphertext) từ server.
4. Dùng chính key đó để giải mã chuỗi ciphertext ở máy local để lấy Flag.

```html
from pwn import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from binascii import unhexlify

# Configuration
HOST = 'crypto.heroctf.fr'
PORT = 9001

def solve():
    # 1. Connect to server
    r = remote(HOST, PORT)

    # 2. Define a known key (hex string)
    # Using 16 bytes of zeros for simplicity
    my_key_hex = "00" * 16 
    my_key_bytes = unhexlify(my_key_hex)

    # 3. Send the key to get the encrypted flag
    # Server prompt: k = input("flag k: ") 
    r.recvuntil(b"flag k: ")
    r.sendline(my_key_hex.encode())

    # 4. Receive the ciphertext
    encrypted_flag_hex = r.recvline().strip().decode()
    log.info(f"Received Ciphertext: {encrypted_flag_hex}")
    
    encrypted_flag_bytes = unhexlify(encrypted_flag_hex)

    # 5. Local Decryption
    # Since MASK cancels out, we just decrypt standard RC4 with our key.
    algorithm = algorithms.ARC4(my_key_bytes)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    
    flag_bytes = decryptor.update(encrypted_flag_bytes)
    
    # 6. Print Flag
    log.success(f"FLAG FOUND: {flag_bytes.decode(errors='ignore')}")
    r.close()

if __name__ == "__main__":
    solve()
```

<img width="659" height="224" alt="image" src="https://github.com/user-attachments/assets/81fdca5a-4417-4d3d-8ce1-ef28a40667b7" />

