# Sunshine CTF 2025 — Plutonian Crypto

---

**Thể loại:** Cryptography

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách yêu cầu kết nối đến một dịch vụ mạng. Dịch vụ này, sau khi hiển thị một banner, sẽ liên tục gửi các phiên bản mã hóa của cùng một thông điệp bí mật. Tệp `main.py` được cung cấp cho thấy rằng server sử dụng thuật toán AES ở chế độ CTR (Counter Mode). Điểm mấu chốt là mỗi lần mã hóa, giá trị khởi tạo của bộ đếm được tăng lên một. Thử thách cũng cung cấp một phần của thông điệp gốc: "Greetings, Earthlings.", đây là một dạng tấn công bản rõ đã biết (Known-Plaintext Attack).

---

## Mục tiêu

Mục tiêu chính là khai thác việc triển khai chế độ CTR bị lỗi của server để phục hồi lại toàn bộ luồng khóa (keystream) đã được sử dụng. Một khi có được keystream, ta có thể dễ dàng giải mã ciphertext đầu tiên nhận được để tìm ra thông điệp bí mật chứa flag.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Chế độ mã hóa AES-CTR:** Hiểu nguyên lý hoạt động của chế độ Counter, đặc biệt là cách keystream được tạo ra từ Key, Nonce và giá trị của bộ đếm.
- **Tấn công bản rõ đã biết (Known-Plaintext Attack):** Biết cách áp dụng kỹ thuật này trên các mã hóa luồng, nơi việc biết một cặp (plaintext, ciphertext) cho phép phục hồi lại keystream.
- **Thao tác XOR:** Thành thạo các phép toán XOR trên dữ liệu dạng byte.
- **Lập trình mạng (Sockets):** Viết kịch bản Python để kết nối, nhận và xử lý dữ liệu từ server một cách đáng tin cậy.

---

## Phân tích và hướng tiếp cận

Lỗ hổng cốt lõi nằm ở việc server sử dụng lại cặp (Key, Nonce) và chỉ thay đổi giá trị khởi tạo của bộ đếm (`initial_value=C`) theo một cách có thể dự đoán được (tăng dần `C += 1`).

1. **Nguyên lý AES-CTR:**
    - `Ciphertext = Plaintext ⊕ Keystream`
    - `Keystream` được tạo thành từ các khối `K_i = AES_Encrypt(Key, Nonce || Counter_value + i)`.
2. **Lỗ hổng triển khai:**
    - Server gửi nhiều ciphertext: `CT_0, CT_1, CT_2, ...` của cùng một `Plaintext`.
    - `CT_0` (khi `C=0`) được mã hóa bằng keystream bắt đầu từ `K_0, K_1, K_2, ...`
    - `CT_1` (khi `C=1`) được mã hóa bằng keystream bắt đầu từ `K_1, K_2, K_3, ...`
    - `CT_n` (khi `C=n`) được mã hóa bằng keystream bắt đầu từ `K_n, K_{n+1}, ...`
3. **Quy trình tấn công:**
    - Gọi `P_0` là khối plaintext đầu tiên (16 byte). Từ mô tả, ta biết `P_0` là 16 byte đầu của `b"Greetings, Earthlings."`.
    - Khối ciphertext đầu tiên của `CT_n` là `CT_n_block_0`. Ta có mối quan hệ:
    `CT_n_block_0 = P_0 ⊕ K_n`
    - Từ đó, ta có thể tính được khối keystream thứ `n` của luồng khóa ban đầu (luồng khóa đã mã hóa `CT_0`):
    `K_n = CT_n_block_0 ⊕ P_0`
    - Bằng cách thu thập các ciphertext `CT_0, CT_1, ..., CT_35`, chúng ta có thể lần lượt phục hồi các khối keystream `K_0, K_1, ..., K_35`.
    - Sau khi có đủ các khối keystream, ta ghép chúng lại để tạo thành luồng khóa hoàn chỉnh `Keystream_full`.
    - Cuối cùng, giải mã thông điệp bằng cách:
    `Plaintext_full = CT_0 ⊕ Keystream_full`

---

## Kịch bản giải mã (Exploit)

Kịch bản Python dưới đây tự động hóa toàn bộ quá trình: kết nối, xử lý buffer để đọc dữ liệu một cách chính xác, phục hồi keystream, và giải mã thông điệp.

```python
import socket
from binascii import unhexlify
import sys

# --- Cấu hình ---
HOST = "chal.sunshinectf.games"
PORT = 25403
BLOCK_SIZE = 16
# Dựa trên thử nghiệm, 36 ciphertexts là đủ để lấy toàn bộ message
CIPHERTEXTS_TO_COLLECT = 36

# --- Plaintext đã biết ---
known_plaintext_part = b"Greetings, Earthlings."
p0 = known_plaintext_part[:BLOCK_SIZE] # Khối plaintext đầu tiên đã biết

# --- Hàm hỗ trợ ---
def xor(b1, b2):
    """Thực hiện phép XOR trên hai chuỗi byte."""
    return bytes([x ^ y for x, y in zip(b1, b2)])

def solve():
    print(f"[*] Đang kết nối đến {HOST}:{PORT}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            buffer = b''
            # Đọc cho đến khi nhận được tín hiệu bắt đầu truyền tin
            while b"== BEGINNING TRANSMISSION ==\\n\\n" not in buffer:
                buffer += s.recv(1024)

            print("[*] Đã nhận banner, bắt đầu thu thập ciphertext...")

            # Loại bỏ phần banner đã đọc ra khỏi buffer
            start_index = buffer.find(b"== BEGINNING TRANSMISSION ==\\n\\n")
            buffer = buffer[start_index + len(b"== BEGINNING TRANSMISSION ==\\n\\n"):]

            ciphertexts = []
            while len(ciphertexts) < CIPHERTEXTS_TO_COLLECT:
                if b'\\n' in buffer:
                    line, buffer = buffer.split(b'\\n', 1)
                    hex_line = line.strip()
                    if hex_line:
                        ciphertexts.append(unhexlify(hex_line))
                        sys.stdout.write(f"\\r[*] Đã thu thập {len(ciphertexts)}/{CIPHERTEXTS_TO_COLLECT} ciphertexts.")
                        sys.stdout.flush()
                else:
                    more_data = s.recv(4096)
                    if not more_data: break
                    buffer += more_data

            print("\\n[*] Thu thập hoàn tất. Bắt đầu phục hồi keystream...")

            ct_to_decrypt = ciphertexts[0]
            keystream = b''
            for i in range(len(ciphertexts)):
                ct_i_first_block = ciphertexts[i][:BLOCK_SIZE]
                k_i = xor(p0, ct_i_first_block)
                keystream += k_i

            print(f"[*] Đã phục hồi {len(keystream)} bytes keystream.")

            recovered_plaintext = xor(ct_to_decrypt, keystream[:len(ct_to_decrypt)])

            print("\\n" + "="*40)
            print("==> THÔNG ĐIỆP ĐÃ GIẢI MÃ (FLAG):")
            print(recovered_plaintext.decode('utf-8', errors='ignore'))
            print("="*40)

    except Exception as e:
        print(f"\\n[!] Đã xảy ra lỗi không mong muốn: {e}")

if __name__ == "__main__":
    solve()

```

**Kết quả (Flag)**

Khi thực thi kịch bản, nó sẽ kết nối, thu thập 36 dòng ciphertext, tái tạo keystream và giải mã thành công toàn bộ thông điệp, bao gồm cả flag ở cuối.

<img width="1505" height="688" alt="image" src="https://github.com/user-attachments/assets/4766993e-5a57-4821-adbe-2844f3770584" />


`sun{n3v3r_c0unt_0ut_th3_p1ut0ni4ns}`

---

## Ghi chú và mẹo

- Lỗi cơ bản nhất khi sử dụng mã hóa luồng là tái sử dụng keystream. Thử thách này minh họa một biến thể tinh vi hơn, nơi keystream không được tái sử dụng hoàn toàn nhưng có mối quan hệ và có thể dự đoán được, dẫn đến việc nó có thể bị phục hồi hoàn toàn.
- Nguyên tắc vàng của chế độ CTR: **Không bao giờ** sử dụng lại cùng một cặp (Key, Nonce) để mã hóa. Server này đã vi phạm nguyên tắc đó bằng cách mã hóa cùng một thông điệp với các bộ đếm có thể dự đoán được, tạo ra một mối quan hệ chết người giữa các ciphertext.

---

# ENGLISH VERSION

**Category:** Cryptography

**Difficulty:** Easy

---

## Challenge Overview

The challenge requires connecting to a network service. This service, after displaying a banner, continuously sends encrypted versions of the same secret message. The provided `main.py` file reveals that the server uses the AES algorithm in CTR (Counter Mode). The crucial detail is that for each encryption, the initial value of the counter is incremented. The challenge also provides a part of the original message: "Greetings, Earthlings.", setting up a known-plaintext attack scenario.

---

## Objective

The main objective is to exploit the server's flawed implementation of CTR mode to recover the entire keystream used for the encryption. Once the keystream is recovered, we can easily decrypt the first ciphertext received to reveal the full secret message, which contains the flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **AES-CTR Mode:** Understanding the principles of Counter Mode, especially how the keystream is generated from a Key, a Nonce, and the counter's value.
- **Known-Plaintext Attack:** Knowing how to apply this technique to stream ciphers, where knowing a (plaintext, ciphertext) pair allows for keystream recovery.
- **XOR Operation:** Proficiency in performing XOR operations on byte data.
- **Network Programming (Sockets):** Writing a Python script to reliably connect, receive, and process data from a server.

---

## Analysis and Approach

The core vulnerability lies in the server reusing the (Key, Nonce) pair and only predictably altering the counter's initial value (`initial_value=C`) by incrementing it (`C += 1`).

1. **AES-CTR Principles:**
    - `Ciphertext = Plaintext ⊕ Keystream`
    - The `Keystream` is composed of blocks `K_i = AES_Encrypt(Key, Nonce || Counter_value + i)`.
2. **Implementation Flaw:**
    - The server sends multiple ciphertexts: `CT_0, CT_1, CT_2, ...` of the same `Plaintext`.
    - `CT_0` (when `C=0`) is encrypted with a keystream starting from `K_0, K_1, K_2, ...`
    - `CT_1` (when `C=1`) is encrypted with a keystream starting from `K_1, K_2, K_3, ...`
    - `CT_n` (when `C=n`) is encrypted with a keystream starting from `K_n, K_{n+1}, ...`
3. **Attack Process:**
    - Let `P_0` be the first plaintext block (16 bytes). From the description, we know `P_0` is the first 16 bytes of `b"Greetings, Earthlings."`.
    - Let `CT_n_block_0` be the first ciphertext block of `CT_n`. We have the relationship:
    `CT_n_block_0 = P_0 ⊕ K_n`
    - From this, we can calculate the n-th block of the original keystream (the one that encrypted `CT_0`):
    `K_n = CT_n_block_0 ⊕ P_0`
    - By collecting the ciphertexts `CT_0, CT_1, ..., CT_35`, we can successively recover the keystream blocks `K_0, K_1, ..., K_35`.
    - After obtaining enough keystream blocks, we concatenate them to form the full keystream, `Keystream_full`.
    - Finally, we decrypt the message using:
    `Plaintext_full = CT_0 ⊕ Keystream_full`

---

## Exploit Script

The Python script below automates the entire process: connecting, reliably handling the data buffer, recovering the keystream, and decrypting the message.
