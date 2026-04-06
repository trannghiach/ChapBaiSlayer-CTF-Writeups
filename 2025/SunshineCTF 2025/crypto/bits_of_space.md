# Sunshine CTF 2025 — Bits of Space

---

**Thể loại:** Cryptography

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp cho chúng ta hai tệp: một kịch bản server Python (`relay.py`) và một tệp dữ liệu nhị phân (`voyager.bin`). Server lắng nghe trên một cổng mạng, nhận một gói tin được mã hóa, giải mã nó bằng AES-CBC, và sau đó kiểm tra một trường `device_id` trong dữ liệu đã giải mã. Mục tiêu là lấy được cờ (flag), vốn chỉ được trả về nếu `device_id` khớp với một giá trị bí mật là `0xdeadbabe`. Tệp `voyager.bin` là một gói tin hợp lệ đã được mã hóa cho một thiết bị khác.

---

## Mục tiêu

Mục tiêu chính là khai thác cách hoạt động của chế độ mã hóa AES-CBC để sửa đổi gói tin mã hóa (`voyager.bin`) được cung cấp. Bằng cách thay đổi một cách có chủ đích vector khởi tạo (IV), chúng ta có thể điều khiển kết quả của khối dữ liệu được giải mã đầu tiên, cụ thể là thay đổi `device_id` thành giá trị mục tiêu để server trả về flag.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Chế độ mã hóa AES-CBC:** Hiểu rõ quy trình giải mã của chế độ Cipher Block Chaining (CBC), đặc biệt là mối quan hệ giữa Vector Khởi tạo (IV), khối mã hóa đầu tiên và khối giải mã đầu tiên.
- **Tấn công lật bit CBC (CBC Bit-Flipping Attack):** Nhận biết và áp dụng kỹ thuật tấn công này, trong đó việc thay đổi các bit trong IV sẽ dẫn đến việc lật các bit tương ứng trong khối plaintext đầu tiên sau khi giải mã.
- **Xử lý dữ liệu nhị phân:** Sử dụng một ngôn ngữ lập trình như Python để đọc, phân tích và sửa đổi dữ liệu nhị phân, bao gồm cả việc sử dụng module `struct` để đóng gói/giải nén dữ liệu theo các định dạng cụ thể.
- **Lập trình mạng cơ bản (Sockets):** Viết một kịch bản đơn giản để kết nối đến server, gửi dữ liệu đã sửa đổi và nhận phản hồi.

---

## Phân tích và hướng tiếp cận

Lỗ hổng nằm ở bản chất của chế độ giải mã CBC. Quá trình giải mã cho khối plaintext đầu tiên (`P[0]`) được tính theo công thức:

`P[0] = Decrypt(key, C[0]) XOR IV`

Trong đó `C[0]` là khối ciphertext đầu tiên. Quan trọng là, server không xác thực tính toàn vẹn của ciphertext. Điều này cho phép chúng ta, với vai trò là kẻ tấn công, có thể thay đổi `IV` mà không cần biết khóa (`key`).

1. **Phân tích `relay.py`:**
    - Server đọc dữ liệu, coi 16 byte đầu là `iv` và phần còn lại là `body` (ciphertext).
    - Nó giải mã `body` bằng `iv` và một `key` bí mật.
    - Plaintext sau đó được giải nén bằng `struct.unpack("<IQQI", plaintext)`, nghĩa là 4 byte đầu tiên (little-endian) chính là `device_id`.
    - Nếu `device_id == 0xdeadbabe`, server sẽ gửi flag.
2. **Lên kế hoạch tấn công:**
    - Chúng ta có thể thay đổi `IV` của gói tin `voyager.bin` để tạo ra một `IV_mới`. Khi server giải mã bằng `IV_mới`, khối plaintext mới (`P_mới[0]`) sẽ là:
    `P_mới[0] = Decrypt(key, C[0]) XOR IV_mới`
    - Chúng ta biết rằng `Decrypt(key, C[0])` có thể được biểu diễn dưới dạng `P_gốc[0] XOR IV_gốc`. Thay thế vào công thức trên, ta có:
    `P_mới[0] = (P_gốc[0] XOR IV_gốc) XOR IV_mới`
    - Từ đây, chúng ta có thể tính toán `IV_mới` cần thiết để tạo ra `P_mới[0]` mong muốn:
    `IV_mới = IV_gốc XOR P_gốc[0] XOR P_mới[0]`
    - Chúng ta chỉ cần thay đổi 4 byte đầu tiên (tương ứng với `device_id`), vì vậy `P_gốc[0]` và `P_mới[0]` sẽ chỉ khác nhau ở 4 byte này.
3. **Quy trình giải mã:**
    - Đọc tệp `voyager.bin` để lấy `IV_gốc` (16 byte đầu) và `ciphertext` (phần còn lại).
    - Xác định `device_id_gốc`. Bằng cách gửi `voyager.bin` gốc đến server, ta thấy nó xác thực là "Status Relay", tương ứng với `device_id` là `0x13371337`.
    - `device_id_mục_tiêu` của chúng ta là `0xdeadbabe`.
    - Tính toán sự khác biệt: `diff = device_id_gốc ^ device_id_mục_tiêu`.
    - Tạo một "mặt nạ XOR" bằng cách đóng gói `diff` thành 4 byte little-endian, theo sau là 12 byte null, vì chúng ta không muốn thay đổi các phần khác của khối.
    - Tạo `IV_mới` bằng cách XOR `IV_gốc` với mặt nạ này.
    - Xây dựng gói tin tấn công cuối cùng bằng cách nối `IV_mới` với `ciphertext` gốc.
    - Gửi gói tin này đến server để nhận flag.

---

## Kịch bản giải mã (Exploit)

Kịch bản Python dưới đây tự động hóa toàn bộ quá trình tấn công lật bit CBC.

```python
import socket
import struct

# Thông tin kết nối
HOST = "sunshinectf.games"
PORT = 25401

# ID thiết bị gốc và mục tiêu
# ID gốc được xác định bằng cách gửi voyager.bin không sửa đổi tới server
original_device_id = 0x13371337
target_device_id = 0xdeadbabe  # ID để lấy flag

# Đọc dữ liệu từ file voyager.bin
with open("voyager.bin", "rb") as f:
    voyager_data = f.read()

# Tách IV gốc và ciphertext
iv_original = voyager_data[:16]
ciphertext_body = voyager_data[16:]

# 1. Tính toán sự thay đổi cần thiết cho device_id
# P_new = P_original XOR IV_original XOR IV_new
# Chúng ta muốn thay đổi 4 byte đầu tiên của plaintext.
diff = original_device_id ^ target_device_id

# 2. Tạo mặt nạ XOR cho IV
# Chỉ thay đổi 4 byte đầu (little-endian unsigned int)
xor_mask = struct.pack('<I', diff) + b'\\x00' * 12

# 3. Tạo IV mới bằng cách XOR IV gốc với mặt nạ
iv_target = bytes([b1 ^ b2 for b1, b2 in zip(iv_original, xor_mask)])

# 4. Tạo payload tấn công
payload = iv_target + ciphertext_body

# 5. Gửi payload và nhận flag
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Nhận banner
    s.recv(1024)

    # Gửi payload đã bị sửa đổi
    s.sendall(payload)

    # Nhận và in phản hồi chứa flag
    response = s.recv(4096)
    print(response.decode(errors='ignore'))

```

**Kết quả (Flag)**

Khi thực thi kịch bản, nó sẽ kết nối đến server, gửi gói tin đã được chế tạo cẩn thận và server sẽ phản hồi lại với flag.

`sun{m4yb3_4_ch3ck5um_w0uld_b3_m0r3_53cur3}`

---

## Ghi chú và mẹo

- Đây là một ví dụ kinh điển về tấn công lật bit CBC, một lỗ hổng phổ biến khi chế độ CBC được sử dụng mà không có cơ chế xác thực tính toàn vẹn dữ liệu.
- Lỗ hổng này nhấn mạnh rằng chỉ mã hóa (đảm bảo tính bí mật) là không đủ. Tính toàn vẹn của dữ liệu cũng phải được đảm bảo.
- Các phương pháp phòng chống bao gồm việc sử dụng các chế độ mã hóa đã được xác thực (AEAD) như AES-GCM, hoặc kết hợp mã hóa CBC với một Mã xác thực tin nhắn (MAC), chẳng hạn như HMAC. Bản thân flag cũng gợi ý về điều này ("a checksum would be more secure").

---

# ENGLISH VERSION

**Category:** Cryptography

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides two files: a Python server script (`relay.py`) and a binary data file (`voyager.bin`). The server listens on a network port, accepts an encrypted packet, decrypts it using AES-CBC, and then checks a `device_id` field within the decrypted data. The goal is to obtain the flag, which is only returned if the `device_id` matches the secret value `0xdeadbabe`. The `voyager.bin` file is a valid encrypted packet for a different device.

---

## Objective

The main objective is to exploit the mechanics of the AES-CBC encryption mode to modify the provided encrypted packet (`voyager.bin`). By strategically altering the initialization vector (IV), we can control the outcome of the first decrypted block of data, specifically changing the `device_id` to the target value required by the server to release the flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **AES-CBC Mode:** A clear understanding of the Cipher Block Chaining (CBC) decryption process, particularly the relationship between the Initialization Vector (IV), the first ciphertext block, and the first plaintext block.
- **CBC Bit-Flipping Attack:** Recognizing and applying this attack technique, where modifying bits in the IV results in a predictable flipping of corresponding bits in the first plaintext block after decryption.
- **Binary Data Manipulation:** Using a programming language like Python to read, parse, and modify binary data, including the use of the `struct` module for packing/unpacking data into specific formats.
- **Basic Network Programming (Sockets):** Writing a simple script to connect to the server, send the modified data, and receive the response.

---

## Analysis and Approach

The vulnerability lies in the nature of the CBC decryption mode. The decryption process for the first plaintext block (`P[0]`) is calculated as:

`P[0] = Decrypt(key, C[0]) XOR IV`

Where `C[0]` is the first ciphertext block. Crucially, the server does not verify the integrity of the ciphertext. This allows us, as the attacker, to tamper with the `IV` without needing to know the encryption `key`.

1. **Analyze `relay.py`:**
    - The server reads data, treating the first 16 bytes as the `iv` and the rest as the `body` (ciphertext).
    - It decrypts the `body` using the `iv` and a secret `key`.
    - The resulting plaintext is unpacked using `struct.unpack("<IQQI", plaintext)`, meaning the first 4 bytes (little-endian) are the `device_id`.
    - If `device_id == 0xdeadbabe`, the server sends the flag.
2. **Formulate the Attack Plan:**
    - We can change the `IV` of the `voyager.bin` packet to a new `IV_new`. When the server decrypts with `IV_new`, the new plaintext block (`P_new[0]`) will be:
    `P_new[0] = Decrypt(key, C[0]) XOR IV_new`
    - We know that `Decrypt(key, C[0])` can be expressed as `P_original[0] XOR IV_original`. Substituting this into the equation, we get:
    `P_new[0] = (P_original[0] XOR IV_original) XOR IV_new`
    - From this, we can calculate the required `IV_new` to produce our desired `P_new[0]`:
    `IV_new = IV_original XOR P_original[0] XOR P_new[0]`
    - We only need to change the first 4 bytes (the `device_id`), so `P_original[0]` and `P_new[0]` will only differ in these bytes.
3. **Decoding Process:**
    - Read the `voyager.bin` file to get the `IV_original` (first 16 bytes) and the `ciphertext` (the rest).
    - Determine the `original_device_id`. By sending the original `voyager.bin` to the server, we see it authenticates as "Status Relay," which corresponds to `device_id` `0x13371337`.
    - Our `target_device_id` is `0xdeadbabe`.
    - Calculate the difference: `diff = original_device_id ^ target_device_id`.
    - Create an "XOR mask" by packing `diff` into 4 little-endian bytes, followed by 12 null bytes, since we don't want to alter the rest of the block.
    - Create the `IV_new` by XORing `IV_original` with this mask.
    - Construct the final attack packet by concatenating `IV_new` with the original `ciphertext`.
    - Send this packet to the server to receive the flag.

---

## Exploit Script

The Python script below automates the entire CBC bit-flipping attack process.

```python
import socket
import struct

# Connection details
HOST = "sunshinectf.games"
PORT = 25401

# Original and target device IDs
# Original ID was determined by sending the unmodified voyager.bin to the server
original_device_id = 0x13371337
target_device_id = 0xdeadbabe  # The ID required to get the flag

# Read the provided data file
with open("voyager.bin", "rb") as f:
    voyager_data = f.read()

# Split the original IV from the ciphertext
iv_original = voyager_data[:16]
ciphertext_body = voyager_data[16:]

# 1. Calculate the required change for the device_id
# P_new = P_original XOR IV_original XOR IV_new
# We want to flip bits in the first 4 bytes of the plaintext.
diff = original_device_id ^ target_device_id

# 2. Create the XOR mask for the IV
# We only want to modify the first 4 bytes (little-endian unsigned int)
xor_mask = struct.pack('<I', diff) + b'\\x00' * 12

# 3. Create the new IV by XORing the original IV with the mask
iv_target = bytes([b1 ^ b2 for b1, b2 in zip(iv_original, xor_mask)])

# 4. Construct the final attack payload
payload = iv_target + ciphertext_body

# 5. Send the payload and receive the flag
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Receive banner
    s.recv(1024)

    # Send the tampered payload
    s.sendall(payload)

    # Receive and print the response containing the flag
    response = s.recv(4096)
    print(response.decode(errors='ignore'))

```

**Result (Flag)**

Executing the script connects to the server, sends the crafted packet, and the server responds with the flag.

`sun{m4yb3_4_ch3ck5um_w0uld_b3_m0r3_53cur3}`

---

## Postmortem / Tips

- This is a classic example of a CBC bit-flipping attack, a common vulnerability when CBC mode is used without an integrity-checking mechanism.
- This vulnerability highlights that confidentiality (from encryption) is not enough. The integrity of the data must also be guaranteed.
- Mitigations include using authenticated encryption (AEAD) modes like AES-GCM or combining CBC encryption with a Message Authentication Code (MAC), such as an HMAC. The flag itself hints at this solution ("a checksum would be more secure").
