# Sunshine CTF 2025 — Pluto Chat

**Thể loại:** Reverse Engineering / Forensics

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Bài đưa cho chúng ta một binary **`plutochat`** (ứng dụng chat giả lập) và một file **`evidence.pcap`** ghi lại các gói tin giữa client và server. Server đã bị tắt, nhiệm vụ là phân tích cơ chế mã hóa trong binary và từ đó giải mã các gói tin để tìm ra flag.

---

## Mục tiêu

Mục tiêu chính:

- Phân tích binary để hiểu cơ chế mã hóa.
- Viết script giải mã payload trong pcap.
- Trích xuất thông điệp ẩn (flag) từ nội dung chat.

---

## Kiến thức cần thiết

- **Reverse Engineering ELF**: Sử dụng Ghidra hoặc IDA để đọc hàm, nhận diện hàm mã hóa.
- **Cryptography basics**: Nhận diện mẫu thuật toán stream cipher (RC4).
- **Forensics**: Dùng Wireshark/tshark/scapy để trích xuất payload TCP từ pcap.
- **Python scripting**: Viết lại thuật toán mã hóa, dùng để giải gói tin.

---

## Phân tích và hướng tiếp cận

1. **Quan sát binary**
    - Binary kết nối tới `127.0.0.1:31337`.
    - Các hàm chính:
        - `FUN_00101510`: sinh key 0x50 bytes từ một seed (4 byte đầu gói tin).
        - `FUN_00101389`: thực hiện RC4 KSA.
        - `FUN_001012e5`: thực hiện RC4 PRGA sinh keystream.
        - `FUN_00101452`: XOR dữ liệu với keystream.
            
            → Toàn bộ cơ chế là một **RC4 custom**.
            
2. **Định dạng gói tin** (theo code trong `FUN_00101ac6`):
    - Bytes 0–3: seed (little-endian).
    - Bytes 4–7: length.
    - Phần còn lại: ciphertext.
3. **Giải mã**
    - Lấy seed, sinh key theo hàm `FUN_00101510` (gồm rotate, hoán đổi bằng bảng `DAT_00104100`, và whitening bằng bảng `DAT_00104120`).
    - Dùng RC4 (KSA + PRGA) để tạo keystream.
    - XOR với payload để ra plaintext.

---

## Script giải mã (Exploit)

```python
#!/usr/bin/env python3
from scapy.all import rdpcap, TCP, Raw

def rol32(v, r):
    r &= 0x1F
    return ((v << r) & 0xffffffff) | (v >> (32-r))

DAT_104100 = [0x0d,0x08,0x11,0x0c,0x0e,0x07,0x00,0x05,
              0x09,0x04,0x0b,0x10,0x06,0x12,0x0a,0x01,
              0x02,0x03,0x0f,0x13]

# trích từ .rodata
DAT_104120 = bytes([...])  # copy đầy đủ từ binary

def make_key(seed):
    vals=[]
    val=seed
    for i in range(0x14):
        vals.append(val)
        val=rol32(val, val & 0xf)
    key=bytearray()
    for v in vals:
        key.extend(v.to_bytes(4,'little'))
    for idx in range(0x14):
        j=DAT_104100[idx]
        off_i,off_j=idx*4,j*4
        key[off_i:off_i+4],key[off_j:off_j+4]=key[off_j:off_j+4],key[off_i:off_i+4]
    prev=0
    for i in range(0x50):
        key[i]=DAT_104120[key[i]] ^ prev
        prev=key[i]
    return key

def rc4crypt(data, key):
    s=list(range(256)); j=0
    for i in range(256):
        j=(j+s[i]+key[i%len(key)])&0xff
        s[i],s[j]=s[j],s[i]
    i=j=0; out=bytearray()
    for b in data:
        i=(i+1)&0xff
        j=(j+s[i])&0xff
        s[i],s[j]=s[j],s[i]
        k=s[(s[i]+s[j])&0xff]
        out.append(b^k)
    return bytes(out)

pkts=rdpcap("evidence.pcap")
for p in pkts:
    if TCP in p and Raw in p:
        buf=bytes(p[Raw].load)
        if len(buf)>=8:
            seed=int.from_bytes(buf[:4],'little')
            length=int.from_bytes(buf[4:8],'little')
            pt=rc4crypt(buf[8:8+length], make_key(seed))
            print(seed, length, pt)

```

---

## Kết quả (Flag)

Giải mã cho ra đoạn hội thoại:

```
topsecretengineer: Hey can you give me that sensitive key you were talking about?
givemethemoney: Of course! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}

```

👉 Flag:

`sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}`

---

## Ghi chú & mẹo

- Binary bị strip nhưng vẫn có thể khôi phục thuật toán từ pattern RC4 (KSA/PRGA rất dễ nhận diện).
- Đừng chỉ dừng ở XOR một byte, hãy tìm các cấu trúc keystream.
- Đây là một ví dụ điển hình của “Security through obscurity” → đúng như flag.

---

# ENGLISH VERSION

**Category:** Reverse Engineering / Forensics

**Difficulty:** Medium

---

## Challenge Overview

We are given a binary **`plutochat`** (a chat client) and a packet capture **`evidence.pcap`**. The server is offline, and our task is to reverse engineer the binary to figure out the custom encryption and then decrypt the recorded packets to recover the hidden flag.

---

## Objective

- Reverse engineer the binary to identify the encryption scheme.
- Write a script to decrypt the packets.
- Extract the secret flag from the chat conversation.

---

## Required Knowledge

- **ELF reverse engineering** (Ghidra/IDA).
- **Cryptography basics**, recognizing RC4 patterns.
- **Forensics tools** (Wireshark/scapy) to parse PCAP payloads.
- **Python scripting** to reimplement the cipher and decode the data.

---

## Analysis & Approach

- The binary connects to `127.0.0.1:31337`.
- Functions identified:
    - `FUN_00101510`: builds a 0x50-byte key from a 4-byte seed.
    - `FUN_00101389`: RC4 key scheduling.
    - `FUN_001012e5`: RC4 PRGA.
    - `FUN_00101452`: XOR with keystream.
- Packet format:
    - First 4 bytes: seed (LE).
    - Next 4 bytes: payload length.
    - Rest: ciphertext.

Thus, PlutoChat uses a **custom RC4 variant** with a strange key derivation step, but otherwise standard RC4.

---

## Exploit Script

*(see Python code above)*

---

## Result (Flag)

Decrypted conversation reveals:

```
topsecretengineer: Hey can you give me that sensitive key you were talking about?
givemethemoney: Of course! It's: sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}

```

✅ Flag:

`sun{S3cur1ty_thr0ugh_Obscur1ty_1s_B4D}`

---

## Notes / Tips

- Even stripped binaries can reveal crypto by recognizing algorithmic patterns (RC4 loops are very distinctive).
- When encountering weird XOR-like traffic, check for stream ciphers with PRGA.
- The flag itself emphasizes the lesson: relying on obscure custom crypto is not real security.
