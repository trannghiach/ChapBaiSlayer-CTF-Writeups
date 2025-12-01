# **1. Challenge Overview**

The challenge presents a “five-layer bank vault” implemented using a *vibe-coded* hashing function.

Despite being branded as “unhackable”, each layer contains a structural weakness that can be exploited with controlled input length, bcrypt truncation behavior, or modulo arithmetic.

The full challenge logic was provided in `vibe_vault.py`.

---

# **2. The Core Vulnerability: Broken Hash Function**

The server defines:

```python
_STATIC_SALT = b"$2b$12$C8YQMlqDyz3vGN9VOGBeGu"

def vibe_hash(data):
    payload = data.encode()
    portion = payload[: len(payload) % 256]
    digest = bcrypt.hashpw(portion, _STATIC_SALT)
    return "vb$1$" + base64.b64encode(digest).decode()

```

Two critical issues:

---

## **2.1. Modulo-based truncation**

`portion = payload[: len(payload) % 256]`

Meaning:

- If `len(payload) % 256 == 0` → `portion = b""`
- Small changes in input length drastically change what gets hashed.
- This creates an enormous attack surface for collisions.

---

## **2.2. bcrypt truncates input to 72 bytes**

Even if `portion` is huge, bcrypt internally uses only the first **72 bytes**.

This makes bcrypt effectively a 72-byte hash here, enabling small brute-forces and controlled-collision attacks.

---

# **3. Exploits by Layer**

---

# **Layer 1 – Brute-forcing 2 Unknown Bytes**

The server leaks:

- The first **70 characters** of a 72-byte bcrypt password.
- The final 2 characters are from `[A-Za-z0–9]` → total 62×62 = **3844** possibilities.

Offline attack:

```
Try all 3844 combinations:
bcrypt(leaked70 + a + b) == target_hash ?

```

Because bcrypt uses **static salt**, the hash is fully deterministic, so brute-forcing is feasible (< 0.5s optimized).

---

# **Layer 2 – Making Two Different Strings Hash Identically**

Server shows random prefix:

`vibe_abcd123_`

You must produce two *different* strings beginning with that prefix that hash to the same value.

Trick:

Make both strings exactly **256 bytes long**.

Because `len % 256 == 0`:

```
portion = payload[:0] = b""

```

Thus both hash bcrypt(empty), regardless of actual content.

Solution:

```
s1 = prefix + "A" * (256 - len(prefix))
s2 = prefix + "B" * (256 - len(prefix))

```

---

# **Layer 3 – Matching a Long B-String’s Hash**

Admin password:

```
"B" * target_len   where target_len ∈ [300, 500]

```

Large input (length > 256) means:

```
portion = payload[: target_len - 256]

```

We can simply send:

```
"B" * (target_len - 256)

```

This produces the same `portion` → same hash.

---

# **Layer 4 – UTF-8 Emoji Truncation**

Target password:

```
pad_len × "C"  +  emoji_count × "🔥"

```

Facts:

- `"🔥"` is **4 bytes** in UTF-8.
- bcrypt uses only first 72 bytes.

We choose number of emojis K so that:

```
pad_len + 4*K = 72

```

Then our string matches the exact bcrypt portion.

Solution:

```
payload = "C" * pad_len + "🔥" * K

```

---

# **Layer 5 – Bypassing the Admin Bcrypt via Length Modulo Collision**

Admin’s internal password:

```
admin_pw = prefix + ("X" * random_length)

```

Depending on:

```
r = total_length % 256

```

the hashed portion is:

- empty (`r == 0`)
- prefix substring (`r <= len(prefix)`)
- prefix + some “X”s (`r > len(prefix)`)

We compute our own payload so that:

```
(len(prefix) + len(our_input)) % 256 == r

```

and our portion matches the admin’s portion exactly.

This yields:

```
vibe_hash(our_payload) == vibe_hash(admin_payload)

```

We pass the final layer and get the flag.

---

# **4. Final Result**

We used:

- deterministic bcrypt salt,
- modulo-truncation misdesign,
- UTF-8 length control,
- bcrypt’s 72-byte limit,

to fully break all five layers.

---

# 🟩 **WRITEUP — VIỆT NGỮ**

## **Tổng quan**

Đề bài mô phỏng một “két sắt 5 lớp” dùng một hàm hash tự chế – `vibe_hash`.

Thực chất hệ thống cực kỳ dễ vỡ vì:

- Dùng modulo độ dài để chọn phần cần hash
- bcrypt chỉ dùng 72 byte đầu
- Salt cố định
- Nhiều tầng phụ thuộc vào độ dài input

Từ đó dẫn đến hàng loạt collision predictable.

---

# **1. Lỗ hổng chính: `vibe_hash` sai thiết kế**

```python
portion = payload[: len(payload) % 256]
digest = bcrypt.hashpw(portion, STATIC_SALT)

```

**Sai lầm:**

### (1) Nếu `len % 256 == 0` → portion = rỗng → hash = bcrypt("")

→ Collision rất dễ.

### (2) bcrypt truncate về 72 byte

→ Nhiều input rất dài thực ra hash như nhau.

---

# **2. Giải từng tầng**

---

## **Layer 1 – brute 3844 trường hợp**

Server leak:

- 70 ký tự đầu
- Còn 2 ký tự từ `[A-Za-z0-9]`

→ tổng cộng 62×62 = 3844 → brute offline trong <1s.

So sánh trực tiếp digest:

```
bcrypt(leak70 + a + b) == raw_digest ?

```

---

## **Layer 2 – tạo collision bằng độ dài 256**

Nếu:

```
len(payload) % 256 == 0

```

→ portion = rỗng → mọi input dài 256 đều hash giống nhau.

Chỉ cần:

```
string1 = prefix + "A" * pad
string2 = prefix + "B" * pad

```

---

## **Layer 3 – tái tạo portion của admin**

Admin password cực dài `"B"*N`.

Do modulo:

```
portion = "B" * (N - 256)

```

Ta chỉ cần gửi chính chuỗi này.

---

## **Layer 4 – tính toán số emoji để vừa 72 byte**

Emoji `"🔥"` dài 4 byte → chọn K sao cho:

```
pad_len + 4*K = 72

```

Gửi:

```
"C"*pad_len + "🔥"*K

```

---

## **Layer 5 – collision theo (total_len % 256)**

Admin hash phụ thuộc vào:

```
r = total_len % 256

```

Dựa vào r, portion của admin là:

- r = 0 → portion=""
- r ≤ len(prefix) → portion = prefix[:r]
- r > len(prefix) → prefix + X*(r-P)

Ta chọn input sao cho:

```
(len(prefix) + len(my_input)) % 256 = r

```

→ portion của ta giống admin → hash bằng nhau.

```html
#!/usr/bin/env python3
import socket
import base64
import bcrypt
import string
import re

# --------------------------------------------------
#  vibe_hash y hệt file challenge
# --------------------------------------------------

_STATIC_SALT = b"$2b$12$C8YQMlqDyz3vGN9VOGBeGu"

def vibe_hash(data: str) -> str:
    payload = data.encode("utf-8")
    portion = payload[: len(payload) % 256]
    digest = bcrypt.hashpw(portion, _STATIC_SALT)
    return "vb$1$" + base64.b64encode(digest).decode()

# --------------------------------------------------
#  helper recv & send
# --------------------------------------------------

def recv_until(sock, marker: str) -> str:
    data = b""
    m = marker.encode()
    while m not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="ignore")

def sendline(sock, s: str):
    sock.sendall((s + "\n").encode())

# --------------------------------------------------
#  Level 1: brute 2 ký tự cuối (3844 case)
#  Tối ưu: so sánh trực tiếp digest, có in progress
# --------------------------------------------------

def solve_level1(leaked70: str, target_hash: str) -> str:
    print("[*] Level 1: brute-forcing 2 missing chars (max 3844 tries)")

    # target_hash = "vb$1$<base64(bcrypt_digest)>"
    b64_part = target_hash.split("$", 2)[2]
    raw_target = base64.b64decode(b64_part)

    alph = string.ascii_letters + string.digits
    prefix_bytes = leaked70.encode()

    cnt = 0
    for a in alph:
        for b in alph:
            cand_bytes = prefix_bytes + a.encode() + b.encode()  # 72 bytes
            digest = bcrypt.hashpw(cand_bytes, _STATIC_SALT)
            cnt += 1
            if cnt % 200 == 0:
                print(f"    ... tried {cnt} candidates")
            if digest == raw_target:
                pw = leaked70 + a + b
                print(f"[+] Level 1 solved after {cnt} tries: {pw}")
                return pw

    raise RuntimeError("[-] Level 1 brute failed (unexpected).")

# --------------------------------------------------
#  Main exploit
# --------------------------------------------------

def main():
    HOST = "18.212.136.134"
    PORT = 6666

    s = socket.socket()
    s.connect((HOST, PORT))

    # ==========================
    # Level 1
    # ==========================
    banner = recv_until(s, "Enter password:")
    print(banner)

    leaked = re.search(r"Leaked Note:\s*([A-Za-z0-9]{70})", banner).group(1)
    target_hash = re.search(r"Target Hash:\s*(vb\$1\$[A-Za-z0-9+/=]+)", banner).group(1)

    lvl1_pw = solve_level1(leaked, target_hash)
    sendline(s, lvl1_pw)

    # ==========================
    # Level 2
    # ==========================
    out2 = recv_until(s, "Format: string1,string2")
    print(out2)

    prefix = re.search(r"prefix: '([^']+)'", out2).group(1)
    P = len(prefix)

    pad = 256 - P
    s1 = prefix + "A" * pad
    s2 = prefix + "B" * pad
    pair = f"{s1},{s2}"

    print(f"[+] Level 2: using two strings of length 256 (portion empty)")
    sendline(s, pair)

    # ==========================
    # Level 3
    # ==========================
    out3 = recv_until(s, "Enter the equivalent password:")
    print(out3)

    target_len = int(re.search(r"very long \((\d+) 'B's\)", out3).group(1))
    m = target_len - 256
    payload3 = "B" * m
    print(f"[+] Level 3: target_len={target_len}, sending {m} 'B's")
    sendline(s, payload3)

    # ==========================
    # Level 4
    # ==========================
    out4 = recv_until(s, "Enter password:")
    print(out4)

    pad_len = int(re.search(r"target password is: (\d+) 'C's", out4).group(1))
    # bcrypt chỉ lấy 72 byte đầu → chọn K sao cho pad_len + 4*K = 72
    K = (72 - pad_len) // 4
    payload4 = "C" * pad_len + "🔥" * K

    print(f"[+] Level 4: pad_len={pad_len}, K={K}, total bytes={len(payload4.encode())}")
    sendline(s, payload4)

    # ==========================
    # Level 5
    # ==========================
    out5 = recv_until(s, "Input your password:")
    print(out5)

    admin_pw_len = int(
        re.search(r"SecretPassword: (\d+) 'X' characters\.", out5).group(1)
    )
    total_len = int(re.search(r"Total Length = (\d+) bytes\.", out5).group(1))

    print(f"[+] Level 5: admin_pw_len={admin_pw_len}, total_len={total_len}")

    prefix_admin = "XCORP_VAULT_ADMIN"
    P = len(prefix_admin)
    T = total_len

    if T < 256:
        # Case 1: portion_admin = full string, bcrypt dùng 72 byte đầu = prefix + 55 'X'
        user_input = "X" * 55
        print("[+] Level 5 Case 1 (T < 256): using 55 'X'")
    else:
        # Case 2: portion_admin = first r bytes, r = T % 256
        r = T % 256
        if r == 0:
            # portion_admin = b"" ⇒ ta cũng làm length %256 == 0
            n = 256 - P
            user_input = "X" * n
            print(f"[+] Level 5 Case 2 (r=0): using {n} 'X'")
        elif r <= P:
            # portion_admin = prefix_admin[:r]
            n = r - P + 256
            user_input = "X" * n
            print(f"[+] Level 5 Case 2 (r <= P): r={r}, using {n} 'X'")
        else:
            # r > P ⇒ portion_admin = prefix_admin + "X"*(r-P)
            k = r - P
            user_input = "X" * k
            print(f"[+] Level 5 Case 2 (r > P): r={r}, using {k} 'X'")

    sendline(s, user_input)

    # ==========================
    # Nhận FLAG
    # ==========================
    chunks = []
    while True:
        try:
            chunk = s.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)

    final_out = b"".join(chunks).decode("utf-8", errors="ignore")
    print("\n================= FINAL OUTPUT =================")
    print(final_out)
    print("================================================")

    s.close()

if __name__ == "__main__":
    main()
```

```html
[🏆] CONGRATULATIONS! You have completely compromised the Vibe Bank!
[*] Here is your reward: PCTF{g00d_v1b3s_b4d_3ntropy_sync72_b4ck1ng}
[*] Kevin has been fired.

================================================

```
