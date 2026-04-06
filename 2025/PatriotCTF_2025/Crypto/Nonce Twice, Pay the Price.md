### *Challenge — ECDSA Nonce Reuse Key Recovery & Decryption*

---

# 🇬🇧 **English Version**

## **1. Challenge Overview**

We are given:

- A public key `pub.pem`
- Two ECDSA signatures `sig1.txt` and `sig2.txt`
- An encrypted blob `secret_blob.bin`

The hint says the service **reused the same ECDSA nonce**.

Nonce-reuse in ECDSA is catastrophic because it leaks the **private key**.

The mission:

1. Recover the private key from the two signatures.
2. Use it to decrypt the secret blob and obtain the flag.

---

## **2. Why ECDSA Nonce Reuse Is Fatal**

For ECDSA over curve order nnn:

A signature on hash hhh is:

s=k−1(h+d⋅r)(modn)s = k^{-1}(h + d \cdot r) \pmod{n}

s=k−1(h+d⋅r)(modn)

Where:

- ddd = private key
- kkk = nonce
- rrr = signature component

If two signatures reuse the same nonce kkk, they share the **same rrr**:

s1=k−1(h1+dr)s2=k−1(h2+dr)\begin{aligned}
s_1 &= k^{-1}(h_1 + d r) \\
s_2 &= k^{-1}(h_2 + d r)
\end{aligned}

s1s2=k−1(h1+dr)=k−1(h2+dr)

Subtracting:

s1−s2=k−1(h1−h2)s_1 - s_2 = k^{-1}(h_1 - h_2)

s1−s2=k−1(h1−h2)

This gives:

k=(h1−h2)⋅(s1−s2)−1(modn)k = (h_1 - h_2)\cdot (s_1 - s_2)^{-1} \pmod{n}

k=(h1−h2)⋅(s1−s2)−1(modn)

Then solve for private key:

d=(s1k−h1)⋅r−1(modn)d = (s_1 k - h_1)\cdot r^{-1} \pmod{n}

d=(s1k−h1)⋅r−1(modn)

This fully recovers the secret key.

---

## **3. Extracting Signature Values**

Both signatures had **identical r**, confirming nonce reuse.

The values taken from `sig1.txt` and `sig2.txt` give us r,s1,s2,h1,h2r, s_1, s_2, h_1, h_2r,s1,s2,h1,h2.

---

## **4. Computing k and d**

```python
k = ((h1 - h2) * pow((s1 - s2) % n, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n
```

Recovered private key:

```
d = 0x3d5d238dfd8ccd1472cd22f80e22ae57e9ad79d779f4630930efb5cc21977ce7
```

We validated this key by regenerating the public key and comparing it to `pub.pem`:

→ **Perfect match** ✔️

---

## **5. Decrypting the Encrypted Blob**

The challenge encrypts data using:

```
keystream_block_i = SHA256(key || i.to_bytes(4, 'big'))
ciphertext = plaintext XOR keystream
```

This is effectively a **CTR-like hash stream cipher** built from SHA-256.

We replicate the keystream and XOR with the blob.

---

## **6. Full Exploit Script (one file)**

```python
#!/usr/bin/env python3
import hashlib

def parse_sig_file(path):
    lines = open(path).read().splitlines()
    vals = {}
    for line in lines:
        line = line.strip()
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        vals[k.strip()] = v.strip()
    return vals

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

v1 = parse_sig_file("sig1.txt")
v2 = parse_sig_file("sig2.txt")

r  = int(v1["r"], 16)
s1 = int(v1["s"], 16)
s2 = int(v2["s"], 16)
h1 = int(v1["msg_hash"], 16)
h2 = int(v2["msg_hash"], 16)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

k = ((h1 - h2) * pow((s1 - s2) % n, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n

print("[+] k =", hex(k))
print("[+] d =", hex(d))

key = d.to_bytes(32, "big")
data = open("secret_blob.bin", "rb").read()

ks = b""
i = 0
while len(ks) < len(data):
    ks += hashlib.sha256(key + i.to_bytes(4, "big")).digest()
    i += 1
ks = ks[:len(data)]

pt = xor_bytes(data, ks)

print("[+] Plaintext:")
print(pt.decode(errors="ignore"))
```

Output:

```
pctf{ecdsa_n0nc3_r3us7e_get!s_y0u8_0wn1ed}
```

---

## **7. Final Flag**

```
pctf{ecdsa_n0nc3_r3us7e_get!s_y0u8_0wn1ed}
```

---

# 🇻🇳 **Vietnamese Version**

## **1. Tổng quan bài**

Challenge cho:

- Public key `pub.pem`
- 2 chữ ký ECDSA `sig1.txt`, `sig2.txt`
- File mã hóa `secret_blob.bin`

Gợi ý cho biết service **dùng lại một nonce ECDSA**.

Nếu 2 chữ ký dùng chung nonce, private key sẽ bị lộ hoàn toàn.

Mục tiêu:

1. Recover private key từ 2 chữ ký bị reuse nonce
2. Giải mã file `secret_blob.bin` để lấy flag

---

## **2. Vì sao reuse nonce làm lộ private key?**

Công thức chữ ký ECDSA:

s=k−1(h+dr)(modn)s = k^{-1}(h + d r) \pmod{n}

s=k−1(h+dr)(modn)

Nếu hai chữ ký có **cùng r** → cùng nonce kkk:

s1=k−1(h1+dr)s2=k−1(h2+dr)\begin{aligned}
s_1 &= k^{-1}(h_1 + d r) \\
s_2 &= k^{-1}(h_2 + d r)
\end{aligned}

s1s2=k−1(h1+dr)=k−1(h2+dr)

Lấy hiệu:

s1−s2=k−1(h1−h2)s_1 - s_2 = k^{-1}(h_1 - h_2)

s1−s2=k−1(h1−h2)

Suy ra:

k=(h1−h2)⋅(s1−s2)−1(modn)k = (h_1 - h_2)\cdot (s_1 - s_2)^{-1} \pmod{n}

k=(h1−h2)⋅(s1−s2)−1(modn)

Sau đó:

d=(s1k−h1)⋅r−1(modn)d = (s_1k - h_1)\cdot r^{-1} \pmod{n}

d=(s1k−h1)⋅r−1(modn)

Thế là lộ private key.

---

## **3. Lấy dữ liệu chữ ký**

Từ file `sig1.txt` và `sig2.txt` lấy được:

- r giống nhau
- s1, s2 khác nhau
- hash message khác nhau

→ Xác nhận reuse nonce.

---

## **4. Tính nonce k và private key d**

```python
k = ((h1 - h2) * pow((s1 - s2) % n, -1, n)) % n
d = ((s1 * k - h1) * pow(r, -1, n)) % n
```

Private key thu được:

```
0x3d5d238dfd8ccd1472cd22f80e22ae57e9ad79d779f4630930efb5cc21977ce7
```

Check lại public key → **trùng khớp**.

---

## **5. Giải mã secret_blob.bin**

Service dùng một kiểu mã hóa tùy chỉnh:

```
keystream_i = SHA256(key || i)
ciphertext = plaintext XOR keystream
```

Chỉ cần:

- Generate lại keystream bằng SHA256
- XOR với ciphertext
    
    → Flag hiện ra.
    

---

## **6. Script hoàn chỉnh**

(đã đưa ở bản tiếng Anh)

Chạy xong:

```
pctf{ecdsa_n0nc3_r3us7e_get!s_y0u8_0wn1ed}
```

---
