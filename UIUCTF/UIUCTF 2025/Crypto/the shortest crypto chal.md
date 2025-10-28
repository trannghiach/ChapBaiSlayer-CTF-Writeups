a^4+b^4=c^4+d^4+17

Bài này yêu cầu giải 1 phương trình a^4+b^4=c^4+d^4+17

Ý tưởng của bài này như sau : 

- Tìm cách **tính toán hiệu quả tất cả các tổng có dạng x⁴ + y⁴**.
- Lưu lại cặp `(c, d)` sao cho `c⁴ + d⁴ = rhs`
- Với mỗi cặp `(a, b)`, bạn tính `a⁴ + b⁴ - 17` → kiểm tra xem có tồn tại `(c, d)` nào đã lưu khớp với giá trị đó không.

Ta sẽ bruteforce với limit 3000 để tìm ra số thỏa mãn

```html
from Cryptodome.Cipher import AES

# Given ciphertext
ciphertext = bytes.fromhex("41593455378fed8c3bd344827a193bde7ec2044a3f7a3ca6fb77448e9de55155")
LIMIT = 3000  # Adjust based on available compute resources

# Step 1: Precompute fourth powers to avoid repeated exponentiation
fourth = [i**4 for i in range(LIMIT)]

# Step 2: Build all (c,d) pairs such that c^4 + d^4 = val
cd_sums = {}
for c in range(1, LIMIT):
    for d in range(c, LIMIT):  # symmetry: d ≥ c
        val = fourth[c] + fourth[d]
        cd_sums[val] = (c, d)

# Step 3: Try all (a, b) combinations
for a in range(1, LIMIT):
    for b in range(a, LIMIT):
        lhs = fourth[a] + fourth[b]
        rhs_target = lhs - 17
        if rhs_target in cd_sums:
            c, d = cd_sums[rhs_target]
            product = a * b * c * d
            keystr = str(product).zfill(16)
            if len(keystr) != 16:
                continue  # AES key must be exactly 16 bytes
            key = keystr.encode()
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(ciphertext)
            try:
                decoded = pt.decode()
                if decoded.startswith("uiuctf{") and decoded.endswith("}"):
                    print(f"[+] 🎉 Flag found: {decoded}")
                    print(f"[+] 🔑 Key: {keystr}")
                    print(f"[+] 🧮 Params: a={a}, b={b}, c={c}, d={d}")
                    exit()
            except:
                continue
```

Từ đó ta tìm được FLAG thỏa mãn

<img width="427" height="102" alt="image" src="https://github.com/user-attachments/assets/ad9ca972-f943-4a22-9232-c6bba985cc2f" />
