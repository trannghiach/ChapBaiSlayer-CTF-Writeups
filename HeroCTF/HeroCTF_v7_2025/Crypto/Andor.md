<img width="680" height="845" alt="image" src="https://github.com/user-attachments/assets/edb74a8c-6cec-4167-944b-946815f87d99" />

# English Write-Up

## Challenge Analysis

We are provided with the source code `chall.py`. The server runs a loop where it performs bitwise operations on the flag using a random key.

1. **Flag Splitting:** The flag is read from `flag.txt` and split into two equal halves (`l` is the midpoint).
2. **Key Generation:** In each iteration, a random key `k` (same length as the flag) is generated using `secrets.token_bytes`.
3. **Operations:**
    - **Part 1 (`a`):** Calculated using **AND** (`&`) between the first half of the flag and the first half of the key.
    - **Part 2 (`o`):** Calculated using **IOR** (`|`) between the second half of the flag and the second half of the key.

## Solution Strategy

### Part 1: Recovering the AND (`a = flag & key`)

- **Logic:** $0 \land x = 0$ and $1 \land x = x$.
- If a bit in the flag is `0`, the result is always `0`.
- If a bit in the flag is `1`, the result will be `1` if the random key bit is `1`, and `0` if the key bit is `0`.
- **Strategy:** Over many iterations, if the flag bit is `1`, we will eventually see a `1` from the random key. We can recover the original bits by taking the **Bitwise OR** of all received `a` values.

### Part 2: Recovering the OR (`o = flag | key`)

- **Logic:** $1 \lor x = 1$ and $0 \lor x = x$.
- If a bit in the flag is `1`, the result is always `1`.
- If a bit in the flag is `0`, the result will be `0` if the random key bit is `0`, and `1` if the key bit is `1`.
- **Strategy:** The random key introduces "noise" (random 1s). We want to find the bits that are *always* `0`. We can recover the original bits by taking the **Bitwise AND** of all received `o` values to filter out the random 1s.

---

# 🇻🇳 Vietnamese Write-Up

## Phân tích

Chúng ta được cung cấp source code `chall.py`. Server chạy một vòng lặp vô hạn, thực hiện các phép toán bit (bitwise) lên flag với một key ngẫu nhiên.

1. **Chia Flag:** Flag được đọc từ file và chia làm 2 phần bằng nhau.
2. **Sinh Key:** Mỗi lần lặp, server tạo một key `k` ngẫu nhiên có độ dài bằng flag.
3. **Phép toán:**
    - **Phần 1 (`a`):** Là kết quả của phép **AND** (`&`) giữa nửa đầu flag và nửa đầu key.
    - **Phần 2 (`o`):** Là kết quả của phép **OR** (`|`) giữa nửa sau flag và nửa sau key.

## Chiến thuật giải

### Phần 1: Khôi phục phép AND (`a = flag & key`)

- **Logic:** Nếu bit của flag là `1`, kết quả sẽ phụ thuộc vào key ngẫu nhiên. Nếu bit của flag là `0`, kết quả luôn là `0`.
- **Chiến thuật:** Chỉ cần key xuất hiện bit `1` tại vị trí tương ứng thì ta sẽ thu được bit `1`. Vì key là ngẫu nhiên, sau nhiều lần thử, ta chắc chắn sẽ thu được tất cả các bit `1` của flag.
- **Hành động:** Thực hiện phép **Bitwise OR** tất cả các mẫu `a` nhận được để "gộp" các bit 1 lại.

### Phần 2: Khôi phục phép OR (`o = flag | key`)

- **Logic:** Phép OR với key ngẫu nhiên sẽ thêm các bit `1` "rác" vào kết quả. Tuy nhiên, nếu bit gốc của flag là `0`, thì thỉnh thoảng kết quả sẽ là `0` (khi key tại đó cũng là 0).
- **Chiến thuật:** Ta cần loại bỏ các bit `1` do key tạo ra.
- **Hành động:** Thực hiện phép **Bitwise AND** tất cả các mẫu `o` nhận được. Các bit `1` ngẫu nhiên của key sẽ bị triệt tiêu bởi các lần xuất hiện bit `0`, để lộ ra flag gốc.

---

# 🚀 Solver Script (End-to-End)
```html
from pwn import *
from binascii import unhexlify

# Configuration
HOST = 'crypto.heroctf.fr'
PORT = 9000

def solve():
    # Connect to the server
    r = remote(HOST, PORT)
    
    # Store the accumulated results
    part1_accumulator = None
    part2_accumulator = None
    
    # Number of samples to collect (50-100 is usually sufficient)
    iterations = 100
    log.info(f"Collecting {iterations} samples...")

    for i in range(iterations):
        try:
            # Parse output from server
            r.recvuntil(b"a = ")
            a_hex = r.recvline().strip().decode()
            r.recvuntil(b"o = ")
            o_hex = r.recvline().strip().decode()
            
            a_bytes = bytearray(unhexlify(a_hex))
            o_bytes = bytearray(unhexlify(o_hex))
            
            # --- LOGIC PART 1 (AND -> Recover via OR) ---
            if part1_accumulator is None:
                part1_accumulator = a_bytes
            else:
                # Accumulate 1s: result |= new_sample
                for idx, b in enumerate(a_bytes):
                    part1_accumulator[idx] |= b

            # --- LOGIC PART 2 (OR -> Recover via AND) ---
            if part2_accumulator is None:
                part2_accumulator = o_bytes
            else:
                # Eliminate random 1s: result &= new_sample
                for idx, b in enumerate(o_bytes):
                    part2_accumulator[idx] &= b
            
            # Send dummy input to trigger next loop
            r.sendline(b"1")
            
        except Exception as e:
            log.warning(f"Stopped at iteration {i}: {e}")
            break

    # Combine parts
    full_flag = part1_accumulator + part2_accumulator
    log.success(f"Flag recovered: {full_flag.decode(errors='ignore')}")
    r.close()

if __name__ == "__main__":
    solve()
```

<img width="644" height="275" alt="image" src="https://github.com/user-attachments/assets/9ef8e1c4-2710-4343-9e42-a27d80072c9a" />
