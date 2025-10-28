# EnigmaXplore 3.0 — Clockwork

## Metadata

- Challenge: Clockwork
- Author: unknown
- Category: Reverse
- Difficulty: 100
- Event: EnigmaXplore 3.0
- Solver: lilsadfoqs
- Analyst: Aurelinth
- Target: local ELF x86_64 PIE (clockwork_pieces)
- Date: 2025-10-11

---

## Executive summary

Chương trình hỏi một "key" 8-byte phụ thuộc `time()` và in "Try harder."; tuy nhiên flag không nằm trên luồng kiểm tra key. Flag được lưu dưới dạng một blob 26 bytes trong `.data`, và có một chuỗi hàm độc lập (`FUN_001015b0` load blob → `FUN_00101380` decrypt → `FUN_00101670` print) có nhiệm vụ giải mã và in flag. Vì những hàm này không được `main` gọi, cách ngắn nhất để có flag là gọi trực tiếp hàm in flag (địa chỉ `0x1670` trong binary) trong GDB — hàm sẽ load, giải mã và in flag.

---

## Scope & preconditions

- Môi trường: CTF lab, binary `clockwork_pieces` được phép phân tích.
- Không cần network hay credentials.
- Binary: ELF 64-bit, PIE, stripped.

---

## Recon / initial observations

- `file` và `strings` cho thấy thông báo: "Try harder.", "Enter key:", "Invalid key".
- Ghidra/objdump reveal:
    - Hàm chính (entry) bắt `time()` và xây một vector thời gian dùng cho kiểm tra key.
    - `FUN_00101460`: một transform nibble-based trên 0x32 bytes trên stack.
    - `FUN_001014c0`: kiểm tra key — chỉ chấp nhận input length == 8 và so sánh 8 bytes với giá trị được tạo từ constants và `time()`.
    - Có chuỗi hàm `FUN_001015b0`, `FUN_00101380`, `FUN_00101670` thực hiện: load blob 26 bytes → decrypt (XOR + bit shifts) → print bytes bằng `putc`.
- Kết luận reconnaissance: luồng hiển thị flag không thông qua kiểm tra key — ta cần gọi chuỗi hàm in flag hoặc tái tạo thuật toán decrypt offline.

---

## Vulnerability / Design note

**Không phải lỗ hổng dạng crash/exploit** — đây là thiết kế challenge: tác giả để luồng chính (nhập key) là mồi nhử; flag ẩn trong hàm không gọi. Vì binary stripped và PIE, cần tính base address runtime hoặc disable ASLR trong GDB để gọi hàm trực tiếp.

---

## Exploitation — full chain (cách ngắn nhất, GDB)

**Mục tiêu:** gọi trực tiếp hàm in flag `FUN_00101670`.

1. Chuẩn bị GDB:
    
    ```bash
    gdb ./clockwork_pieces
    (gdb) starti
    
    ```
    
    `starti` giúp chương trình load và dừng ngay sau `_start` => ta biết mapping memory.
    
2. Xem mappings để tìm base address của binary (ví dụ `0x555555554000` trong ví dụ):
    
    ```
    (gdb) info proc mappings
    
    ```
    
3. Tính địa chỉ thực của hàm in flag: `real = base + 0x1670` (địa chỉ hàm trong disassembly). Đặt breakpoint an toàn (tùy ý) trước chỗ in hoặc dừng ở entry; ví dụ đặt breakpoint trước `fgets` để chương trình dừng tới prompt:
    
    ```
    (gdb) set $base = 0x555555554000
    (gdb) b *($base + 0x1206)  # optional, để dừng trước fgets
    (gdb) c
    
    ```
    
4. Khi chương trình dừng (an toàn), gọi hàm in flag trực tiếp:
    
    ```
    (gdb) call ((void(*)())($base + 0x1670))()
    
    ```
    
    Hàm sẽ tự gọi `FUN_001015b0` (load blob), `FUN_00101380` (decrypt) và in flag ra stdout.
    
  <img width="590" height="347" alt="image" src="https://github.com/user-attachments/assets/4a6256b3-ca0a-4ac8-997f-a44a57c908f9" />

    
5. Kết quả in ra (ví dụ): `EnXp{5CR3W_TH3_4WN_4UTH0R}`.

**Lưu ý:** Hàm in flag tự thực hiện tất cả bước load/giải mã; không cần thay đổi bộ nhớ chương trình hay truyền input.

---

## Artifacts

- Flag: `EnXp{5CR3W_TH3_4WN_4UTH0R}`
- Binary: `clockwork_pieces` (ELF64 PIE, stripped).
- Disassembly pointers: entry ~0x1140, transform ~0x1460, checker ~0x14c0, loader ~0x15b0, decryptor ~0x1380, printer ~0x1670.

---

## Appendix — PoC script (offline decrypt)

Dưới đây là script Python tái tạo thuật toán `FUN_001015b0` + `FUN_00101380` để giải blob offline mà không cần GDB.

```python
# decrypt_clockwork.py
buf = [0x6C,0xF8,0x1C,0x75,0x19,0x81,0x47,0x80,0x0E,0x21,0xF5,0xCD,0xCA,0x10,0x12,0x4A,0x05,0x63,0x4E,0x3E,0x91,0x79,0x40,0x95,0x1D,0x91]
key = [0x29,0x4B,0x11,0x05,0x31,0x2D,0x04,0x69,0x4F,0x76,0x55,0x66,0x82,0x91,0x53,0x7E]

def apply_pass(b, key, r9):
    out = []
    keylen = len(key)
    for i, x in enumerate(b):
        k = key[i % keylen]
        pos = i % 3
        if r9 == 1:
            shift = 8 - pos
            val = (k >> shift) & 0xFF
        else:
            shift = pos
            val = ((k << shift) & 0xFF)
        out.append(x ^ val)
    return out

# first pass: r9 = 1 (right-shift)
tmp = apply_pass(buf, key, 1)
# second pass: r9 = 0 (left-shift)
plain = apply_pass(tmp, key, 0)

print(bytes(plain).decode('utf-8', errors='replace'))

```

Chạy `python3 decrypt_clockwork.py` sẽ in ra `EnXp{5CR3W_TH3_4WN_4UTH0R}`.

---

*Writeup kết thúc.*

---

# ENGLISH VERSION

# Writeup — Clockwork (EnigmaXplore)

## Metadata

- Challenge: Clockwork
- Category: Reverse Engineering
- Difficulty: 100
- Event: EnigmaXplore 3.0
- Solver: Anh (user)
- Analyst: Aurelinth
- Target: ELF x86_64 PIE (clockwork_pieces)
- Date: 2025-10-11

---

## Executive Summary

The binary asks for an 8-byte "key" derived from `time()` and prints "Try harder."; however, the actual flag is **not** tied to the key verification path. Instead, a hidden function chain (`FUN_001015b0` → `FUN_00101380` → `FUN_00101670`) loads an encrypted blob, decrypts it, and prints the flag. These functions are never called from `main()`. The fastest method to retrieve the flag is to directly invoke the print function (at address `0x1670`) using GDB.

---

## Environment & Preconditions

- Context: Local CTF reverse challenge
- Binary: `clockwork_pieces`, ELF64 PIE, stripped
- Tools used: GDB, objdump, Ghidra

---

## Initial Analysis

- `strings` output: "Try harder.", "Enter key:", "Invalid key"
- Disassembly and decompilation show:
    - `main()` uses `time()` and builds a vector used to check an 8-byte key.
    - `FUN_001014c0` validates the key — correct key only prints “Try harder.” again.
    - Separate chain (`FUN_001015b0`, `FUN_00101380`, `FUN_00101670`) decrypts and prints a hidden blob.

These latter functions form the **real flag path**, isolated from the main logic.

---

## Design Note

Not a vulnerability — a deliberate misdirection by the challenge author. The main logic distracts solvers into wasting time brute-forcing a key. The actual decryption and flag printing reside in unreachable code.

---

## Exploitation — Fastest GDB Method

### Goal:

Invoke the hidden flag printer `FUN_00101670` directly.

### Steps

1. Start the program under GDB:

```bash
gdb ./clockwork_pieces
(gdb) starti

```

1. Find the base address:

```
(gdb) info proc mappings

```

Example: base = `0x555555554000`

1. Optionally set a breakpoint before `fgets` (for safety):

```
(gdb) set $base = 0x555555554000
(gdb) b *($base + 0x1206)
(gdb) c

```

1. When stopped, call the flag printer:

```
(gdb) call ((void(*)())($base + 0x1670))()

```

This triggers the hidden chain: load blob → decrypt → print flag.

### Output

```
EnXp{5CR3W_TH3_4WN_4UTH0R}

```

---

## Artifacts

- Flag: `EnXp{5CR3W_TH3_4WN_4UTH0R}`
- Binary: `clockwork_pieces`
- Functions: entry (~0x1140), transform (~0x1460), key check (~0x14c0), blob loader (~0x15b0), decryptor (~0x1380), printer (~0x1670)

---

## Recommendations (for challenge authors)

- If intentional: leave as-is — perfect misdirection challenge.
- If unintended (in production code): remove or protect dead functions containing sensitive data.
- Never hardcode secrets or decryption routines inside distributed binaries.

---

## Appendix — Offline Python Decryptor

Below is the reimplementation of `FUN_001015b0` + `FUN_00101380` for local flag recovery:

```python
# decrypt_clockwork.py
buf = [0x6C,0xF8,0x1C,0x75,0x19,0x81,0x47,0x80,0x0E,0x21,0xF5,0xCD,0xCA,0x10,0x12,0x4A,0x05,0x63,0x4E,0x3E,0x91,0x79,0x40,0x95,0x1D,0x91]
key = [0x29,0x4B,0x11,0x05,0x31,0x2D,0x04,0x69,0x4F,0x76,0x55,0x66,0x82,0x91,0x53,0x7E]

def apply_pass(b, key, r9):
    out = []
    keylen = len(key)
    for i, x in enumerate(b):
        k = key[i % keylen]
        pos = i % 3
        if r9 == 1:
            shift = 8 - pos
            val = (k >> shift) & 0xFF
        else:
            shift = pos
            val = ((k << shift) & 0xFF)
        out.append(x ^ val)
    return out

tmp = apply_pass(buf, key, 1)
plain = apply_pass(tmp, key, 0)
print(bytes(plain).decode('utf-8', errors='replace'))

```

Running the script prints the same flag: `EnXp{5CR3W_TH3_4WN_4UTH0R}`.

---

*End of writeup.*
