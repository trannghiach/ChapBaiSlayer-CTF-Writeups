# QnQSec CTF 2025 - Baby Reverse
- **Category:** Reverse Engineering
- **Tags:** Algorithm Reversal, XOR, Ghidra
- **Author:** LemonTea
- **Solver:** lilsadfoqs
- **Analyst:** Aurelinth

## 1. Challenge Summary

This challenge provides a single binary named `main` and 
asks for a safety check. The goal is to reverse engineer the binary to 
find the correct flag required for a "Correct!" message.

## 2. Initial Analysis & Reconnaissance

1. **File Type & Mitigations:** Running `file main` confirmed an ELF 64-bit executable. `checksec main` showed standard mitigations like `Canary` and `NX`, but no `PIE` (Position Independent Executable), which simplifies static analysis.
2. **Ghidra Decompilation:** Loading the binary into Ghidra and decompiling the `main` function revealed the core logic.
    - User input is read into a buffer (`local_228 + 0x10`).
    - A hardcoded 15-byte string `Th1s_1s_th3_k3y` is initialized at `local_228[0]` to `local_228[0xe]`. This serves as the encryption key.
    - The user input length is checked to be exactly `0x29` (41 characters).
    - A loop iterates 41 times, performing a bitwise `OR` operation to compute `local_24a`:
    `local_24a = local_24a | (encrypted[i] ^ key_string[i % 15] ^ flag_input[i])`
    - The program prints "Correct!" only if `local_24a` is `0` after the loop.

## 3. The Vulnerability

The condition `local_24a == 0` implies that each XOR operation in the loop must result in `0`. This means:
`encrypted[i] ^ key_string[i % 15] ^ flag_input[i] == 0`
This is a simple XOR cipher where `key_string[i % 15]` is the repeating key. The flag can be recovered by inverting the operation:
`flag_input[i] = encrypted[i] ^ key_string[i % 15]`

## 4. Exploitation Steps

1. **Extract Key String:** The hardcoded key bytes were `0x54, 0x68, 0x31, 0x73, 0x5f, 0x31, 0x73, 0x5f, 0x74, 0x68, 0x33, 0x5f, 0x6b, 0x33, 0x79, 0x00`, which translates to `Th1s_1s_th3_k3y` (15 characters, followed by a null byte).
2. **Extract Encrypted Data:** The `encrypted` array, located at `0x00104060`, was dumped from Ghidra:
`[0x05, 0x06, 0x60, 0x20, 0x3a, 0x52, 0x08, 0x0b, 0x1c, 0x01, 0x40, 0x00, 0x5a, 0x40, 0x26, 0x60, 0x06, 0x6e, 0x40, 0x3e, 0x42, 0x0a, 0x00, 0x06, 0x5b, 0x45, 0x6c, 0x19, 0x40, 0x4a, 0x0b, 0x0b, 0x59, 0x47, 0x33, 0x5d, 0x40, 0x31, 0x13, 0x5b, 0x4e]`
3. **Implement Decoder:** A Python script was written to perform the XOR operation using the extracted `encrypted` bytes and `key_string`.

## 5. Final Exploit / Payload

```python
encrypted_bytes = [
    0x05, 0x06, 0x60, 0x20, 0x3a, 0x52, 0x08, 0x0b, 0x1c, 0x01, 0x40, 0x00, 0x5a, 0x40, 0x26,
    0x60, 0x06, 0x6e, 0x40, 0x3e, 0x42, 0x0a, 0x00, 0x06, 0x5b, 0x45, 0x6c, 0x19, 0x40, 0x4a,
    0x0b, 0x0b, 0x59, 0x47, 0x33, 0x5d, 0x40, 0x31, 0x13, 0x5b, 0x4e
]

key_string = b"Th1s_1s_th3_k3y\x00"

flag = []
for i in range(len(encrypted_bytes)):
    flag_char_value = encrypted_bytes[i] ^ key_string[i % 15]
    flag.append(chr(flag_char_value))

print("Flag: " + "".join(flag))

```

**Output Flag:** `QnQSec{This_1s_4n_3asy_r3v3rs3_ch4ll3ng3}`

## 6. Key Takeaways & Lessons Learned

- **Static Analysis:** Ghidra's decompilation is
invaluable for quickly understanding binary logic and identifying key
data structures like hardcoded keys and encrypted arrays.
- **XOR Cipher:** Simple XOR is a common technique in beginner RE challenges. Understanding its reversible property is fundamental.
- **Modular Arithmetic:** The `i % key_length` pattern is crucial for repeating-key ciphers.
- **Data Extraction:** Knowing how to extract raw bytes from the data segment in Ghidra is essential for solving such problems.
