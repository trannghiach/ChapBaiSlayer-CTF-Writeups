# Sunshine CTF 2025 — Warp

**Thể loại:** Reverse / eBPF

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Thử thách cung cấp một binary `warp` (static PIE, Rust) nạp một **eBPF ELF object** và gắn chương trình XDP. Do môi trường không có quyền BPF, khi chạy sẽ lỗi tạo map ring buffer `rb`. Tuy nhiên, bên trong eBPF có sẵn dữ liệu và thuật toán so khớp payload — ta có thể **phân tích tĩnh** để khôi phục flag mà không cần chạy trong kernel.

---

## Mục tiêu

Trích xuất flag định dạng `sun{...}` bằng cách:

- Xác định vị trí bytes liên quan trong `.rodata` của eBPF.
- Áp dụng đúng phép biến đổi byte theo logic trong `xdp_prog`.
- Ghép chuỗi kết quả để thu được flag.

---

## Kiến thức cần thiết

- **ELF/eBPF cơ bản:** biết đọc section `.rodata`, `xdp`, `.maps`.
- **Disassembly/Decompile eBPF:** nắm cách diễn giải lệnh và so sánh trường header mạng.
- **Python ngắn:** đọc file nhị phân theo offset và biến đổi từng byte.

---

## Phân tích và hướng tiếp cận

Chương trình XDP:

1. Kiểm tra khung Ethernet/IPv4, protocol TCP/UDP.
2. Yêu cầu payload bắt đầu bằng 4 byte `"W4rp"`.
3. Rồi so sánh **30 byte** tiếp theo của payload với một mảng `expected` được tính từ `.rodata` bằng phép biến đổi per-byte:
    - Với mỗi byte `r` từ `.rodata`:
        
        ```
        t  = r ^ 0x60
        ts = (int8)t      # xét như signed 8-bit
        if ts > 0x20:
            out = ((ts + 0x0e) % 0x5e) + 0x21
        else:
            out = t
        
        ```
        
    - `out` là byte kỳ vọng. Vòng lặp chạy 0x1e (30) lần.

Từ `readelf -S ebpf_blob.o`, `.rodata` nằm ở offset file `0x0d00`. Ciphertext cần decode bắt đầu tại **`.rodata + 0x10`** và dài **`0x1e`** byte.

---

## Kịch bản giải mã (Exploit)

Script Python tối giản, tái tạo đúng phép biến đổi và in flag:

```python
# solve.py
with open("ebpf_blob.o","rb") as f:
    f.seek(0x0d00 + 0x10)   # .rodata + 0x10
    b = f.read(0x1e)        # 30 bytes

def dec_byte(r):
    t = r ^ 0x60
    ts = t if t < 0x80 else t - 0x100
    return ((ts + 0x0e) % 0x5e) + 0x21 if ts > 0x20 else (t & 0xff)

print(bytes(dec_byte(x) for x in b).decode())

```

> Ghi chú: nếu objcopy không hỗ trợ elf64-bpf, cách seek theo offset như trên là ổn định nhất.
> 

---

## Kết quả (Flag)

Khi thực thi kịch bản với `ebpf_blob.o`, kết quả thu được:

`sun{n0n_gp1_BPF_code_g0_brrrr}`

---

## Ghi chú và mẹo

- Không cần chạy eBPF trong kernel nếu có thể phân tích tĩnh — đặc biệt hữu ích khi gặp lỗi quyền `memlock`/`CAP_BPF`.
- Luôn đối chiếu **độ dài** từ code (0x1e) và **offset** từ `readelf -S` để tránh lỗi off-by-one (dẫn tới thừa/mất ký tự).
- Chú ý **signedness**: điều kiện dùng `signed char` ảnh hưởng trực tiếp kết quả phép biến đổi.

---

# ENGLISH VERSION

**Category:** Reverse / eBPF

**Difficulty:** Medium

---

## Challenge Overview

The `warp` binary embeds an **eBPF ELF object** and attempts to attach an XDP program. Running without BPF privileges fails at map creation for the ring buffer `rb`. The XDP program, however, already contains the data and the per-byte transform to validate payload — allowing a **static** solution without kernel execution.

---

## Objective

Recover the `sun{...}` flag by:

- Locating the relevant bytes in the eBPF `.rodata`.
- Applying the exact per-byte transform implemented by `xdp_prog`.
- Concatenating the decoded bytes to obtain the flag.

---

## Required Knowledge

- **ELF/eBPF basics:** reading `.rodata`, `xdp`, `.maps`.
- **eBPF disassembly/decompile:** understanding header checks and bytewise comparisons.
- **Short Python script:** reading binary by offset and transforming bytes.

---

## Analysis and Approach

The XDP program:

1. Verifies Ethernet/IPv4 and TCP/UDP.
2. Requires the payload to start with `"W4rp"`.
3. Compares the next **30 bytes** with an `expected` array computed from `.rodata` using this transform per byte:

```
t  = r ^ 0x60
ts = (int8)t
if ts > 0x20:
    out = ((ts + 0x0e) % 0x5e) + 0x21
else:
    out = t

```

From `readelf -S ebpf_blob.o`, `.rodata` is at file offset `0x0d00`. The ciphertext to decode begins at **`.rodata + 0x10`** and has length **`0x1e`** bytes.

---

## Exploit Script

Minimal Python to reproduce the transform and print the flag:

```python
# solve.py
with open("ebpf_blob.o","rb") as f:
    f.seek(0x0d00 + 0x10)   # .rodata + 0x10
    b = f.read(0x1e)        # 30 bytes

def dec_byte(r):
    t = r ^ 0x60
    ts = t if t < 0x80 else t - 0x100
    return ((ts + 0x0e) % 0x5e) + 0x21 if ts > 0x20 else (t & 0xff)

print(bytes(dec_byte(x) for x in b).decode())

```

---

## Result (Flag)

`sun{n0n_gp1_BPF_code_g0_brrrr}`

---

## Postmortem / Tips

- Static reversing is sufficient here — no need to load the eBPF program when permissions are missing.
- Double-check **offsets and lengths** from `readelf -S` and loop bounds (0x1e) to avoid off-by-one errors.
- The signedness in the condition (`(int8)t > 0x20`) is crucial for reproducing the exact output.
