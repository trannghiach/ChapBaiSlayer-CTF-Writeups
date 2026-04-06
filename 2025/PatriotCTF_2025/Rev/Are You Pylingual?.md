## Challenge Summary

We are given a strange Python bytecode file `pylinguese.pyc`.

The challenge hints that the author “obfuscated” Python code into a `.pyc` and the user must reverse-engineer it to recover the flag.

We are also given an `output.txt` which contains a large list of integers.

The goal:

**Recover the flag in the format `pctf{...}`.**

---

## 🔍 Step 1 — Inspecting the `.pyc` file

We decompile the file using **PyLingual** or `uncompyle6`.

Decompiled code:

```python
import pyfiglet
file = open('flag.txt', 'r')
flag = file.read()
font = 'slant'
words = 'MASONCC IS THE BEST CLUB EVER'
flag_track = 0
art = list(pyfiglet.figlet_format(words, font=font))
i = len(art) % 10
for ind in range(len(art)):
    if ind == i and flag_track < len(flag):
        art[ind] = flag[flag_track]
        i += 28
        flag_track += 1
art_str = ''.join(art)
first_val = 5
second_val = 6
first_half = art_str[:len(art_str) // 2]
second_half = art_str[len(art_str) // 2:]
first = [~ord(char) ^ first_val for char in first_half]
second = [~ord(char) ^ second_val for char in second_half]
output = second + first
print(output)

```

---

## 🧠 Step 2 — Understanding the logic

### 1. Generate ASCII-art

The program makes FIGlet ASCII-art of:

```
"MASONCC IS THE BEST CLUB EVER"

```

### 2. Embed the flag

The flag is *injected* directly into this art:

- Starting at index `i = len(art) % 10`
- Every **28 characters**, one character of the flag is inserted:
    
    ```
    art[i] = flag[flag_track]
    i += 28
    
    ```
    

### 3. Encode the resulting string

The ASCII-art string `art_str` is split into two halves, and each half is encoded by bitwise operations:

```
first =  [ ~ord(c) ^ 5 ]
second = [ ~ord(c) ^ 6 ]
output = second + first

```

This matches the structure seen in `output.txt`.

---

## 🔁 Step 3 — Reversing the encoding

To recover the original art string:

```
decoded = chr(~(encoded ^ key) & 0xFF)

```

- use key = 6 for the first half of output
- use key = 5 for the second half

After decoding, we reconstruct the full `art_str`.

---

## 🔎 Step 4 — Extracting the flag from the reconstructed art

We now simulate the original flag embedding logic in reverse:

```
i = len(art) % 10
while i < len(art):
    flag_char = art[i]
    i += 28

```

This yields the actual characters of the flag in the correct order.

---

## 🧪 Step 5 — Final solver script

The solver below fully recovers the flag:

```python
def decode_char(v, key):
    return chr(~(v ^ key) & 0xFF)

namespace = {}
with open("output.txt", "r") as f:
    exec(f.read(), namespace)

output = namespace["output"]

half = len(output) // 2
second = output[:half]
first  = output[half:]

decoded_second = [decode_char(x, 6) for x in second]
decoded_first  = [decode_char(x, 5) for x in first]

art_str = "".join(decoded_first + decoded_second)

art = list(art_str)
i = len(art) % 10
flag_chars = []

while i < len(art):
    flag_chars.append(art[i])
    i += 28

print("FLAG:", "".join(flag_chars))

```

Running the script produces:

```
┌──(venv)─(kimdokja㉿kimdokja)-[~/Downloads]
└─$ python3 rev1.py         
Recovered flag (raw): pctf{obFusc4ti0n_i5n't_EncRypt1oN} 
```

(**Replace with real flag when you run it locally**)

---

# 🇻🇳 **WRITEUP — Are You Pylingual? (Bản Tiếng Việt)**

## 🧩 Tóm tắt đề

Ta được cho file bytecode Python `pylinguese.pyc` cùng với file `output.txt` chứa một danh sách số nguyên rất lớn.

Nhiệm vụ:

**Reverse `.pyc` → decode → lấy flag `pctf{...}`.**

---

## 🔍 Bước 1 — Decompile file `.pyc`

Dùng **PyLingual** ta thu được đoạn code (đã rút gọn):

```python
import pyfiglet
flag = open('flag.txt').read()
art = list(pyfiglet.figlet_format("MASONCC IS THE BEST CLUB EVER", font="slant"))
i = len(art) % 10
for idx in range(len(art)):
    if idx == i:
        art[idx] = flag[flag_track]
        i += 28

```

→ Flag được **chèn trực tiếp** vào ASCII-art, **một ký tự mỗi 28 bước**.

Sau đó nó mã hóa art thành số với phép toán bit:

```
first:  ~ord(c) ^ 5
second: ~ord(c) ^ 6
output = second + first

```

---

## 🧠 Bước 2 — Giải mã ngược

Giải mã lại theo công thức:

```
original_char = chr(~(encoded ^ key) & 0xFF)

```

- key = 6 cho nửa đầu
- key = 5 cho nửa sau

Ghép lại → thu được chuỗi ASCII-art gốc.

---

## 🔁 Bước 3 — Lấy flag từ art

Chạy ngược logic chèn:

```
i = len(art) % 10
flag[i] = art[i]
i += 28

```

→ Thu được các ký tự thật của flag.

---

## 🔥 Bước 4 — Script giải hoàn chỉnh

```python
def decode_char(v, key):
    return chr(~(v ^ key) & 0xFF)

namespace = {}
with open("output.txt") as f:
    exec(f.read(), namespace)

output = namespace["output"]

half = len(output)//2
second = output[:half]
first  = output[half:]

decoded_second = [decode_char(x, 6) for x in second]
decoded_first  = [decode_char(x, 5) for x in first]

art_str = "".join(decoded_first + decoded_second)
art = list(art_str)

i = len(art) % 10
flag = []

while i < len(art):
    flag.append(art[i])
    i += 28

print("FLAG:", "".join(flag))

```

```html
┌──(venv)─(kimdokja㉿kimdokja)-[~/Downloads]
└─$ python3 rev1.py         
Recovered flag (raw): pctf{obFusc4ti0n_i5n't_EncRypt1oN} 
```
