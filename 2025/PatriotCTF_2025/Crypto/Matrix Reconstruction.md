## **Challenge Description**

You intercept:

- A ciphertext (`cipher.txt`)
- A list of leaked internal PRNG states (`keystream_leak.txt`)
- README explaining the PRNG model:

```
Model: S[n+1] = A * S[n] XOR B   over GF(2)
Keystream byte = lowest byte of S[n]
Recover A, B → reconstruct S → decrypt
```

You must:

1. Recover the secret **32×32 matrix A**
2. Recover vector **B** (32 bits)
3. Rebuild keystream
4. Decrypt ciphertext
5. Extract flag

The PRNG is linear over GF(2), so reconstruction is possible.

---

## **2. Understanding the PRNG**

State is a 32-bit vector.

Transition:

Sn+1=ASn⊕BS_{n+1} = A S_n \oplus B

Sn+1=ASn⊕B

Where:

- AAA is a 32×32 bit matrix
- BBB is a 32-bit vector
- Arithmetic is in GF(2)
- Output keystream byte = lowest 8 bits of SnS_nSn

We are given:

- 42 leaked states → 41 transition equations

Each equation contains 32 bit constraints →

Total equations: 41 × 32 = 1312

Number of unknowns:

- 32×32 = 1024 elements of A
- 32 for B
    
    Total = 1056 unknowns
    

Since 1312 > 1056 → system is solvable and has a unique solution.

---

## **3. Building the Linear System**

Each transition:

AS[i]⊕B=S[i+1]A S[i] \oplus B = S[i+1]

AS[i]⊕B=S[i+1]

Rearranged in GF(2):

AS[i]+B=S[i+1]A S[i] + B = S[i+1]

AS[i]+B=S[i+1]

Each equation yields 32 linear equations in 1056 unknowns.

We treat the unknowns as:

- Variable X0…X1023X_0 \ldots X_{1023}X0…X1023 = entries of A
- Next X1024…X1055X_{1024} \ldots X_{1055}X1024…X1055 = entries of B

Then perform **Gaussian elimination over GF(2)**.

---

## **4. Solving for A and B**

Using Python’s bitwise operations on integers enables efficient bit-matrix elimination.

The elimination yields:

- The full 32×32 matrix **A**
- The 32-bit constant vector **B**

(Values omitted for brevity; solver constructs them automatically.)

---

## **5. Decrypting the Ciphertext**

The keystream is simply:

```
keystream[i] = S[i] & 0xff
```

So for ciphertext length N, we take the first N leaked states.

Then:

```
plaintext_byte = ciphertext_byte XOR keystream_byte
```

This works because ciphertext was produced via XOR stream cipher.

---

## **6. Final Python Solver (End-to-End)**

```python
import base64, hashlib

# Load leaked states
states=[]
with open('keystream_leak.txt') as f:
    for line in f:
        line=line.strip()
        if line:
            states.append(int(line))

pairs=len(states)-1
n_vars=32*32+32

# Build equations
M=[]
Y=[]
for i in range(pairs):
    S=states[i]
    Sn=states[i+1]
    Sb=[(S>>k)&1 for k in range(32)]
    SNb=[(Sn>>k)&1 for k in range(32)]
    for j in range(32):
        row=0
        for k in range(32):
            if Sb[k]:
                row |= (1<<(j*32+k))
        row |= (1<<(32*32+j))  # B[j]
        M.append(row)
        Y.append(SNb[j])

# Gaussian elimination GF(2)
num_vars=n_vars
num_eqs=len(M)
M2=M[:]; Y2=Y[:]
row=0
pivot_cols=[-1]*num_vars

for col in range(num_vars):
    sel=-1
    for r in range(row, num_eqs):
        if (M2[r]>>col)&1:
            sel=r; break
    if sel==-1: continue
    M2[row],M2[sel]=M2[sel],M2[row]
    Y2[row],Y2[sel]=Y2[sel],Y2[row]
    for r in range(num_eqs):
        if r!=row and ((M2[r]>>col)&1):
            M2[r]^=M2[row]; Y2[r]^=Y2[row]
    pivot_cols[col]=row
    row+=1

X=[0]*num_vars
for col in range(num_vars-1,-1,-1):
    r=pivot_cols[col]
    if r==-1: continue
    rhs=Y2[r]
    m=M2[r]
    for c in range(num_vars):
        if c!=col and ((m>>c)&1):
            rhs ^= X[c]
    X[col]=rhs

# Reconstruct A, B
A=[[0]*32 for _ in range(32)]
B=[0]*32
for j in range(32):
    for k in range(32):
        A[j][k]=X[j*32+k]
    B[j]=X[32*32+j]

# Decode ciphertext (base64 provided)
cipher_b64="bKrYyKQISPIAAJ3mxzRMe5wD9b68qWIZOu9KhK05epn/BPQ="
cipher=base64.b64decode(cipher_b64)

keystream=[s & 0xff for s in states]
pt = bytes([c ^ k for c,k in zip(cipher, keystream)])

print(pt.decode())
```

Running the solver yields:

```
pctf{mAtr1x_r3construct?on_!s_fu4n}
```

---

## **7. Final Flag**

# 🎉 **pctf{mAtr1x_r3construct?on_!s_fu4n}**

---

# 🇻🇳 **Phiên Bản Tiếng Việt**

## **1. Mô tả bài**

Ta được cung cấp:

- `cipher.txt` — ciphertext
- `keystream_leak.txt` — danh sách các trạng thái S[n] bị lộ
- README:

```
S[n+1] = A * S[n] XOR B  (GF(2))
Keystream = byte thấp nhất của S[n]
```

Yêu cầu:

1. Khôi phục **ma trận A (32×32)**
2. Khôi phục **vector B (32-bit)**
3. Sinh lại keystream
4. Giải mã ciphertext → lấy flag

---

## **2. Hiểu PRNG**

Trạng thái S là vector 32 bit.

Quy tắc sinh:

Sn+1=ASn⊕BS_{n+1} = A S_n \oplus B

Sn+1=ASn⊕B

Mỗi S menghasilkan **1 byte** làm keystream.

Có 42 trạng thái leak → đủ để thu được 41 phương trình tuyến tính mỗi phương trình 32 bit → tổng 1312 điều kiện.

Số biến:

- 1024 bit trong ma trận A
- 32 bit trong B
    
    → 1056 biến
    

1312 phương trình > 1056 biến → giải được hệ duy nhất.

---

## **3. Dựng hệ tuyến tính GF(2)**

Mỗi phương trình:

AS[i]⊕B=S[i+1]A S[i] \oplus B = S[i+1]

AS[i]⊕B=S[i+1]

Tách thành 32 phương trình line-by-line.

Biến hoá thành một hệ **Gaussian elimination trên GF(2)**.

---

## **4. Tìm được A và B**

Sau khi chạy loại Gauss, ta khôi phục:

- A: ma trận 32×32
- B: vector 32-bit

Tiếp theo chỉ cần mô phỏng máy PRNG ngược.

---

## **5. Giải mã ciphertext**

Keystream:

```
keystream[i] = S[i] & 0xff
```

Giải mã:

```
plaintext = ciphertext XOR keystream
```

---

## **6. Chạy script end-to-end**

Script có trong bản tiếng Anh.

Kết quả:

```
pctf{mAtr1x_r3construct?on_!s_fu4n}
```

---

## **7. Flag**

 🎉 **pctf{mAtr1x_r3construct?on_!s_fu4n}**
