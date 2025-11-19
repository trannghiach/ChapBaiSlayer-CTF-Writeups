english below

# GPT

## 1. Mô tả đề

Đề (dịch ý chính):

> “GPT nói tao giấu gì đó trong đoạn base64 này…”
> 

Và cho một đống dòng base64, ví dụ:

```
Q2hhdEdQVCBpcyBhIGdlbmVyYXRpdmUgYXJ0aWZpY2lhbCBpbnRlbGxpZ2VuY2UgY2hhdGJvdCBkZXZlbG9wZWQgYnkgT3BlbkFJIGFuZCByZWxlYXNlZCBpbiBOb3ZlbWJlciAyMDIy
SXQgY3VycmVudGx5IHVzZXMgR1BVLTV=
YSBnZW5lcmF0aXZlIHByZS10cmFpbmVkIHRyYW5zZm9ybWVyIChHUFQp
...

```

Decode base64 ra thì được một bài viết tiếng Anh kiểu tóm tắt lịch sử ChatGPT/OpenAI, rất giống nội dung trên Wikipedia.

Đề hint rõ: “hided something inside this base64 encoding”

=> Cái bị giấu nằm **trong base64**, không phải trong text decode ra.

---

## 2. Ôn lại base64 một chút

Để hiểu stego của đề này, cần nắm sơ sơ base64 hoạt động thế nào.

- Dữ liệu gốc là bytes (mỗi byte = 8 bit).
- Base64 chia dữ liệu thành block 3 byte = 24 bit.
- 24 bit đó được chia thành 4 nhóm 6 bit.
- Mỗi 6 bit map sang 1 ký tự trong bảng:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/

```

=> 3 byte gốc → 4 ký tự base64.

Trường hợp số byte không chia hết cho 3:

- Nếu dư 1 byte → sẽ có 8 bit thật, còn 16 bit còn lại được padding.
- Nếu dư 2 byte → có 16 bit thật, còn 8 bit padding.
- Lúc encode chuẩn thì phần “thiếu” được xử lý theo quy tắc, và thường dùng ký tự `=` để padding ở cuối.

Điểm quan trọng:

> Decoder chỉ dùng phần bit tương ứng với số byte gốc. Những bit “thừa” ở cuối (nếu ta cố ý sửa) vẫn có thể bị bỏ qua khi decode, miễn là theo format hợp lệ.
> 

Đề lợi dụng đúng chuyện này: chỉnh các bit “thừa” để nhét dữ liệu ẩn.

---

## 3. Ý tưởng tấn công: so sánh với base64 “chuẩn”

Với mỗi dòng base64 trong đề:

1. Ta **decode** base64 → ra bytes gốc (chính là text tiếng Anh).
2. Từ bytes đó, ta **encode lại base64 chuẩn** bằng thư viện chuẩn.
3. Ta convert cả:
    - base64 gốc (đề cho)
    - base64 chuẩn (ta tự encode)
    
    → sang chuỗi bit (mỗi ký tự base64 = 6 bit).
    
4. Số bit “thật” của dữ liệu:
    
    `data_bits = số_bytes_decode * 8`
    
5. Phần bit từ `0` tới `data_bits - 1` của hai bên **bắt buộc giống nhau** (vì decode cùng ra 1 dữ liệu).
6. Phần bit **sau `data_bits`** (ở base64 gốc) là phần tác giả có thể “phá” để nhét dữ liệu, mà không làm thay đổi dữ liệu decode.

Nên:

> “Hidden data” = các bit dư ở cuối (sau data_bits) của base64 gốc, ghép lại từ tất cả các dòng.
> 

---

## 4. Cài đặt bằng Python

Giả sử ta copy toàn bộ các dòng base64 trong đề vào file `enc.txt` (mỗi dòng một đoạn, bỏ dòng trống).

### 4.1. Chuẩn bị hàm chuyển base64 → bit

Ta cần mapping mỗi ký tự base64 sang 6 bit:

```python
import base64

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def b64bits(s: str) -> str:
    bits = ""
    for ch in s:
        if ch == "=":
            break  # bỏ qua padding
        bits += format(alphabet.index(ch), "06b")
    return bits

```

### 4.2. Lặp từng dòng, lấy bit thừa

```python
hidden_bits = ""

with open("enc.txt", "r", encoding="utf-8") as f:
    lines = [l.strip() for l in f if l.strip()]

for line in lines:
    # 1) decode dữ liệu gốc từ base64 (dòng đề cho)
    dec = base64.b64decode(line)

    # 2) encode lại base64 "chuẩn" từ dữ liệu gốc
    canon = base64.b64encode(dec).decode().rstrip("=")

    # 3) tính số bit "thật" của dữ liệu
    data_bits = len(dec) * 8

    # 4) chuyển cả 2 base64 sang chuỗi bit
    obits = b64bits(line.rstrip("="))   # bits của base64 gốc
    cbits = b64bits(canon)             # bits của base64 chuẩn

    # 5) sanity check: phần data phải giống nhau
    assert obits[:data_bits] == cbits[:data_bits]

    # 6) phần dư (sau data_bits) trong obits chính là stego
    #    (chú ý: chỉ lấy đến độ dài cbits, vì đó là số bit base64 chuẩn)
    hidden_bits += obits[data_bits:len(cbits)]

```

Sau vòng lặp, `hidden_bits` là một chuỗi `'0'/'1'` rất dài, là dữ liệu ẩn.

### 4.3. Convert bit → bytes → text

Ta cắt chuỗi bit thành các block 8 bit để chuyển thành byte:

```python
# cắt cho đủ bội số của 8
n = (len(hidden_bits) // 8) * 8
hidden_bits = hidden_bits[:n]

# chuyển sang bytes
hidden_bytes = int(hidden_bits, 2).to_bytes(n // 8, "big")

print(hidden_bytes)
print(hidden_bytes.decode("utf-8", "replace"))

```

Khi chạy, ta nhận được kết quả kiểu:

```
b'amatetrsCTF;3v3rqth1ng_c4n_b3_st3go}'
amatetrsCTF;3v3rqth1ng_c4n_b3_st3go}

```

Chuỗi hơi lỗi chính tả, nhưng nhìn là đoán được:

- `amatetrsCTF;` -> `amateursCTF{`
- `3v3rqth1ng` -> `3v3ryth1ng`

=> Flag format đúng sẽ là:

```
amateursCTF{3v3ryth1ng_c4n_b3_st3go}

```

---

## 5. Tóm tắt logic giải

1. Đề cho một đống base64, decode ra chỉ là bài Wikipedia → nội dung chỉ để đánh lạc hướng.
2. Hint nói “giấu trong base64 encoding” → phải soi vào base64, không phải text.
3. Base64 dùng 6 bit / ký tự, nhưng số bit dữ liệu không phải lúc nào cũng chia hết → xuất hiện “bit thừa” cuối.
4. Tác giả chỉnh các bit thừa để nhét dữ liệu ẩn.
5. Cách lôi dữ liệu ra:
    - Decode từng dòng → dữ liệu gốc.
    - Encode lại bằng thư viện chuẩn → base64 chuẩn.
    - So sánh bit của base64 gốc vs base64 chuẩn.
    - Phần bit sau `data_bits` trong base64 gốc là stego.
    - Ghép tất cả các đoạn bit lại, convert sang bytes → ASCII → flag.

---

Chốt lại:

> Thấy base64 dài bất thường hoặc nhiều dòng, đặc biệt khi đề nói “giấu trong base64”, thì ngoài việc decode ra text, hãy nghĩ đến việc so sánh với encode chuẩn / phân tích bit.
>



-----

# ENGLISH

## 🧩 Challenge Description

The prompt states (paraphrased):

> “GPT says I hid something in this base64 chunk…”

Followed by a large amount of base64 strings, like:

```
Q2hhdEdQVCBpcyBhIGdlbmVyYXRpdmUgYXJ0aWZpY2lhbCBpbnRlbGxpZ2VuY2UgY2hhdGJvdCBkZXZlbG9wZWQgYnkgT3BlbkFJIGFuZCByZWxlYXNlZCBpbiBOb3ZlbWJlciAyMDIy
SXQgY3VycmVudGx5IHVzZXMgR1BVLTV=
YSBnZW5lcmFhdGl2ZSBwcmUtdHJhaW5lZCB0cmFuc2Zvcm1lciAoS1BOKQ=
...
```

Decoding these base64 strings reveals an English article, similar to a Wikipedia summary of ChatGPT/OpenAI history.

The key hint is: **“hided something inside this base64 encoding.”**

This strongly suggests the hidden data is embedded **within the base64 structure**, not in the decoded text itself.

-----

## 🔍 Base64 Review & Stego Principle

To understand the attack, a basic knowledge of Base64 is necessary:

1.  **Original Data:** Bytes (8 bits each).
2.  **Encoding:** Divides the data into 3-byte blocks (24 bits).
3.  **Mapping:** Each 24-bit block is split into four 6-bit groups.
4.  **Character Set:** Each 6-bit value is mapped to one character in the Base64 Alphabet:
    $$ \text{ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/}$$
5.  **Padding:** If the original byte count is not a multiple of 3 (1 or 2 bytes remaining), padding is used, often marked by one or two `=` characters at the end.

The crucial point exploited in this steganography is the **"extra bits"** at the end of the encoding:

> A standard Base64 decoder only uses the bits corresponding to the original data length. Any **"excess" bits** at the very end of the encoding (which might arise from the final 6-bit groups that are not fully utilized to form an 8-bit byte) can be modified without changing the decoded output, as long as the overall format remains valid.

The attacker modified these unused "extra bits" to embed the hidden data.

-----

## 💡 Attack Strategy: Comparison with Canonical Encoding

The idea is to compare the given Base64 string (the "Original") with a **Canonical** (standard/correctly generated) Base64 string for the same underlying data.

For each line of Base64 from the challenge:

1.  **Decode:** Convert the original Base64 to its original bytes (the English text).
2.  **Canonical Encode:** Re-encode those original bytes using a standard Base64 library to get the **Canonical Base64**.
3.  **Bit Conversion:** Convert both the Original Base64 and the Canonical Base64 into their respective 6-bit sequences.
4.  **Data Bits Length:** Calculate the total number of "true" data bits:
    $$\text{data\_bits} = \text{number\_of\_decoded\_bytes} \times 8$$
5.  **Comparison:**
      * The bits from index $0$ to $\text{data\_bits} - 1$ **must be identical** in both the Original and Canonical Base64.
      * The bits **after $\text{data\_bits}$** in the Original Base64 are the ones the author could "tamper" with without changing the decoded output.

Therefore:

> The **"Hidden data"** is the sequence of excess bits (after the $\text{data\_bits}$ mark) collected from the Original Base64 of all lines, concatenated together.

-----

## 🐍 Python Implementation Summary

The WP outlines a Python script to extract the bits:

1.  **Define a `b64bits` function:** Maps each Base64 character to its 6-bit binary string (e.g., 'A' $\to$ '000000').
2.  **Iterate through lines:**
      * `dec = base64.b64decode(line)`
      * `canon = base64.b64encode(dec).decode().rstrip("=")` (Generates the standard Base64)
      * `data_bits = len(dec) * 8`
      * `obits = b64bits(line.rstrip("="))` (Original bits)
      * `cbits = b64bits(canon)` (Canonical bits)
      * **Extraction:** `hidden_bits += obits[data_bits:len(cbits)]` (Collects the trailing excess bits from the original Base64 up to the length of the canonical Base64's bits).
3.  **Convert Bits to Text:**
      * The collected `hidden_bits` string is truncated to a length divisible by 8.
      * The binary string is converted into an integer, and then into bytes.
      * `hidden_bytes = int(hidden_bits, 2).to_bytes(n // 8, "big")`
      * The bytes are decoded as UTF-8.

### 🏁 Final Result

The decoded bytes result in a string like:
`b'amatetrsCTF;3v3rqth1ng_c4n_b3_st3go}'`

After correcting the obvious typos/substitutions, the flag is reconstructed:

$$\text{amateursCTF\{3v3ryth1ng\_c4n\_b3\_st3go\}} $$

-----

## 📝 Conclusion

The challenge is a classic example of Base64 steganography, where the hidden data is embedded in the **excess/unused bits** at the end of the Base64 encoding blocks, which do not affect the integrity of the decoded payload. The solution involves comparing the provided Base64 stream against a standard re-encoded stream to isolate the modified bits.
