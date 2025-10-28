# Sunshine CTF 2025 — t0le t0le

---

**Thể loại:** Forensics

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một tệp tin Microsoft Word có tên `Team_5_-_Inject_72725.docx`. Mô tả đi kèm khá hài hước: "Our CCDC business guy made a really weird inject. He's just obsessed with that damn cat... there's nothing hiding in there, right?" (Chàng trai kinh doanh CCDC của chúng tôi đã tạo ra một inject kỳ lạ. Anh ta bị ám ảnh bởi con mèo chết tiệt đó... không có gì giấu trong đó đâu, phải không?).

Mô tả này trực tiếp gợi ý rằng có một thứ gì đó được che giấu liên quan đến tệp tin và có thể là cả hình ảnh con mèo bên trong.

---

## Mục tiêu

Mục tiêu là phân tích cấu trúc của tệp DOCX, xác định vị trí dữ liệu ẩn, trích xuất và giải mã nó qua nhiều lớp để tìm ra flag cuối cùng.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Cấu trúc tệp DOCX:** Hiểu rằng tệp `.docx` về cơ bản là một kho lưu trữ ZIP chứa các tệp XML, media và các đối tượng nhúng khác.
- **Đối tượng nhúng OLE:** Nhận biết các đối tượng được nhúng (Embedded Objects) trong tài liệu Office, thường được lưu dưới dạng tệp `.bin`.
- **Công cụ dòng lệnh Linux:** Thành thạo việc sử dụng các công cụ `strings`, `grep`, `base64` và toán tử pipe (`|`) để tạo thành một chuỗi xử lý dữ liệu hiệu quả.
- **Mã hóa Base64:** Có khả năng nhận diện và giải mã các chuỗi Base64.
- **Mật mã cổ điển:** Nhận biết và giải mã các dạng mật mã thay thế đơn giản, đặc biệt là Caesar Cipher / ROT13.

---

## Phân tích và hướng tiếp cận

Hướng tiếp cận được xây dựng dựa trên các manh mối từ mô tả và bản chất của định dạng tệp.

1. **Vấn đề ban đầu:** Tệp DOCX là một định dạng phức hợp. Việc xem nó như một tài liệu văn bản thông thường sẽ bỏ qua các dữ liệu được nhúng hoặc ẩn trong cấu trúc của nó.
2. **Giải pháp "mổ xẻ":** Bước đầu tiên và cơ bản nhất khi phân tích tệp Office trong forensics là coi nó như một tệp ZIP. Bằng cách đổi đuôi tệp thành `.zip` và giải nén, chúng ta có thể truy cập vào toàn bộ cấu trúc tệp bên trong, bao gồm hình ảnh, XML và các đối tượng nhúng.
3. **Xác định mục tiêu:** Sau khi giải nén, thư mục `word/embeddings/` ngay lập tức thu hút sự chú ý. Nó chứa một tệp `oleObject1.bin`, là một đối tượng nhúng. Đây là một nơi ẩn giấu thông tin rất phổ biến.
4. **Săn tìm trong tệp nhị phân:** Tệp `.bin` là dữ liệu nhị phân. Để tìm kiếm thông tin có thể đọc được, `strings` là công cụ lý tưởng. Tuy nhiên, kết quả trả về thường rất lớn. Thay vì tìm kiếm thủ công, ta sẽ tìm các dấu hiệu của dữ liệu được mã hóa. Base64 là ứng cử viên hàng đầu.
5. **Phương pháp dò tìm tự động:** Ta sử dụng biểu thức chính quy (Regex) với `grep` để lọc đầu ra từ `strings`, chỉ giữ lại các chuỗi dài trông giống Base64.
6. **Giải mã đa lớp:**
    - Sau khi trích xuất và giải mã chuỗi Base64, kết quả vẫn chưa phải là flag cuối cùng. Nó lại là một chuỗi được mã hóa khác.
    - Dựa vào định dạng `prefix{content}` và các ký tự, ta có thể suy đoán đây là một mật mã thay thế. ROT13 là loại phổ biến nhất và nên được thử đầu tiên.
    - Áp dụng giải mã ROT13 sẽ tiết lộ flag cuối cùng.

---

## Kịch bản giải mã (Exploit)

Toàn bộ thử thách có thể được giải quyết nhanh chóng bằng một chuỗi lệnh trên terminal.

**Bước 1: Giải nén tệp DOCX**

Cách đơn giản nhất là đổi tên tệp và sử dụng công cụ giải nén.

```bash
# Đổi tên tệp
mv Team_5_-_Inject_72725.docx inject.zip

# Giải nén
unzip inject.zip

```

Thao tác này sẽ tạo ra một cấu trúc thư mục bao gồm `word/embeddings/oleObject1.bin`.

**Bước 2: Tìm, trích xuất và giải mã Base64**

Chúng ta sẽ tạo một đường ống lệnh để thực hiện tất cả các bước trong một lần. Lệnh này sẽ:

1. Đọc các chuỗi ký tự từ `oleObject1.bin`.
2. Lọc ra chuỗi duy nhất khớp với mẫu Base64 và có độ dài đáng kể.
3. Giải mã chuỗi Base64 đó.

```bash
strings word/embeddings/oleObject1.bin | grep -E -o '[A-Za-z0-9+/=]{20,}' | base64 -d

```

Lệnh này sẽ cho ra kết quả trung gian: `fha{g0yr_g0yr_zl_o3y0i3q!}`.

**Bước 3: Giải mã ROT13**

Chuỗi kết quả ở trên rõ ràng là một dạng mật mã thay thế. Chúng ta có thể sử dụng một công cụ ROT13 trực tuyến hoặc dùng lệnh `tr` trong terminal để giải mã.

```bash
echo 'fha{g0yr_g0yr_zl_o3y0i3q!}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'

```

---

## Kết quả (Flag)

Sau khi thực hiện bước giải mã cuối cùng, flag hoàn chỉnh sẽ xuất hiện. Flag này khớp với tên thử thách và mô tả về "sự ám ảnh".

**`sun{t0le_t0le_my_b3l0v3d!}`**

---

## Ghi chú và mẹo

- **Nguyên tắc vàng:** Khi nhận được một tệp DOCX, XLSX, hoặc PPTX trong một thử thách forensics, hãy luôn bắt đầu bằng cách giải nén nó.
- **Phân tích đa lớp:** Các thử thách CTF thường không chỉ có một lớp mã hóa. Hãy luôn chuẩn bị tinh thần để giải mã nhiều bước (ví dụ: Binary -> Base64 -> ROT13).
- **Liên kết bối cảnh:** Flag cuối cùng (`my_b3l0v3d!`) liên quan trực tiếp đến mô tả ("obsessed with that damn cat"). Việc chú ý đến các chi tiết trong mô tả có thể giúp xác nhận rằng bạn đang đi đúng hướng.
- **Sức mạnh của đường ống lệnh:** Việc kết hợp `strings`, `grep`, `awk`, `base64`... thông qua pipe (`|`) là một kỹ năng cực kỳ mạnh mẽ và tiết kiệm thời gian trong forensics và xử lý dữ liệu.

---

# ENGLISH VERSION

---

**Category:** Forensics

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a Microsoft Word file named `Team_5_-_Inject_72725.docx`. The accompanying description is quite humorous: "Our CCDC business guy made a really weird inject. He's just obsessed with that damn cat... there's nothing hiding in there, right?".

This description directly suggests that something is hidden related to the file and possibly the cat image within it.

---

## Objective

The objective is to analyze the structure of the DOCX file, identify the location of hidden data, and extract and decode it through multiple layers to find the final flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **DOCX File Structure:** Understanding that a `.docx` file is fundamentally a ZIP archive containing XML files, media, and other embedded objects.
- **OLE Embedded Objects:** Recognizing embedded objects within Office documents, which are often stored as `.bin` files.
- **Linux Command-Line Tools:** Proficiency in using tools like `strings`, `grep`, `base64`, and the pipe operator (`|`) to create an efficient data processing chain.
- **Base64 Encoding:** The ability to recognize and decode Base64 strings.
- **Classical Ciphers:** Recognizing and decoding simple substitution ciphers, especially the Caesar Cipher / ROT13.

---

## Analysis and Approach

The approach is built upon clues from the description and the nature of the file format.

1. **The Initial Problem:** A DOCX file is a complex format. Viewing it as a simple text document would miss any data embedded or hidden within its structure.
2. **The "Dissection" Solution:** The first and most fundamental step when analyzing an Office file in forensics is to treat it as a ZIP archive. By changing the file extension to `.zip` and unzipping it, we gain access to the entire internal file structure, including images, XML, and embedded objects.
3. **Identifying the Target:** After unzipping, the `word/embeddings/` directory immediately draws attention. It contains an `oleObject1.bin` file, which is an embedded object. This is a very common hiding place for information.
4. **Hunting in the Binary:** The `.bin` file contains binary data. To search for human-readable information, `strings` is the ideal tool. However, its output is often verbose. Instead of searching manually, we will look for patterns of encoded data. Base64 is a prime candidate.
5. **Automated Detection Method:** We use a regular expression (Regex) with `grep` to filter the output from `strings`, keeping only long strings that look like Base64.
6. **Multi-Layered Decoding:**
    - After extracting and decoding the Base64 string, the result is not yet the final flag. It is another encoded string.
    - Based on the `prefix{content}` format and the characters, we can deduce it's a substitution cipher. ROT13 is the most common and should be tried first.
    - Applying a ROT13 decryption will reveal the final flag.

---

## Exploit Script

The entire challenge can be solved quickly with a chain of commands in the terminal.

**Step 1: Unzip the DOCX file**

The simplest way is to rename the file and use an unzipping tool.

```bash
# Rename the file
mv Team_5_-_Inject_72725.docx inject.zip

# Unzip it
unzip inject.zip

```

This will create a directory structure that includes `word/embeddings/oleObject1.bin`.

**Step 2: Find, Extract, and Decode the Base64**

We will create a command pipeline to perform all steps at once. This command will:

1. Read the character strings from `oleObject1.bin`.
2. Filter out the unique string that matches a Base64 pattern and has a significant length.
3. Decode that Base64 string.

```bash
strings word/embeddings/oleObject1.bin | grep -E -o '[A-Za-z0-9+/=]{20,}' | base64 -d

```

This command will produce the intermediate result: `fha{g0yr_g0yr_zl_o3y0i3q!}`.

**Step 3: Decode with ROT13**

The resulting string above is clearly a form of substitution cipher. We can use an online ROT13 tool or the `tr` command in the terminal to decode it.

```bash
echo 'fha{g0yr_g0yr_zl_o3y0i3q!}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'

```

---

## Result (Flag)

After executing the final decoding step, the complete flag appears. The flag's content matches the challenge name and the "obsession" theme from the description.

**`sun{t0le_t0le_my_b3l0v3d!}`**

---

## Notes and Tips

- **The Golden Rule:** When you receive a DOCX, XLSX, or PPTX file in a forensics challenge, always start by unzipping it.
- **Multi-Layered Analysis:** CTF challenges often feature more than one layer of encoding. Always be prepared to perform multiple decoding steps (e.g., Binary -> Base64 -> ROT13).
- **Contextual Clues:** The final flag (`my_b3l0v3d!`) relates directly to the description ("obsessed with that damn cat"). Paying attention to details in the description can help confirm you are on the right track.
- **The Power of the Pipeline:** Chaining tools like `strings`, `grep`, `awk`, `base64`, etc., via the pipe operator (`|`) is an extremely powerful and time-saving skill in forensics and data processing.
