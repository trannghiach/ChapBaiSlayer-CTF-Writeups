# Sunshine CTF 2025 — Pretty Delicious Food

---

**Thể loại:** Forensics

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một tệp tin PDF duy nhất có tên `prettydeliciouscakes.pdf`. Mô tả của thử thách đưa ra các gợi ý mơ hồ như "out of this world" (nằm ngoài thế giới này) và quan trọng nhất là một lưu ý: **"This is not a steganography challenge"** (Đây không phải là một thử thách giấu tin). Điều này hướng người chơi tập trung vào việc phân tích cấu trúc bên trong của tệp tin thay vì tìm kiếm thông tin ẩn trong hình ảnh.

---

## Mục tiêu

Mục tiêu chính là điều tra cấu trúc tệp PDF để phát hiện, trích xuất và giải mã một chuỗi dữ liệu ẩn, vốn là flag của thử thách.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Cấu trúc tệp PDF:** Hiểu rằng các đối tượng và luồng dữ liệu (streams) bên trong PDF thường được nén (ví dụ bằng Zlib/FlateDecode) để giảm dung lượng.
- **Công cụ dòng lệnh Linux:** Thành thạo các công cụ cơ bản như `grep`, `awk`, `qpdf`, và `base64` để xử lý và phân tích tệp.
- **Mã hóa Base64:** Có khả năng nhận diện các đặc điểm của một chuỗi Base64 (bộ ký tự, ký tự đệm `==`, chiều dài là bội số của 4) và biết cách giải mã nó.
- **Biểu thức chính quy (Regex):** Sử dụng Regex để xây dựng các mẫu tìm kiếm phức tạp nhằm lọc ra các chuỗi dữ liệu đáng ngờ từ một khối văn bản lớn.

---

## Phân tích và hướng tiếp cận

Vì thử thách đã loại trừ khả năng giấu tin trong hình ảnh, hướng tiếp cận hợp lý nhất là mổ xẻ cấu trúc của tệp PDF.

1. **Vấn đề ban đầu:** Nội dung bên trong tệp PDF được nén. Việc chạy lệnh `strings` hoặc `grep` trực tiếp trên tệp gốc sẽ không hiệu quả vì flag có thể nằm trong một luồng dữ liệu đã được nén.
2. **Giải pháp giải nén:** Cần một công cụ có khả năng "làm phẳng" hoặc giải nén toàn bộ tệp PDF về dạng văn bản thuần túy mà con người có thể đọc được. `qpdf` là một lựa chọn tuyệt vời cho nhiệm vụ này. Bằng cách chuyển đổi tệp PDF sang định dạng QDF, tất cả các luồng dữ liệu sẽ được giải nén.
3. **Săn tìm trong "đống cỏ khô":** Sau khi có tệp `uncompressed.pdf`, chúng ta đối mặt với một tệp văn bản lớn. Thay vì tìm kiếm các từ khóa cụ thể như "flag" (có thể không tồn tại), một chiến lược hiệu quả hơn là tìm kiếm các dấu hiệu của dữ liệu được mã hóa. Base64 là một trong những phương thức mã hóa phổ biến nhất trong CTF.
4. **Phương pháp dò tìm Base64:** Một chuỗi Base64 hợp lệ có hai đặc điểm chính có thể khai thác:
    - Nó chỉ chứa các ký tự trong bộ `[A-Za-z0-9+/=]`.
    - Tổng chiều dài của nó phải là một bội số của 4.
5. **Quy trình giải mã:**
    - Sử dụng `qpdf` để giải nén tệp PDF.
    - Xây dựng một chuỗi lệnh (pipeline) kết hợp `grep` và `awk` để lọc ra tất cả các chuỗi ký tự thỏa mãn cả hai điều kiện trên.
    - Lấy các chuỗi ứng viên tìm được và giải mã chúng bằng tiện ích `base64`.
    - Kiểm tra kết quả đã giải mã để tìm flag có định dạng chuẩn.

---

## Kịch bản giải mã (Exploit)

Không cần một kịch bản phức tạp, thử thách này có thể được giải quyết hoàn toàn bằng một vài lệnh trên terminal.

**Bước 1: Giải nén tệp PDF bằng `qpdf`**

Lệnh này sẽ đọc `prettydeliciouscakes.pdf`, giải nén tất cả các luồng dữ liệu và tạo ra một tệp văn bản có thể đọc được là `uncompressed.pdf`.

```bash
qpdf --qdf --object-streams=disable prettydeliciouscakes.pdf uncompressed.pdf

```

**Bước 2: Dò tìm và lọc chuỗi Base64 tiềm năng**

Đây là bước quan trọng nhất. Chúng ta sử dụng một đường ống lệnh để tự động tìm ra chuỗi Base64 từ tệp đã giải nén.

```bash
grep -oE '[A-Za-z0-9+/=]{20,}' uncompressed.pdf | awk 'length % 4 == 0'

```

- `grep -oE '[A-Za-z0-9+/=]{20,}'`: Trích xuất tất cả các chuỗi có độ dài từ 20 ký tự trở lên và chỉ chứa các ký tự hợp lệ của Base64.
- `| awk 'length % 4 == 0'`: Lọc kết quả từ `grep`, chỉ giữ lại những chuỗi có chiều dài chia hết cho 4.

Lệnh này sẽ trả về một hoặc một vài chuỗi ứng viên rất đáng ngờ.

**Bước 3: Giải mã chuỗi tìm được**

Lấy chuỗi ký tự mà lệnh trên đã tìm thấy và giải mã nó bằng `base64`.

```bash
echo 'c3Vue3AzM3BfZDFzX2ZsQGdfeTAhfQ==' | base64 -d

```

---

## Kết quả (Flag)

Sau khi thực thi lệnh giải mã, kết quả thu được chính là flag của thử thách. Định dạng `sun{...}` khớp với thông tin về giải Sunshine CTF.

`sun{p33p_d1s_fl@g_y0!}`

---

## Ghi chú và mẹo

- Luôn chú ý đến các mô tả của thử thách. Việc đề bài ghi rõ "không phải steganography" là một manh mối cực kỳ giá trị, giúp tiết kiệm thời gian và định hướng điều tra.
- Thành thạo các công cụ như `qpdf` hoặc `mutool` là một lợi thế lớn khi xử lý các định dạng tệp phức tạp như PDF.
- Xây dựng một phương pháp luận chung để săn tìm các loại mã hóa phổ biến (Base64, Base32, Hex, v.v.) dựa trên đặc tính cấu trúc của chúng là một kỹ năng forensics cốt lõi, có thể áp dụng cho rất nhiều bài toán khác nhau.

---

# ENGLISH VERSION

**Category:** Forensics

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a single PDF file named `prettydeliciouscakes.pdf`. The description gives vague hints like "out of this world" and, most importantly, a note: **"This is not a steganography challenge."** This directs the player to focus on analyzing the internal structure of the file itself rather than looking for information hidden within the visible image.

---

## Objective

The main objective is to investigate the PDF file structure to discover, extract, and decode a hidden data string, which represents the flag for the challenge.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **PDF File Structure:** Understanding that objects and streams within a PDF are often compressed (e.g., with Zlib/FlateDecode) to reduce file size.
- **Linux Command-Line Tools:** Proficiency with essential tools like `grep`, `awk`, `qpdf`, and `base64` for file processing and analysis.
- **Base64 Encoding:** The ability to recognize the characteristics of a Base64 string (character set, `==` padding, length being a multiple of 4) and how to decode it.
- **Regular Expressions (Regex):** Using Regex to build sophisticated search patterns to filter suspicious data strings from a large block of text.

---

## Analysis and Approach

Since the challenge explicitly rules out image steganography, the most logical approach is to dissect the PDF's structure.

1. **The Initial Problem:** The content within a PDF file is compressed. Running `strings` or `grep` directly on the original file is unlikely to be effective, as the flag could be located within a compressed data stream.
2. **The Decompression Solution:** A tool is needed to "flatten" or decompress the entire PDF into a human-readable text format. `qpdf` is an excellent choice for this task. By converting the PDF to the QDF format, all data streams are decompressed.
3. **Finding the Needle in the Haystack:** After obtaining the `uncompressed.pdf` file, we are faced with a large text file. Instead of searching for specific keywords like "flag" (which may not be present), a more effective strategy is to hunt for artifacts of encoded data. Base64 is one of the most common encoding schemes used in CTFs.
4. **Base64 Detection Method:** A valid Base64 string has two key properties that can be programmatically exploited:
    - It only contains characters from the set `[A-Za-z0-9+/=]`.
    - Its total length must be a multiple of 4.
5. **Decoding Process:**
    - Use `qpdf` to decompress the PDF file.
    - Construct a command-line pipeline combining `grep` and `awk` to filter out all strings that satisfy both Base64 properties.
    - Take the candidate strings found and decode them using the `base64` utility.
    - Check the decoded output for a standard flag format.

---

## Exploit Script

No complex script is needed; this challenge can be solved entirely with a few commands in the terminal.

**Step 1: Decompress the PDF file using `qpdf`**

This command reads `prettydeliciouscakes.pdf`, decompresses all its streams, and creates a human-readable text file named `uncompressed.pdf`.

```bash
qpdf --qdf --object-streams=disable prettydeliciouscakes.pdf uncompressed.pdf

```

**Step 2: Hunt for and Filter Potential Base64 Strings**

This is the most critical step. We use a command pipeline to automatically find the Base64 string from the decompressed file.

```bash
grep -oE '[A-Za-z0-9+/=]{20,}' uncompressed.pdf | awk 'length % 4 == 0'

```

- `grep -oE '[A-Za-z0-9+/=]{20,}'`: Extracts all strings of 20 characters or more that consist solely of valid Base64 characters.
- `| awk 'length % 4 == 0'`: Filters the output from `grep`, keeping only those strings whose length is a multiple of 4.

This command will return one or a few highly suspicious candidate strings.

**Step 3: Decode the Found String**

Take the string identified by the command above and decode it using `base64`.

```bash
echo 'c3Vue3AzM3BfZDFzX2ZsQGdfeTAhfQ==' | base64 -d

```

---

## Result (Flag)

After executing the decode command, the output is the flag for the challenge. The `sun{...}` format matches the context of the Sunshine CTF.

`sun{p33p_d1s_fl@g_y0!}`

---

## Notes and Tips

- Always pay close attention to challenge descriptions. The hint "not steganography" is an invaluable clue that saves time and directs the investigation.
- Proficiency with tools like `qpdf` or `mutool` is a significant advantage when dealing with complex file formats like PDF.
- Developing a generic methodology to hunt for common encoding formats (Base64, Base32, Hex, etc.) based on their structural properties is a core forensics skill that is applicable to many other challenges.
