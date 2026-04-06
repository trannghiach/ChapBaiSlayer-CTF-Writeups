# Sunshine CTF 2025 — the poop challenge

**Thể loại:** Steganography / Forensics

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một khối văn bản chứa nhiều biểu tượng cảm xúc `💩`. Thoạt nhìn, các biểu tượng này có vẻ giống hệt nhau. Tuy nhiên, một số trong chúng được theo sau bởi một ký tự vô hình, đó là **ZWSP (Zero Width Space)**. Nhiệm vụ của người chơi là phát hiện và giải mã thông điệp (flag) được ẩn giấu bằng kỹ thuật này.

---

## Mục tiêu

Mục tiêu chính là trích xuất thông điệp bí mật được mã hóa trong khối văn bản bằng cách phân biệt giữa các biểu tượng `💩` có và không có ký tự ZWSP.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Ký tự Zero Width Space (ZWSP):** Nhận biết sự tồn tại của các ký tự không hiển thị như ZWSP (Unicode `\\u200B`) trong một chuỗi văn bản.
- **Mã hóa nhị phân:** Hiểu cách chuyển đổi một chuỗi bit nhị phân (ví dụ: `01100110`) thành các ký tự ASCII tương ứng.
- **Lập trình và xử lý chuỗi:** Sử dụng một ngôn ngữ lập trình như Python để tự động hóa quá trình phân tích chuỗi, phát hiện ký tự ẩn và thực hiện chuyển đổi.

---

## Phân tích và hướng tiếp cận

Kỹ thuật giấu tin trong thử thách này dựa trên một quy ước mã hóa nhị phân đơn giản. Thông điệp ẩn được chuyển đổi thành một chuỗi các bit 0 và 1, sau đó được biểu diễn bằng cách sử dụng biểu tượng `💩` kết hợp với ZWSP.

1. **Quy ước mã hóa:** Dựa trên mô tả, ta có thể suy ra quy tắc sau:
    - `💩` theo sau bởi một ký tự ZWSP (`\\u200B`) đại diện cho bit `1`.
    - `💩` đứng một mình (không có ZWSP) đại diện cho bit `0`.
2. **Cấu trúc dữ liệu:** Thử thách được cấu trúc để mỗi dòng trong khối văn bản chứa 8 biểu tượng `💩`. Điều này gợi ý rằng mỗi dòng tương ứng với 8 bit, hay một byte, của thông điệp ẩn.
3. **Quy trình giải mã:**
    - Đọc toàn bộ khối văn bản.
    - Xử lý từng dòng một.
    - Trong mỗi dòng, thay thế chuỗi "💩" + ZWSP bằng "1" và chuỗi "💩" còn lại bằng "0".
    - Sau khi chuyển đổi, mỗi dòng sẽ trở thành một chuỗi nhị phân gồm 8 ký tự (ví dụ: `01110011`).
    - Chuyển đổi chuỗi nhị phân 8-bit này thành giá trị số nguyên tương ứng.
    - Chuyển đổi giá trị số nguyên đó thành ký tự ASCII.
    - Nối tất cả các ký tự đã giải mã lại để có được flag cuối cùng.

---

## Kịch bản giải mã (Exploit)

Một kịch bản Python là công cụ hiệu quả để tự động hóa quá trình này. Đoạn mã dưới đây thực hiện các bước đã phân tích ở trên.

```python
# decode_poop_zwsp_ctf.py
# Để chạy: python3 decode_poop_zwsp_ctf.py

# Ký tự Zero Width Space (U+200B)
ZWSP = "\\u200B"

# Dán khối emoji từ thử thách vào đây
text = """(dán nguyên block emoji từ đề vào đây)"""

def decode_block(block):
    """
    Giải mã một khối văn bản chứa emoji và ZWSP.
    """
    # Tách khối văn bản thành các dòng và loại bỏ khoảng trắng thừa
    lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
    decoded_chars = []

    for i, line in enumerate(lines, 1):
        # Thay thế "💩" kèm ZWSP thành "1" và "💩" không kèm ZWSP thành "0"
        bits = line.replace("💩" + ZWSP, "1").replace("💩", "0")

        # Kiểm tra xem dòng có đúng 8 bit không
        if len(bits) != 8:
            raise ValueError(f"Dòng {i} không hợp lệ, không chứa đúng 8 bit: '{bits}' (độ dài={len(bits)})")

        # Chuyển chuỗi nhị phân thành ký tự ASCII và thêm vào danh sách
        decoded_chars.append(chr(int(bits, 2)))

    # Nối các ký tự lại để tạo thành flag cuối cùng
    return "".join(decoded_chars)

if __name__ == "__main__":
    try:
        flag = decode_block(text)
        print("Decoded Flag:", flag)
    except ValueError as e:
        print("Error:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)

```

**Kết quả (Flag)**

Khi thực thi kịch bản với dữ liệu từ thử thách, kết quả thu được sẽ là flag có định dạng `sun{...}`. Định dạng này khớp với thông tin về giải Sunshine CTF.

`sun{lesssgooo_solved_the_poop_challenge!}`

---

## Ghi chú và mẹo

- Đây là một bài tập steganography cơ bản, được thiết kế để giới thiệu cho người chơi về khái niệm các ký tự vô hình và cách chúng có thể được sử dụng để che giấu dữ liệu.
- Khi gặp phải các chuỗi văn bản có vẻ "bất thường" hoặc đáng ngờ trong các thử thách CTF, hãy luôn kiểm tra sự hiện diện của các ký tự không hiển thị. Các công cụ như trình soạn thảo hex hoặc các kịch bản tùy chỉnh có thể giúp phát hiện chúng.
- Để làm cho kịch bản mạnh mẽ hơn, có thể mở rộng để kiểm tra nhiều loại ký tự zero-width khác nhau, chẳng hạn như Zero-Width Non-Joiner (`\\u200C`) hoặc Zero-Width Joiner (`\\u200D`).

---

# ENGLISH VERSION

**Category:** Steganography / Forensics

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a block of text containing multiple `💩` (poop) emojis. At first glance, these emojis appear identical. However, some of them are followed by an invisible character: the **ZWSP (Zero-Width Space)**. The player's task is to detect this pattern and decode the hidden message (the flag).

---

## Objective

The main goal is to extract the hidden message encoded within the block of emojis by differentiating between the `💩` emojis with and without the trailing ZWSP character.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Zero-Width Space (ZWSP):** Recognizing the existence of non-displaying characters like ZWSP (Unicode `\\u200B`) within a text string.
- **Binary Encoding:** Understanding how to convert a string of binary bits (e.g., `01100110`) into its corresponding ASCII characters.
- **Scripting and String Manipulation:** Using a programming language like Python to automate the process of parsing the string, detecting the hidden characters, and performing the conversion.

---

## Analysis and Approach

The steganographic technique in this challenge is based on a simple binary encoding scheme. The hidden message is converted into a stream of 0s and 1s, which are then represented using the `💩` emoji in combination with the ZWSP.

1. **Encoding Scheme:** Based on the challenge description, we can deduce the following rule:
    - A `💩` emoji followed by a ZWSP (`\\u200B`) represents the bit `1`.
    - A `💩` emoji by itself (with no ZWSP) represents the bit `0`.
2. **Data Structure:** The challenge is structured so that each line in the text block contains 8 `💩` emojis. This strongly suggests that each line corresponds to 8 bits, or one byte, of the hidden message.
3. **Decoding Process:**
    - Read the entire block of text.
    - Process the text line by line.
    - In each line, replace the "💩" + ZWSP sequence with "1" and the remaining "💩" characters with "0".
    - After the replacement, each line becomes an 8-character binary string (e.g., `01110011`).
    - Convert this 8-bit binary string into its corresponding integer value.
    - Convert that integer value into an ASCII character.
    - Concatenate all the decoded characters to reveal the final flag.

---

## Exploit Script

A Python script is an effective tool to automate this process. The code below implements the steps outlined in the analysis.

```python
# decode_poop_zwsp_ctf.py
# To run: python3 decode_poop_zwsp_ctf.py

# The Zero-Width Space character (U+200B)
ZWSP = "\\u200B"

# Paste the emoji block from the challenge here
text = """(paste the entire emoji block from the challenge here)"""

def decode_block(block):
    """
    Decodes a block of text containing emojis and ZWSP.
    """
    # Split the block into lines and remove any extra whitespace
    lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
    decoded_chars = []

    for i, line in enumerate(lines, 1):
        # Replace "💩" with ZWSP as "1" and "💩" without as "0"
        bits = line.replace("💩" + ZWSP, "1").replace("💩", "0")

        # Validate that the line is exactly 8 bits long
        if len(bits) != 8:
            raise ValueError(f"Line {i} is invalid, does not contain 8 bits: '{bits}' (length={len(bits)})")

        # Convert the binary string to an ASCII character and add it to the list
        decoded_chars.append(chr(int(bits, 2)))

    # Join the characters to form the final flag
    return "".join(decoded_chars)

if __name__ == "__main__":
    try:
        flag = decode_block(text)
        print("Decoded Flag:", flag)
    except ValueError as e:
        print("Error:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)

```

**Result (Flag)**

When the script is executed with the challenge data, the result will be the flag, formatted according to the Sunshine CTF standard.

`sun{lesssgooo_solved_the_poop_challenge!}`

---

## Postmortem / Tips

- This is a fundamental steganography challenge designed to introduce players to the concept of invisible characters and how they can be used to hide data.
- When encountering "unusual" or suspicious-looking text strings in CTF challenges, always check for the presence of non-displaying characters. Tools like hex editors or custom scripts can help detect them.
- To make the script more robust, it could be extended to test for other types of zero-width characters, such as the Zero-Width Non-Joiner (`\\u200C`) or the Zero-Width Joiner (`\\u200D`).
