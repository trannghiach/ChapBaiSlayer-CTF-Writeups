# Sunshine CTF 2025 — MoonClicker

---

All credits to: https://hackmd.io/@lamchcl/S1q53tunll#MoonClicker

**Thể loại:** Cryptography / Web

**Độ khó:** Khó

---

## Tổng quan thử thách

Thử thách cung cấp 1 trang mở đầu cho phép nhập username. Sau khi nhập username ta được cấp 1 cookie cho trang chính hiển thị bao gồm:

- username
- số lần click moon
- 1 ảnh moon để click vào

Sau mỗi click thì sẽ refresh lại trang với cookie mới và số lần click moon +1.

---

## Mục tiêu

Mục tiêu chính chắc chắn là phân tích xem cookie được mã như thế nào, từ đó ta có thể suy ra được 1 cookie hợp lệ cho 1 số lượng moon rất lớn (điều mà không thể đạt được nếu chỉ ngồi click chay).

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Mật mã khối (Block Ciphers):** Hiểu cách dữ liệu được chia thành các khối có kích thước cố định (ví dụ: 16 byte) và được mã hóa từng khối một.
- **Các chế độ hoạt động của mật mã khối, đặc biệt là ECB (Electronic Codebook):** Nắm rõ điểm yếu chí mạng của ECB là các khối plaintext giống hệt nhau sẽ luôn tạo ra các khối ciphertext giống hệt nhau. Đây là chìa khóa để nhận diện và khai thác lỗ hổng.
- **Tấn công ECB Cut-and-Paste:** Đây là kỹ thuật tấn công kinh điển vào chế độ ECB, cho phép kẻ tấn công "cắt" các khối ciphertext từ các cookie khác nhau và "dán" chúng lại để tạo thành một cookie giả mạo hợp lệ.
- **Cấu trúc dữ liệu JSON:** Nhận biết và hiểu cách dữ liệu được tuần tự hóa bằng JSON để có thể phỏng đoán và xây dựng cấu trúc plaintext.
- **HTTP Cookies:** Hiểu cách cookie hoạt động, cách chúng được gửi và nhận giữa client và server để có thể chỉnh sửa và gửi lại cookie giả mạo.

---

## Phân tích và hướng tiếp cận

1. Để có được dữ liệu cần thiết cho việc phân tích, ta sẽ chạy script brute force POST username từ 1 chữ `V` đến 36 chữ `V`. Script:
    
    ```python
    #brute-force.py
    import requests
    from requests import Session
    
    def register(s, name):
            r = s.post("<https://kerbal.sunshinectf.games/>", files={"name": (None, name)})
            cookie = r.headers["Set-Cookie"].split('=', 1)[1].split(';', 1)[0]
            return cookie
    
    s = requests
    
    for i in range(1, 36):
            print("%2d" % i, register(s, "V"*i))
    
    ```
    
    
    
2. Từ danh sách cookie mà ta lấy được từ việc brute-force, ta có thể suy ra được rằng:
- Khoảng độ dài username 8 → 24 sẽ khiến cookie thêm 1 block → Là 1 loại mã theo block 16 byte.
- Từ độ dài là 6 trở đi, block 32 byte đầu của cookie không đổi → prefix 10 kí tự sẽ khiến nó đủ 1 block 16 byte → plaintext có dạng (đoán nó là JSON):
    
    ```python
    0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV
    
    ```
    
- Ở độ dài là 8, việc cookie tăng độ dài → plaintext đủ 2 block 16 byte → thuật toán mã sẽ thêm 1 khối padding cho các plaintext là bội số của độ dài block (ở đây là 16) → plaintext khả năng rất có dạng (0 là số lượng moon ban đầu):
    
    ```python
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VV............0}
    
    ```
    
- Vậy để giải bài toán này, ta cần 1 cookie của plaintext sau:
    
    ```python
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VVVV............ 9999999999999999 }
    
    => need:
    first 2 of
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VVVV............ 0}
    +
    second of
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV 9999999999999999 ............0}
    +
    last of
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VVV............0 }
    
    ```
    
- Vậy những vì ta cần là 64 byte đầu của cookie cho username có 10 chữ `V` và 32 byte thứ 2 cho username 6 chữ `V` + 16 số `9` và byte cuối của username 9 chữ `V`.

---

## Kịch bản giải mã (Exploit)

Script cuối cùng để lấy cookie chiến thắng:

```python
import requests
from requests import Session

def register(s, name):
        r = s.post("https://kerbal.sunshinectf.games/", files={"name": (None, name)})
        cookie = r.headers["Set-Cookie"].split('=', 1)[1].split(';', 1)[0]
        return cookie

s = requests

s1 = Session()
cookie1 = register(s1, "V" * 10)

s2 = Session()
cookie2 = register(s2, "V" * 6 + "9" * 16)

s3 = Session()
cookie3 = register(s3, "V" * 9)

print(cookie1[:64] + cookie2[32:64] + cookie3[64:])
```
<img width="938" height="173" alt="image" src="https://github.com/user-attachments/assets/93d8aa50-d566-450f-86c8-4b8a3ac5cf24" />


**Kết quả (Flag)**

Khi thực thi kịch bản với dữ liệu từ thử thách, kết quả thu được sẽ là flag có định dạng `sun{...}`. Định dạng này khớp với thông tin về giải Sunshine CTF.
<img width="1479" height="594" alt="image" src="https://github.com/user-attachments/assets/f67f5447-9fe3-40c7-97a5-385966847063" />


<img width="1484" height="565" alt="image" src="https://github.com/user-attachments/assets/7d92c2c4-164e-4cb7-b2ce-2290f6fc20f1" />


`sun{g00d_j0b_u51ng_7h3_crumb5_70_m4k3_7h3_c00k13}`

---

## Ghi chú và mẹo

- **Dấu hiệu nhận biết ECB:** Dấu hiệu rõ ràng nhất của ECB là khi bạn thay đổi một phần của plaintext, chỉ có một khối ciphertext duy nhất thay đổi theo. Nếu thay đổi username chỉ làm thay đổi khối đầu tiên của cookie, đó gần như chắc chắn là ECB.
- **Tầm quan trọng của việc căn chỉnh (Alignment):** Chìa khóa của tấn công "Cut-and-Paste" là kiểm soát được ranh giới của các khối. Luôn bắt đầu bằng việc thử các input có độ dài khác nhau (`A`, `AA`, `AAA`...) để xác định chính xác kích thước khối và độ dài của prefix.
- **Chế tạo Payload thông minh:** Khi tạo payload trong username, hãy chắc chắn rằng chuỗi plaintext cuối cùng sau khi ghép nối vẫn hợp lệ (ví dụ: JSON không bị lỗi cú pháp). Tránh các ký tự đặc biệt như `"` hoặc `{}` nếu không cần thiết.
- **Tự động hóa là chìa khóa:** Việc brute-force độ dài và lấy cookie không thể thực hiện thủ công. Sử dụng script (Python với thư viện `requests` là một lựa chọn tuyệt vời) để tự động hóa quá trình thu thập dữ liệu và kiểm tra giả thuyết.

---

# ENGLISH VERSION

**Category:** Cryptography / Web

**Difficulty:** Hard

---

## Challenge Overview

The challenge provides an initial page that allows entering a username. After submitting a username, we are given a cookie for the main page, which displays:

- The username
- The number of moon clicks
- An image of a moon to click on

Each click refreshes the page with a new cookie and increments the moon count by one.

---

## Objective

The main objective is undoubtedly to analyze how the cookie is encrypted. From there, we can forge a valid cookie for an extremely large number of moons, something unattainable through manual clicking.

---

## Required Knowledge

To solve this challenge, a player needs basic knowledge of:

- **Block Ciphers:** Understanding how data is divided into fixed-size blocks (e.g., 16 bytes) and encrypted block by block.
- **Block Cipher Modes of Operation, especially ECB (Electronic Codebook):** Knowing ECB's critical weakness: identical plaintext blocks will always encrypt to identical ciphertext blocks. This is the key to identifying and exploiting the vulnerability.
- **ECB Cut-and-Paste Attack:** This is the classic attack technique against ECB mode, allowing an attacker to "cut" ciphertext blocks from different cookies and "paste" them together to create a new, valid, forged cookie.
- **JSON Data Structure:** Recognizing and understanding how data is serialized using JSON to guess and construct the plaintext structure.
- **HTTP Cookies:** Understanding how cookies work, how they are sent between the client and server, in order to modify and resubmit a forged cookie.

---

## Analysis and Approach

1. To obtain the necessary data for analysis, we'll run a script to brute-force the username POST request with strings from one `V` to 36 `V`s. Script:
    
    ```python
    #brute-force.py
    import requests
    from requests import Session
    
    def register(s, name):
            r = s.post("<https://kerbal.sunshinectf.games/>", files={"name": (None, name)})
            cookie = r.headers["Set-Cookie"].split('=', 1)[1].split(';', 1)[0]
            return cookie
    
    s = requests
    
    for i in range(1, 36):
            print("%2d" % i, register(s, "V"*i))
    
    ```
    
2. From the list of cookies obtained through brute-forcing, we can deduce the following:
- A username length between 8 and 24 characters causes the cookie to gain an additional block, indicating a 16-byte block cipher.
- For lengths of 6 and above, the first 16-byte block of the cookie remains unchanged. This means a 10-character prefix plus the 6-character username perfectly fills the first 16-byte block. The plaintext is likely JSON:
    
    ```python
    0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV
    
    ```
    
- At a length of 8, the cookie's length increases. This suggests the plaintext has reached a multiple of the block size (32 bytes), and the encryption algorithm adds a padding block. This strongly supports a plaintext structure like the following (where 0 is the initial moon count):
    
    ```python
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VV............0}
    
    ```
    
- Therefore, to solve this challenge, we need to forge a cookie for the following plaintext:
    
    ```python
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VVVV............ 9999999999999999 }
    
    => need:
    first 2 of
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VVVV............ 0}
    +
    second of
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV 9999999999999999 ............0}
    +
    last of
    0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF 0123456789ABCDEF
    {.........VVVVVV VVV............0 }
    
    ```
    

---

## Exploit Scenario

The final script to get the winning cookie:

```python
import requests
from requests import Session

def register(s, name):
        r = s.post("https://kerbal.sunshinectf.games/", files={"name": (None, name)})
        cookie = r.headers["Set-Cookie"].split('=', 1)[1].split(';', 1)[0]
        return cookie

s = requests

s1 = Session()
cookie1 = register(s1, "V" * 10)

s2 = Session()
cookie2 = register(s2, "V" * 6 + "9" * 16)

s3 = Session()
cookie3 = register(s3, "V" * 9)

print(cookie1[:64] + cookie2[32:64] + cookie3[64:])
```

**Result (Flag)**

Executing this script will produce the flag in the `sun{...}` format, which is consistent with the Sunshine CTF.

`sun{g00d_j0b_u51ng_7h3_crumb5_70_m4k3_7h3_c00k13}`

---

## Notes and Tips

- **The Telltale Sign of ECB:** The most obvious sign of ECB is that when you change a part of the plaintext input, only a single corresponding ciphertext block changes. If changing the username only alters the first block of the cookie, it's almost certainly ECB.
- **The Importance of Alignment:** The key to a successful Cut-and-Paste attack is controlling block boundaries. Always start by testing inputs of varying lengths (`A`, `AA`, `AAA`...) to precisely determine the block size and the length of any prefix.
- **Smart Payload Crafting:** When creating a payload within the username, ensure that the final, reassembled plaintext string is still valid (e.g., does not result in a JSON syntax error). Avoid special characters like `"` or `{}` unless necessary.
- **Automation is Key:** Brute-forcing lengths and fetching cookies is not feasible to do manually. Use a script (Python with the `requests` library is an excellent choice) to automate the process of data collection and hypothesis testing.
