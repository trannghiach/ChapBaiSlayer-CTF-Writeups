# QnQSec CTF 2025 — s3cr3ct_w3b
---

- **Category:** Web
- **Tags:** SQL Injection, XXE, Authentication Bypass, File Disclosure
- Author: LemonTea

---

## **1. Challenge Summary**

The challenge presented a web application with two primary components: a PHP login page and an XML parsing feature accessible after authentication. The goal was to find the secret flag hidden on the server. This required chaining two vulnerabilities: first, bypassing the login form using a classic SQL Injection, and second, exploiting an XML External Entity (XXE) vulnerability in the parser to read the flag file from the server's local filesystem.

---

## **2. Initial Analysis & Reconnaissance**

The source code for `login.php`, `index.php`, and `api.php` was provided.

- **`login.php`:** A review of the source code revealed a critical vulnerability. The SQL query for user authentication was constructed by directly concatenating user-provided `username` and `password` variables into the query string, making it a textbook case for SQL Injection.PHP
    
    `$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";`
    
- **`api.php`:** This file handled the XML parsing logic. The code showed that it used PHP's `DOMDocument` to load user-submitted XML. Critically, it used the `LIBXML_NOENT` and `LIBXML_DTDLOAD` flags, which is a well-known insecure configuration that enables XXE attacks.PHP
    
    `if (!@$dom->loadXML($xml, LIBXML_DTDLOAD | LIBXML_NOENT)) {
        // ...
    }`
    
- **`Dockerfile`:** This configuration file was key. It showed that the `flag.txt` was not at the filesystem root (`/`) but was copied into the web root at `/var/www/html/`.

---

## **3. The Vulnerabilities**

- Vulnerability 1: SQL Injection (Authentication Bypass)
    
    The login form was vulnerable because it did not use prepared statements or sanitize user input. An attacker could inject SQL metacharacters to manipulate the WHERE clause of the query, making it always evaluate to true and thus bypassing the authentication check entirely.
    
- Vulnerability 2: XML External Entity (XXE) Injection
    
    The XML parser was configured to resolve external entities. This allowed an attacker to craft a malicious XML document with a DOCTYPE definition that declared an external entity pointing to a local file URI (e.g., file:///...). When the parser processed this XML, it would replace the entity with the contents of the specified local file, disclosing its contents in the response.
    

---

## **4. Exploitation Steps**

1. **Bypass Authentication:** To log in without valid credentials, the following payload was used in the `username` field of the login form, with a random password:
    - **Username:** `' OR '1'='1' --`
    - This payload modified the SQL query to `... WHERE username = '' OR '1'='1' -- ' AND password = '...'`, which is always true, granting access.
2. **Confirm XXE Vulnerability:** After successfully logging in, we accessed the XML parser. To confirm the XXE vulnerability, a payload to read `/etc/passwd` was created and uploaded. The server responded with the contents of the file, confirming local file disclosure was possible.
3. **Locate and Read the Flag:** Based on the `Dockerfile`, the flag was known to be at `/var/www/html/flag.txt`. The final payload was crafted to read this specific file.

---

## **5. Final Exploit / Payload**

The following XML content was saved as `payload.xml` and uploaded to the XML parser to retrieve the flag:

XML
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/flag.txt"> ]>
<data>&xxe;</data>
```

The server's response contained the flag: `QnQSec{sql1+XXE_1ng3tion_but_using_php_filt3r}`.

---

## **6. Key Takeaways & Lessons Learned**

- **Lesson 1:** Never trust user input. The lack of prepared statements in the login form is a classic, high-severity vulnerability that immediately grants an initial foothold.
- **Lesson 2:** Enabling entity parsing in an XML library (`LIBXML_NOENT`) is almost always a security risk and should be a primary target for testing during any web assessment.
- **Lesson 3:** Context is crucial. When standard file paths like `/flag.txt` don't work, reviewing configuration files like a `Dockerfile` can provide the exact location of the target file, saving significant time.

---

# TIẾNG VIỆT

- **Chuyên mục:** Web
- **Tags:** SQL Injection, XXE, Authentication Bypass, File Disclosure

---

## **1. Tóm tắt Thử thách**

Thử thách đưa ra một ứng dụng web với hai thành phần chính: một trang đăng nhập bằng PHP và một tính năng phân tích cú pháp XML có thể truy cập sau khi xác thực. Mục tiêu là tìm ra flag bí mật được giấu trên máy chủ. Để hoàn thành, cần phải xâu chuỗi hai lỗ hổng: đầu tiên, vượt qua biểu mẫu đăng nhập bằng SQL Injection cổ điển, và thứ hai, khai thác lỗ hổng XML External Entity (XXE) trong trình phân tích cú pháp để đọc file chứa flag từ hệ thống tệp cục bộ của máy chủ.

---

## **2. Phân tích & Trinh sát Ban đầu**

Mã nguồn của `login.php`, `index.php`, và `api.php` đã được cung cấp.

- **`login.php`:** Xem xét mã nguồn đã phát hiện ra một lỗ hổng nghiêm trọng. Truy vấn SQL để xác thực người dùng được xây dựng bằng cách nối trực tiếp biến `username` và `password` do người dùng cung cấp vào chuỗi truy vấn, biến nó thành một trường hợp điển hình cho SQL Injection.PHP
    
    `$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";`
    
- **`api.php`:** File này xử lý logic phân tích XML. Mã nguồn cho thấy nó sử dụng `DOMDocument` của PHP để tải XML do người dùng gửi lên. Quan trọng là, nó đã sử dụng các cờ `LIBXML_NOENT` và `LIBXML_DTDLOAD`, đây là một cấu hình không an toàn đã biết, cho phép các cuộc tấn công XXE.PHP
    
    `if (!@$dom->loadXML($xml, LIBXML_DTDLOAD | LIBXML_NOENT)) {
        // ...
    }`
    
- **`Dockerfile`:** File cấu hình này là chìa khóa. Nó cho thấy `flag.txt` không nằm ở thư mục gốc của hệ thống tệp (`/`) mà đã được sao chép vào thư mục gốc của web tại `/var/www/html/`.

---

## **3. Các Lỗ hổng**

- Lỗ hổng 1: SQL Injection (Vượt qua Xác thực)
    
    Biểu mẫu đăng nhập dễ bị tấn công vì nó không sử dụng các câu lệnh đã được chuẩn bị (prepared statements) hoặc làm sạch đầu vào của người dùng. Kẻ tấn công có thể chèn các ký tự đặc biệt của SQL để thao túng mệnh đề WHERE của truy vấn, làm cho nó luôn trả về giá trị đúng và do đó vượt qua hoàn toàn việc kiểm tra xác thực.
    
- Lỗ hổng 2: XML External Entity (XXE) Injection
    
    Trình phân tích XML được cấu hình để giải quyết các thực thể bên ngoài. Điều này cho phép kẻ tấn công tạo ra một tài liệu XML độc hại với định nghĩa DOCTYPE khai báo một thực thể bên ngoài trỏ đến một URI tệp cục bộ (ví dụ: file:///...). Khi trình phân tích xử lý XML này, nó sẽ thay thế thực thể bằng nội dung của tệp cục bộ được chỉ định, tiết lộ nội dung của nó trong phản hồi.
    

---

## **4. Các Bước Khai thác**

1. **Vượt qua Xác thực:** Để đăng nhập mà không cần thông tin hợp lệ, payload sau đã được sử dụng trong trường `username` của biểu mẫu đăng nhập, với một mật khẩu ngẫu nhiên:
    - **Username:** `' OR '1'='1' --`
    - Payload này đã sửa đổi truy vấn SQL thành `... WHERE username = '' OR '1'='1' -- ' AND password = '...'`, điều này luôn đúng, cấp quyền truy cập.
2. **Xác nhận Lỗ hổng XXE:** Sau khi đăng nhập thành công, ta đã truy cập trình phân tích XML. Để xác nhận lỗ hổng XXE, một payload để đọc `/etc/passwd` đã được tạo và tải lên. Máy chủ đã phản hồi với nội dung của tệp, xác nhận rằng việc tiết lộ tệp cục bộ là có thể.
3. **Xác định vị trí và Đọc Flag:** Dựa trên `Dockerfile`, flag được biết là nằm tại `/var/www/html/flag.txt`. Payload cuối cùng đã được tạo ra để đọc tệp cụ thể này.

---

## **5. Exploit / Payload Cuối cùng**

Nội dung XML sau đã được lưu dưới dạng `payload.xml` và tải lên trình phân tích XML để lấy flag:

XML
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/flag.txt"> ]>
<data>&xxe;</data>
```

Phản hồi của máy chủ chứa flag: `QnQSec{sql1+XXE_1ng3tion_but_using_php_filt3r}`.

---

## **6. Bài học Kinh nghiệm**

- **Bài học 1:** Không bao giờ tin tưởng vào đầu vào của người dùng. Việc thiếu các câu lệnh đã được chuẩn bị trong biểu mẫu đăng nhập là một lỗ hổng cổ điển, có mức độ nghiêm trọng cao, ngay lập tức tạo ra một điểm tựa ban đầu.
- **Bài học 2:** Việc kích hoạt phân tích thực thể trong một thư viện XML (`LIBXML_NOENT`) gần như luôn là một rủi ro bảo mật và nên là mục tiêu kiểm tra hàng đầu trong bất kỳ cuộc đánh giá web nào.
- **Bài học 3:** Bối cảnh là rất quan trọng. Khi các đường dẫn tệp tiêu chuẩn như `/flag.txt` không hoạt động, việc xem xét các tệp cấu hình như `Dockerfile` có thể cung cấp vị trí chính xác của tệp mục tiêu, tiết kiệm thời gian đáng kể.
