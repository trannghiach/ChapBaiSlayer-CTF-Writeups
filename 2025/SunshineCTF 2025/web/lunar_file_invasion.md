# Sunshine CTF 2025 — Lunar File Invasion

**Thể loại:** Web

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Thử thách cung cấp một trang web CMS (Hệ thống quản lý nội dung) mới được phát triển. Mô tả thử thách đề cập đến việc quản trị viên đã sử dụng tệp `robots.txt` để ngăn chặn các bot quét web, đồng thời gợi ý rằng không có bản vá lỗi nào được áp dụng. Người chơi phải khai thác một loạt các lỗ hổng, bắt đầu từ việc rò rỉ thông tin, bỏ qua xác thực hai yếu tố, và cuối cùng là khai thác lỗ hổng Path Traversal để đọc một tệp tin trên máy chủ và lấy flag.

---

## Mục tiêu

Mục tiêu chính là tìm và đọc tệp chứa flag trên máy chủ của ứng dụng web bằng cách khai thác các lỗ hổng bảo mật trong quá trình phân tích và tương tác với hệ thống.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức về:

- **Phân tích ứng dụng web:** Hiểu cách hoạt động của tệp `robots.txt`, `.gitignore` và cách chúng có thể làm rò rỉ thông tin nhạy cảm.
- **Lỗ hổng rò rỉ tệp sao lưu:** Nhận biết các tệp sao lưu do trình soạn thảo văn bản (ví dụ: Emacs với đuôi `~`) tạo ra.
- **Khai thác lỗ hổng logic nghiệp vụ:** Khả năng phát hiện và khai thác các sai sót trong luồng xử lý của ứng dụng, chẳng hạn như bỏ qua bước xác thực 2FA.
- **Lỗ hổng Path Traversal:** Hiểu và khai thác khả năng đọc các tệp tin tùy ý trên hệ thống máy chủ.
- **Kỹ thuật bypass Web Application Firewall (WAF):** Sử dụng các phương pháp như mã hóa URL (URL Encoding, Double URL Encoding) và các ký tự thay thế (`\\`) để vượt qua các bộ lọc bảo mật.
- **Sử dụng các công cụ pentest:** Thành thạo các công cụ như Burp Suite để chặn, sửa đổi và gửi lại các yêu cầu HTTP.

---

## Phân tích và hướng tiếp cận

Quá trình giải quyết thử thách có thể được chia thành các giai đoạn chính sau:

1. **Giai đoạn 1: Thu thập thông tin ban đầu**
    - Bắt đầu bằng cách kiểm tra tệp `robots.txt`. Tệp này tiết lộ nhiều đường dẫn ẩn, bao gồm `/.gitignore_test`.
    - Truy cập `/.gitignore_test`, chúng ta phát hiện ra rằng nhà phát triển đã đặt tên sai cho tệp `.gitignore`. Tệp này tiết lộ sự tồn tại của các tệp sao lưu có đuôi `~` được tạo bởi trình soạn thảo Emacs, cụ thể là `/index/static/login.html~`.
2. **Giai đoạn 2: Khai thác tệp sao lưu và bỏ qua đăng nhập**
    - Truy cập `/index/static/login.html~` để tải về mã nguồn của trang đăng nhập.
    - Mã nguồn này chứa thông tin đăng nhập được mã hóa cứng (hardcoded credentials): `admin@lunarfiles.muhammadali` và `jEJ&(32)DMC<!*###`.
    - Sử dụng thông tin này để đăng nhập, chúng ta được chuyển đến trang xác thực hai yếu tố (`/2FA`).
3. **Giai đoạn 3: Bỏ qua xác thực hai yếu tố (2FA)**
    - Tại trang `/2FA`, thay vì cố gắng đoán mã PIN, chúng ta thử truy cập lại trang `/login`.
    - Ứng dụng kiểm tra thấy phiên (session) đã được xác thực ở bước đăng nhập và chuyển hướng sai người dùng đến trang quản trị (`/admin/help`) thay vì yêu cầu hoàn thành 2FA. Đây là một lỗ hổng logic nghiệp vụ (Business Logic Bypass).
4. **Giai đoạn 4: Phân tích lỗ hổng Path Traversal**
    - Bên trong khu vực quản trị, chúng ta tìm thấy trang `/admin/lunar_files` cho phép xem các tệp tin.
    - Phân tích mã nguồn JavaScript của trang này cho thấy chức năng "View" gọi đến một điểm cuối (endpoint) `/admin/download/<filename>`. Tên tệp được truyền trực tiếp vào URL, đây là một dấu hiệu rõ ràng của lỗ hổng Path Traversal.
    - Các tệp `secret.txt` trên trang này cũng gợi ý về một cuộc tấn công Path Traversal trước đó nhắm vào `/etc/passwd`.
5. **Giai đoạn 5: Bypass WAF và các bộ lọc ứng dụng**
    - Nỗ lực khai thác Path Traversal với payload `../` bị chặn bởi lỗi `400 Bad Request`, cho thấy sự tồn tại của một Web Application Firewall (WAF).
    - Sử dụng kỹ thuật **Double URL Encoding** (mã hóa `%` thành `%25`) để bypass WAF. Yêu cầu thành công vượt qua WAF nhưng bị chặn bởi một bộ lọc trong chính ứng dụng, trả về lỗi `Succession of '../../' detected, forbidden`.
    - Để bypass bộ lọc này, chúng ta chèn thêm `.` (thư mục hiện tại) vào giữa các chuỗi `../`, tạo thành payload `.././../`. Kỹ thuật này đánh lừa bộ lọc của ứng dụng trong khi vẫn giữ nguyên chức năng của Path Traversal.
    - Sử dụng payload bypass này (đã được mã hóa hai lần), chúng ta có thể đọc thành công các tệp mã nguồn của ứng dụng như `views.py` và `app.py`.
6. **Giai đoạn 6: Tìm và đọc Flag**
    - Mã nguồn của `app.py` tiết lộ vị trí chính xác của flag:
        
        ```python
        with open("./FLAG/flag.txt", "r") as f:
            FLAG = f.read()
        ```
        
    - Vị trí này là tương đối so với tệp `app.py`. Dựa trên payload thành công trước đó (`../../../app.py`), chúng ta xác định đường dẫn cuối cùng đến flag là `../../../FLAG/flag.txt`.
    - Áp dụng lại kỹ thuật bypass bộ lọc `../..` và Double URL Encoding để xây dựng payload cuối cùng và đọc thành công tệp `flag.txt`.

---

## Kịch bản giải mã (Exploit)

Không có một kịch bản duy nhất, quá trình khai thác là một chuỗi các bước thủ công sử dụng trình duyệt và công cụ Burp Suite. Dưới đây là payload cuối cùng được sử dụng trong Burp Repeater để lấy flag.

1. **Đường dẫn mục tiêu:** `../../../FLAG/flag.txt`
2. **Payload Bypass:** `.././.././../FLAG/flag.txt`
3. **Payload Double URL Encoded:**
    
    ```
    %252e%252e%252f%252e%252f%252e%252e%252f%252e%252f%252e%252e%252fFLAG%252fflag.txt
    
    ```
    
4. **Yêu cầu HTTP đầy đủ (trong Burp Repeater):**
    
    ```
    GET /admin/download/%252e%252e%252f%252e%252f%252e%252e%252f%252e%252f%252e%252e%252fFLAG%252fflag.txt HTTP/2
    Host: asteroid.sunshinectf.games
    Cookie: session=<your_valid_session_cookie>
    ... (các header khác)
    
    ```
    

**Kết quả (Flag)**

Phản hồi từ yêu cầu trên sẽ là một tệp `flag.txt` với nội dung là flag của thử thách.

`sun{lfi_blacklists_ar3_sOo0o_2O16_8373uhdjehdugyedy89eudioje}`

---

## Ghi chú và mẹo

- Luôn bắt đầu một thử thách web bằng cách kiểm tra các tệp tin cơ bản như `robots.txt`, `sitemap.xml`, và các tệp cấu hình có thể bị lộ.
- Khi đối mặt với một WAF, hãy thử các kỹ thuật bypass phổ biến như mã hóa URL (một lần, hai lần), sử dụng các ký tự thay thế (`\\`), và thay đổi kiểu chữ (viết hoa/viết thường).
- Các thông báo lỗi khác nhau (`400 Bad Request`, `404 Not Found`, lỗi tùy chỉnh của ứng dụng) là những manh mối cực kỳ giá trị. Hãy phân tích xem lớp nào (WAF, máy chủ web, hay ứng dụng) đang trả về lỗi để điều chỉnh kỹ thuật tấn công cho phù hợp.
- Nếu không thể đọc tệp hệ thống, hãy luôn coi việc đọc mã nguồn của chính ứng dụng là mục tiêu hàng đầu.

---

# ENGLISH VERSION

**Category:** Web

**Difficulty:** Medium

---

## Challenge Overview

The challenge presents a newly developed Content Management System (CMS) website. The description mentions that administrators have implemented a `robots.txt` file to prevent web scrapers and hints that no new bug fixes have been applied. Players must exploit a chain of vulnerabilities, starting with information disclosure, bypassing two-factor authentication, and culminating in a Path Traversal vulnerability to read a file on the server and retrieve the flag.

---

## Objective

The primary objective is to find and read the flag file on the application's server by exploiting security vulnerabilities discovered during analysis and interaction with the system.

---

## Required Knowledge

To solve this challenge, players need knowledge of:

- **Web Application Analysis:** Understanding how files like `robots.txt` and `.gitignore` can lead to sensitive information disclosure.
- **Backup File Disclosure:** Recognizing backup files created by text editors (e.g., Emacs with a `~` suffix).
- **Business Logic Flaw Exploitation:** The ability to detect and exploit flaws in the application's workflow, such as bypassing a 2FA step.
- **Path Traversal:** Understanding and exploiting the ability to read arbitrary files on the server's file system.
- **WAF Bypass Techniques:** Using methods like URL Encoding (single, double) and alternative characters (`\\`) to evade security filters.
- **Proficiency with Pentesting Tools:** Mastery of tools like Burp Suite to intercept, modify, and resend HTTP requests.

---

## Analysis and Approach

The solution process can be broken down into several key stages:

1. **Stage 1: Initial Reconnaissance**
    - Begin by examining the `robots.txt` file. This file discloses several hidden paths, including `/.gitignore_test`.
    - Accessing `/.gitignore_test` reveals that the developer misnamed the `.gitignore` file. This file, in turn, discloses the existence of backup files with a `~` suffix created by the Emacs editor, specifically `/index/static/login.html~`.
2. **Stage 2: Backup File Exploitation and Login**
    - Access `/index/static/login.html~` to download the source code of the login page.
    - This source code contains hardcoded credentials: `admin@lunarfiles.muhammadali` and `jEJ&(32)DMC<!*###`.
    - Using these credentials to log in successfully redirects the user to a two-factor authentication (`/2FA`) page.
3. **Stage 3: Bypassing Two-Factor Authentication (2FA)**
    - At the `/2FA` page, instead of attempting to guess the PIN, we try navigating back to the `/login` page.
    - The application checks the session, sees that the user is already authenticated from the login step, and incorrectly redirects the user to the admin panel (`/admin/help`) instead of enforcing the 2FA completion. This is a classic Business Logic Bypass.
4. **Stage 4: Analyzing the Path Traversal Vulnerability**
    - Inside the admin area, we discover the `/admin/lunar_files` page, which allows viewing files.
    - Analyzing the page's JavaScript source code reveals that the "View" functionality calls the `/admin/download/<filename>` endpoint. The filename is passed directly in the URL, a strong indicator of a Path Traversal vulnerability.
    - The `secret.txt` files available on this page also hint at a previous Path Traversal attack targeting `/etc/passwd`.
5. **Stage 5: Bypassing the WAF and Application Filters**
    - Initial attempts to exploit the Path Traversal with a standard `../` payload are blocked with a `400 Bad Request` error, indicating the presence of a Web Application Firewall (WAF).
    - To bypass the WAF, **Double URL Encoding** is used (encoding `%` as `%25`). This successfully bypasses the WAF, but the request is then blocked by an application-level filter, which returns the error `Succession of '../../' detected, forbidden`.
    - To bypass this specific application filter, we insert a no-op directory (`./`) between the traversal sequences, creating a payload like `.././../`. This tricks the application's simple string check while preserving the traversal functionality.
    - Using this bypass payload (also double URL encoded), we are able to successfully read the application's source code files, such as `views.py` and `app.py`.
6. **Stage 6: Finding and Reading the Flag**
    - The source code of `app.py` reveals the exact location of the flag:
        
        ```python
        with open("./FLAG/flag.txt", "r") as f:
            FLAG = f.read()
        ```
        
    - This is a relative path, starting from the directory where `app.py` is executed. Based on our previously successful payload (`../../../app.py`), we determine the final path to the flag from the context of the download function is `../../../FLAG/flag.txt`.
    - We apply the same application filter bypass (`./` insertion) and Double URL Encoding technique to construct the final payload and read the `flag.txt` file.

---

## Exploitation Steps

The exploitation is a manual process using a browser and Burp Suite. The final payload used in Burp Repeater to retrieve the flag is constructed as follows.

1. **Target Path:** `../../../FLAG/flag.txt`
2. **Bypass Payload:** `.././.././../FLAG/flag.txt`
3. **Final Double URL Encoded Payload:**
    
    ```
    %252e%252e%252f%252e%252f%252e%252e%252f%252e%252f%252e%252e%252fFLAG%252fflag.txt
    
    ```
    
4. **Full HTTP Request (in Burp Repeater):**
    
    ```
    GET /admin/download/%252e%252e%252f%252e%252f%252e%252e%252f%252e%252f%252e%252e%252fFLAG%252fflag.txt HTTP/2
    Host: asteroid.sunshinectf.games
    Cookie: session=<your_valid_session_cookie>
    ... (other headers)
    
    ```
    

**Result (Flag)**

The response to the request above will be a `flag.txt` file containing the challenge flag.

`sun{lfi_blacklists_ar3_sOo0o_2O16_8373uhdjehdugyedy89eudioje}`

---

## Notes and Tips

- Always start a web challenge by checking for basic files like `robots.txt`, `sitemap.xml`, and any potentially exposed configuration files.
- When facing a WAF, try common bypass techniques such as URL encoding (single, double), using alternative characters (`\\`), and case variations.
- Different error messages (`400 Bad Request`, `404 Not Found`, custom application errors) are valuable clues. Analyze which layer (WAF, web server, or application) is returning the error to adapt your attack technique accordingly.
- If reading system files fails, always consider reading the application's own source code as a primary objective. It often contains credentials, logic flaws, or the flag itself.
