# SecurinetsCTF 2025 — Puzzle

**Thể loại:** Web / Full-chain web exploitation (enumeration → auth → file disclosure)

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Ứng dụng web “Puzzle” là một nền tảng viết lách đơn giản (Flask + SQLite). Mục tiêu thử thách là tìm flag nằm trong thư mục `/data` trên server, nhưng các tài nguyên nhạy cảm bị khóa (admin-only). Nhiệm vụ là dùng các lỗ hổng/thiết kế kém an toàn trong ứng dụng để leo lên quyền admin hoặc đọc file `/data/secrets.zip`, rồi giải nén để lấy flag.

---

## Mục tiêu

- Xác định cách truy cập file `/data/secrets.zip` trên server.
- Từ file `secrets.zip` giải nén để lấy nội dung file `data.txt` chứa flag.

---

## Kiến thức cần thiết

- HTTP / Web flow (cookies, session).
- Cách đọc/hiểu mã nguồn Flask (routes, session, decorators).
- SQLite / cơ bản thao tác với DB (trong trường hợp dump có sẵn).
- Sử dụng curl để tương tác web, unzip/7z để giải nén, `strings` để phân tích binary tĩnh.
- Phân tích logic ứng dụng: tìm cách dùng account bình thường (đã đăng ký) để thu thập thông tin nhạy cảm.

---

## Phân tích & Tóm tắt các yếu tố dễ khai thác (từ source & điều tra)

Từ mã nguồn (đã có access tới các file public) và khảo sát nhanh:

- `app.secret_key` cứng trong source công khai → rủi ro session forgery (tiềm năng).
- `models.init_db()` tạo một admin mặc định trong dump public, nhưng server run có thể khác — dump có thể không khớp DB đang chạy.
- `confirm-register` cho phép tạo tài khoản với `role=1` (editor) công khai → attacker có thể tự đăng ký editor. Editor có quyền gọi `/users/<uuid>` để lấy thông tin (bao gồm `password`) cho mọi user nếu biết UUID.
- Flow publish/collab: publish với `collaborator=<username>` sẽ tạo collab_request nếu collaborator tồn tại, và trang `/collaborations` hiển thị outgoing requests (kèm `request.uuid`). Quan trọng: khi recipient chấp nhận request, trang article show chứa `<span class="d-none collaborator-uuid">…</span>` → **collaborator UUID lộ ra**.
- `/data/` protected bằng `@admin_required` — chỉ admin mới truy cập, nhưng admin credential có thể rò rỉ (plaintext) qua `/users/<uuid>` nếu biết uuid, và editor có thể lấy uuid theo chain trên.
- `db` public có `old.db` (SQL dump) — chứa admin cũ, nhưng không phải database runtime → không dùng trực tiếp.

Từ điều tra trực tiếp (HTTP / files):

- Tạo tài khoản editor thành công, nhận password tạm.
- Dùng editor publish probe kết hợp collaborator tên khả nghi (admin, administrator, root, sysadmin, admin1, admin2 …) → ứng dụng trả `Collaboration request sent` cho một số tên — nghĩa là các username đó tồn tại (hoặc đã được tạo bởi người chơi khác).
- Truy cập `/collaborations` hiển thị outgoing requests và `request.uuid`. Thực hiện `accept` các requests bằng account của attacker → server tạo bài article cho mỗi request. Mở article thấy HTML chứa `<span class="d-none collaborator-uuid">...< /span>` → collaborator UUID lộ ra (điểm then chốt).
- Dùng collaborator UUID gọi `/users/<collab_uuid>` (với cookie editor) → trả JSON chứa thông tin: username/email/phone/role/password. Một trong các collaborator trả về role `"0"` (admin) cùng **plaintext password**.

Kết luận: chuỗi tấn công ngắn gọn:

1. Register editor → login (ta đã có cookie editor).
2. publish → tạo collab_requests tới candidate usernames.
3. accept outgoing requests → article xuất hiện và lộ collaborator UUID.
4. query `/users/<collab_uuid>` → lấy admin username + plaintext password.
5. login admin → truy cập `/data` → download `secrets.zip`.
6. đọc `dbconnect.exe` với `strings` → tìm mật khẩu trong binary → dùng mật khẩu để giải nén `secrets.zip`.
7. đọc `data.txt` → flag.

---

## Chi tiết kịch bản khai thác (các bước & lệnh đã thực hiện)

> Ghi chú: mình tóm tắt chỉ phần cần thiết, giữ đúng logic và các lệnh đã chạy (đã thực thi bằng curl/terminal).
> 

### 1. Tạo account Editor (public `confirm-register` cho phép role=1)

- Gửi POST `/confirm-register` với `role=1`. Server trả password tạm:
    
    ```
    k0NqVY1fjc9X
    
    ```
    
    Cookie session của user attacker lưu ở `cookies.txt`.
    

### 2. Dò username bằng `/publish`

- Thử lần lượt các username khả nghi (`admin`, `administrator`, `root`, `sysadmin`, `admin1`, `admin2`, …) bằng POST `/publish` với `collaborator=<candidate>`.
- Kết quả: `Collaboration request sent` cho một số username (ví dụ admin, administrator, root, sysadmin, admin1, admin2).
    
    (Ứng dụng chia sẻ DB giữa người chơi nên các username có thể do người chơi khác tạo — nhưng điều quan trọng là request tồn tại.)
    

### 3. Xem outgoing requests → lấy request UUIDs

- Truy cập `/collaborations` (sử dụng cookie editor) — trang hiển thị các outgoing requests:
    
    ```
    Sent to admin
    Sent to administrator
    Sent to root
    Sent to sysadmin
    Sent to admin1
    Sent to admin2
    
    ```
    
- Mỗi card có một `request.uuid` (hidden span). Ví dụ:
    
    ```
    adb67964-c809-49bf-ba67-80d5be4a5296
    4eedc17b-f0c2-41a3-be93-488ab85ac592
    ...
    
    ```
    

### 4. Accept các request (editor) để tạo article

- Gọi `POST /collab/accept/<request_uuid>` cho mỗi `request_uuid`.
- Server chèn article dựa trên `collab_requests` (sử dụng `article_uuid` từ request).

### 5. Mở bài viết (article) — collaborator UUID lộ ra

- Tham chiếu article URL `/article/<article_uuid>` — HTML chứa:
    
    ```html
    <span class="d-none author-uuid">c7f6a520-e886-4bca-9426-b2299603a99f</span>
    <span class="d-none collaborator-uuid">2c389240-d72c-48bd-b9e6-f34054613cf4</span>
    <small>Posted by attacker1 in collaboration with admin1 on 2025-10-04 15:32:27</small>
    
    ```
    
- Dùng `collaborator-uuid` để gọi `/users/<collab_uuid>`.

### 6. Truy vấn `/users/<collab_uuid>` (lấy thông tin)

- Ví dụ gọi `/users/9075229d-9bcd-4f8b-9fb0-a484cb3bf914` trả:
    
    ```json
    {
      "email": "admin@securinets.tn",
      "password": "Adm1nooooX333!123!!%",
      "phone_number": "77777777",
      "role": "0",
      "username": "admin",
      "uuid": "9075229d-9bcd-4f8b-9fb0-a484cb3bf914"
    }
    
    ```
    
- **Kết quả then chốt:** admin username + plaintext password (role == "0").

### 7. Login admin & truy cập `/data/`

- Login admin bằng `username=admin`, `password=Adm1nooooX333!123!!%` (thực hiện qua form web, lưu cookie admin).
- Truy cập `/data/` (admin-only) hiển thị:
    
    ```
    secrets.zip 198 bytes
    dbconnect.exe 45853 bytes
    
    ```
    

### 8. Tải file `secrets.zip` và `dbconnect.exe`

- Download `secrets.zip` và `dbconnect.exe` (không thực thi .exe).

### 9. Phân tích `dbconnect.exe` (tĩnh)

- Dùng `strings dbconnect.exe | egrep -i 'server|user|pass|secret|flag|securinets'` phát hiện:
    
    ```
    server = '127.0.0.1'
    username = 'sa'
    password = 'PUZZLE+7011_X207+!*'
    ...
    _flag
    
    ```
    
- **Quan trọng:** `dbconnect.exe` chứa password `PUZZLE+7011_X207+!*`.

### 10. Giải nén `secrets.zip` bằng mật khẩu thu được

- Dùng 7z/unzip với mật khẩu:
    
    ```
    PUZZLE+7011_X207+!*
    
    ```
    
- Giải nén thành công, file `data.txt` chứa flag:
    
    ```
    Securinets{777_P13c3_1T_Up_T0G3Th3R}
    
    ```
    

---

## Flag

`Securinets{777_P13c3_1T_Up_T0G3Th3R}`

---

## Postmortem — bài học & khuyến nghị bảo mật

### Nguyên nhân gốc rễ (vấn đề)

1. **Rò rỉ thông tin nhạy cảm qua endpoint không hợp lý**
    - `/users/<uuid>` trả cả `password` (plaintext) — KHÔNG BAO GIỜ lưu/hiển thị mật khẩu plaintext.
    - `confirm-register` cho phép tạo role cao (`editor`) công khai — cho phép attacker leo theo luồng đọc thông tin.
2. **Thiết kế thông tin lộ dần (information disclosure flow)**
    - Trang article chứa các `span` ẩn với `author-uuid` và `collaborator-uuid` — vô tình tiết lộ UUID người dùng. Những giá trị này kết hợp với endpoint `/users/<uuid>` gây rò rỉ dữ liệu.
3. **Mật khẩu/khóa nhúng trong file nhị phân trên server**
    - `dbconnect.exe` chứa credentials viết cứng (hard-coded) — cho phép giải mã nội dung mật khẩu-protected.

### Cách khắc phục (recommended fixes)

- **Không lưu mật khẩu plaintext.** Luôn hash mật khẩu dùng bcrypt/argon2 và không xuất trường password qua API.
- **Hạn chế thông tin trả về từ API:** endpoint `/users/<uuid>` chỉ nên trả thông tin không nhạy cảm (username, role), chỉ admin mới có quyền hạn chế, và KHÔNG trả password.
- **Không đưa UUID người dùng (hoặc thông tin nhạy cảm) vào DOM ẩn** nếu không cần thiết; nếu cần, mã hóa hoặc ẩn server-side.
- **Kiểm soát role assignment:** `confirm-register` không nên cho phép tự chọn role (đặc biệt roles cao). Role phải được gán thủ công/qua quy trình kiểm duyệt.
- **Tránh hard-coded secrets trong binary:** di chuyển secrets vào vault, cấu hình an toàn, hoặc bảo vệ file nhị phân (hoặc tốt nhất không để file nhị phân có chứa secrets trên webserver).

---

## ENGLISH VERSION

**Category:** Web / Full-chain web exploitation (enumeration → auth → file disclosure)

**Difficulty:** Medium

### Overview

Puzzle is a Flask + SQLite web app. The flag is in `/data/secrets.zip` and access is restricted to admin. The challenge was to escalate from an attacker account to admin or otherwise retrieve secrets and extract the flag.

### Objective

Retrieve `/data/secrets.zip`, extract `data.txt`, and read the flag.

### Key ideas & Vulnerabilities

- Public registration allowed `role=1` (editor) → attacker can create an editor account.
- Articles contain hidden DOM spans with `author-uuid` and `collaborator-uuid`. After accepting collaboration requests the collaborator uuid becomes visible in article HTML.
- `/users/<uuid>` returns a JSON containing `password` (plaintext) — huge information leak.
- `dbconnect.exe` included on server contains hard-coded password used to unlock `secrets.zip`.

### Exploit summary (steps)

1. Register as editor (public endpoint). Save session cookies.
2. Use `/publish` to create collaboration requests to many candidate usernames.
3. View `/collaborations`, accept requests, then open the created articles. Extract `collaborator-uuid` from the article HTML (`<span class="d-none collaborator-uuid">…</span>`).
4. Call `/users/<collab_uuid>` using editor cookie → obtain admin account info and **plaintext password**: `Adm1nooooX333!123!!%`.
5. Login as admin and visit `/data` → download `secrets.zip` and `dbconnect.exe`.
6. Run `strings dbconnect.exe` → find password `PUZZLE+7011_X207+!*`.
7. Use that password to extract `secrets.zip` → open `data.txt` → read flag.

### Flag

`Securinets{777_P13c3_1T_Up_T0G3Th3R}`

### Mitigations (recap)

- Do not expose passwords via APIs. Hash passwords.
- Minimize sensitive data in DOM.
- Disallow user-controlled role escalation.
- Remove hard-coded credentials from binaries and configuration on servers.
