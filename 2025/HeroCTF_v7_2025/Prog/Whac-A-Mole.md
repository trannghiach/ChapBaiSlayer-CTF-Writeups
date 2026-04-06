<img width="535" height="284" alt="image" src="https://github.com/user-attachments/assets/67f0fc52-a16c-4616-b9d2-24f54e9037c3" />

**Category:** Programming / Computer Vision
**Difficulty:** Easy/Medium (Speed focus)

### 1. Phân Tích Đề Bài (Analysis)

Server cung cấp một dịch vụ TCP chạy trên cổng 8000. Quy trình hoạt động như sau:

1. Server gửi một hình ảnh dưới dạng chuỗi **Base64**.
2. Người chơi phải giải mã ảnh, đếm số lượng "con chuột chũi" (moles) xuất hiện trong ảnh.
3. Gửi lại số lượng chính xác cho server.
4. Lặp lại quy trình này nhiều lần (khoảng 50-100 rounds).
5. **Ràng buộc:** Thời gian xử lý cực ngắn (Total timeout ~ 1 giây cho cả quá trình gửi/nhận). Nếu chậm -> `Timeout`.

### 2. Các Vấn Đề Gặp Phải (Challenges)

- **Nhiễu ảnh (Noise):** Nền cỏ có bóng râm (shadow) khiến việc tách chuột bằng độ sáng (Grayscale Threshold) không hiệu quả, dễ bị nhận nhầm bóng cỏ là chuột.
- **Độ trễ mạng (Network Latency):** Server đặt tại Pháp (`.fr`). Khi kết nối từ Việt Nam, ping rất cao (~300ms). Thời gian gửi/nhận gói tin chiếm gần hết quỹ thời gian 1s, dẫn đến timeout dù thuật toán nhanh đến đâu.

### 3. Giải Pháp (Solution)

**Chiến thuật xử lý ảnh (Image Processing Strategy):**
Thay vì cố gắng nhận diện màu nâu của chuột (khó vì chuột có nhiều sắc độ), ta sử dụng phương pháp **"Anti-Green" (Trừ khử màu xanh)**:

1. **Downscaling:** Thu nhỏ ảnh xuống 25% kích thước gốc để tăng tốc độ xử lý lên gấp 16 lần.
2. **HSV Masking:** Tạo mask để nhận diện vùng màu **Xanh lá cây (Cỏ)**.
3. **Invert Mask:** Đảo ngược vùng chọn -> Những gì **không phải cỏ** chính là chuột.
4. **Morphological Operations:** Sử dụng `Erode` và `Dilate` để khử nhiễu (các chấm cỏ nhỏ) và nối liền thân chuột.

**Chiến thuật hạ tầng (Infrastructure Strategy):**
Để khắc phục vấn đề ping cao, script bắt buộc phải chạy trên **Cloud Server** (như Google Colab hoặc VPS) có vị trí gần server mục tiêu để giảm độ trễ xuống mức thấp nhất.

### 4. Mã Khai Thác (Exploit Code)

```html
from pwn import *
import cv2
import numpy as np
import base64

# Cấu hình kết nối
HOST = "prog.heroctf.fr"
PORT = 8000

# Cấu hình bộ lọc màu XANH LÁ (Green) để loại bỏ
GREEN_LOWER = np.array([35, 40, 40])
GREEN_UPPER = np.array([90, 255, 255])

# Thu nhỏ ảnh còn 25% để tăng tốc
SCALE_FACTOR = 0.25  
MIN_AREA = 10 

context.log_level = 'error' 

def solve():
    io = remote(HOST, PORT)
    kernel = np.ones((3,3), np.uint8)

    while True:
        try:
            # Nhận dữ liệu ảnh
            io.recvuntil(b"IMAGE:\n", drop=True)
            b64img = io.recvline().strip()
            if not b64img: break

            # Giải mã & Thu nhỏ ảnh
            nparr = np.frombuffer(base64.b64decode(b64img), np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            small_img = cv2.resize(img, (0, 0), fx=SCALE_FACTOR, fy=SCALE_FACTOR)

            # Lọc màu: Giữ lại những gì KHÔNG PHẢI MÀU XANH
            hsv = cv2.cvtColor(small_img, cv2.COLOR_BGR2HSV)
            mask = cv2.inRange(hsv, GREEN_LOWER, GREEN_UPPER)
            mask_mole = cv2.bitwise_not(mask) # Invert

            # Khử nhiễu
            mask_mole = cv2.erode(mask_mole, kernel, iterations=1)
            mask_mole = cv2.dilate(mask_mole, kernel, iterations=2)

            # Đếm vật thể
            num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(mask_mole)
            count = 0
            for i in range(1, num_labels):
                if stats[i, cv2.CC_STAT_AREA] > MIN_AREA:
                    count += 1
            
            # Gửi đáp án
            io.sendlineafter(b">> ", str(count).encode())

        except EOFError:
            print(io.recvall().decode(errors='ignore')) # Print Flag
            break

if __name__ == "__main__":
    solve()
```

**Category:** Programming / Computer Vision
**Difficulty:** Easy/Medium (Speed focus)

### 1. Challenge Analysis

The server hosts a TCP service on port 8000. The workflow is as follows:

1. Server sends a **Base64** encoded image.
2. Player must decode the image and count the number of "moles".
3. Send the count back to the server.
4. Repeat for multiple rounds (50-100).
5. **Constraint:** Strict time limit (~1s total timeout). Slow responses result in a `Timeout`.

### 2. Obstacles

- **Image Noise:** The grass background contains shadows, making simple Grayscale Thresholding ineffective (shadows are misidentified as moles).
- **Network Latency:** The server is located in France (`.fr`). Connecting from Asia (Vietnam) results in high ping (~300ms). The round-trip time consumes most of the allowed 1-second window, causing timeouts regardless of script efficiency.

### 3. Solution

**Computer Vision Strategy:**
Instead of detecting the brown moles (which vary in shade), we use an **"Anti-Green" Strategy**:

1. **Downscaling:** Resize the image to 25% of its original size to boost processing speed by ~16x.
2. **HSV Masking:** Create a mask to isolate **Green (Grass)** pixels.
3. **Invert Mask:** Invert the selection -> Anything that is **NOT grass** is considered a mole.
4. **Morphological Operations:** Apply `Erode` and `Dilate` to remove noise (small grass blades) and merge mole segments.

**Infrastructure Strategy:**
To overcome the high latency, the script must be executed on a **Cloud Server** (e.g., Google Colab or a European VPS) to minimize ping to the challenge server.
```html
# ! CÀI ĐẶT THƯ VIỆN TRƯỚC (Chỉ dành cho Colab)
!pip install pwntools opencv-python-headless
# [BƯỚC 2] SỬA LỖI FILENO CHO COLAB (QUAN TRỌNG)
import sys
import os

# Đánh lừa pwntools rằng đây là terminal thật
if 'google.colab' in sys.modules:
    sys.stdout.fileno = lambda: 1
    sys.stderr.fileno = lambda: 2
    sys.stdin.fileno = lambda: 0

# [BƯỚC 3] CODE GIẢI CHALLENGE
from pwn import *
import cv2
import numpy as np
import base64
import time

# --- CẤU HÌNH ---
HOST = "prog.heroctf.fr"
PORT = 8000

# Cấu hình màu xanh lá để loại bỏ (Anti-Green)
GREEN_LOWER = np.array([35, 40, 40])
GREEN_UPPER = np.array([90, 255, 255])

SCALE_FACTOR = 0.25  # Thu nhỏ ảnh còn 25%
MIN_AREA_SCALED = 10 # Diện tích tối thiểu sau khi thu nhỏ

# Tắt log của pwntools để tránh spam màn hình
context.log_level = 'error' 

def solve():
    print(f"[+] Connecting to {HOST}:{PORT} via Google Colab...")
    
    try:
        io = remote(HOST, PORT)
    except Exception as e:
        print(f"[-] Không thể kết nối: {e}")
        return

    print("[+] Connected! Speed running...")
    
    # Kernel xử lý ảnh (tạo 1 lần dùng mãi mãi)
    kernel = np.ones((3,3), np.uint8)
    
    round_num = 0
    start_time = time.time()

    while True:
        try:
            # Nhảy cóc đến đoạn dữ liệu ảnh
            io.recvuntil(b"IMAGE:\n", drop=True)
            b64img = io.recvline().strip()
            
            if not b64img: break

            # 1. Decode ảnh
            nparr = np.frombuffer(base64.b64decode(b64img), np.uint8)
            img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            # 2. Thu nhỏ (Downscale) để tăng tốc xử lý
            small_img = cv2.resize(img, (0, 0), fx=SCALE_FACTOR, fy=SCALE_FACTOR)

            # 3. Lọc màu (Anti-Green Logic)
            hsv = cv2.cvtColor(small_img, cv2.COLOR_BGR2HSV)
            mask_grass = cv2.inRange(hsv, GREEN_LOWER, GREEN_UPPER)
            mask_mole = cv2.bitwise_not(mask_grass) # Đảo ngược: Không phải cỏ là chuột

            # 4. Khử nhiễu
            mask_mole = cv2.erode(mask_mole, kernel, iterations=1)
            mask_mole = cv2.dilate(mask_mole, kernel, iterations=2)

            # 5. Đếm
            num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(mask_mole)
            
            count = 0
            for i in range(1, num_labels):
                area = stats[i, cv2.CC_STAT_AREA]
                if area > MIN_AREA_SCALED:
                    count += 1
            
            # 6. Gửi đáp án
            io.sendlineafter(b">> ", str(count).encode())
            
            round_num += 1
            if round_num % 10 == 0:
                elapsed = time.time() - start_time
                print(f"Passed {round_num} rounds (Time: {elapsed:.2f}s)...")

        except EOFError:
            print("\n[-] Server đóng kết nối (Hoàn thành!).")
            # Hứng lấy Flag
            try:
                final_msg = io.recvall(timeout=2).decode(errors='ignore')
                print("\n" + "="*40)
                print("🏆 KẾT QUẢ CUỐI CÙNG:")
                print(final_msg)
                print("="*40)
            except: pass
            break
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break

if __name__ == "__main__":
    solve()
```

<img width="1125" height="348" alt="image" src="https://github.com/user-attachments/assets/03853ee6-0b29-4342-8ee9-b9d0a5caf2c7" />
