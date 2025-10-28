# Sunshine CTF 2025 — Remotely Interesting

**Thể loại:** Forensics

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Thử thách cung cấp một file memory dump (`dwn.exe.dmp`) nặng gần 2GB của tiến trình Desktop Window Manager từ một máy trạm Windows. Bối cảnh được đưa ra là một nhà khoa học đang kết nối RDP thì thấy một cửa sổ lạ hiện lên và ngay sau đó bị khóa khỏi hệ thống. Nhiệm vụ của người chơi là phân tích file dump để tìm ra nội dung của "cửa sổ lạ" đó.

---

## Mục tiêu

Mục tiêu chính là tái tạo lại hình ảnh màn hình của người dùng tại thời điểm xảy ra sự cố từ file memory dump. Cờ (flag) của thử thách được cho là nằm bên trong nội dung của cửa sổ lạ đã xuất hiện.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức về:

- **Memory Forensics:** Hiểu biết cơ bản về memory dump và tại sao tiến trình `dwm.exe` lại quan trọng đối với việc tái tạo giao diện đồ họa.
- **Dữ liệu ảnh thô (Raw Image Data):** Nhận biết rằng hình ảnh trong bộ nhớ không phải lúc nào cũng được lưu dưới dạng file có cấu trúc (như PNG, JPG) mà thường tồn tại dưới dạng một khối pixel thô (raw bitmap buffer).
- **Các tham số đồ họa:** Hiểu các khái niệm về Độ phân giải (Width, Height), Thứ tự kênh màu (RGBA/BGRA), và đặc biệt là Stride/Pitch (số byte thực tế của một hàng pixel trong bộ nhớ).
- **Lập trình (Python):** Sử dụng Python và thư viện xử lý ảnh như Pillow để đọc, phân tích và tái tạo hình ảnh từ dữ liệu nhị phân thô.

---

## Phân tích và hướng tiếp cận

Hướng tiếp cận ban đầu là sử dụng các công cụ file carving tiêu chuẩn như `binwalk` hoặc `foremost` để trích xuất các file ảnh hoàn chỉnh từ file dump. Tuy nhiên, phương pháp này chỉ thu được hàng ngàn icon và thành phần giao diện người dùng nhỏ lẻ, không có ảnh chụp màn hình nào hoàn chỉnh. Điều này củng cố giả thuyết rằng hình ảnh cần tìm tồn tại dưới dạng dữ liệu đồ họa thô.

Con đường giải quyết đúng đắn là một phương pháp brute-force thông minh để quét tìm khối dữ liệu đồ họa thô này.

1. **Giai đoạn 1: Quét thô để tìm vùng dữ liệu tiềm năng**
    - Giả định rằng buffer ảnh nằm đâu đó trong file dump 2GB.
    - Viết một kịch bản để "nhảy" qua các đoạn lớn của file (ví dụ: mỗi 16MB) để tiết kiệm thời gian.
    - Tại mỗi vị trí, thử diễn giải một khối dữ liệu như một hình ảnh bằng cách áp dụng các tham số phổ biến:
        - **Độ phân giải:** Thử các độ phân giải thường gặp (`1920x1080`, `1366x768`, `1024x768`, v.v.).
        - **Thứ tự màu:** Thử cả `RGBA` và `BGRA` (Windows thường dùng `BGRA`).
    - Kết quả của giai đoạn này là một hình ảnh bị lỗi (`offset_16777216_1024x768_BGRA.png`). Hình ảnh này có phần trên là nhiễu và phần dưới là một phần của desktop bị cắt mất phía dưới. Đây là một manh mối quan trọng.
2. **Giai đoạn 2: Tinh chỉnh Offset Bắt đầu**
    - Phân tích hình ảnh lỗi cho thấy `Stride` (số byte mỗi hàng) có vẻ đã đúng (`1024 * 4 = 4096`), vì các cạnh dọc của cửa sổ đều thẳng.
    - Vấn đề nằm ở `Offset` bắt đầu. Offset `16777216` trỏ vào vùng dữ liệu nhiễu nằm ngay *trước* buffer ảnh thật.
    - Hướng tiếp cận mới là giữ nguyên các tham số khác (Width, Height, Stride) và "trượt" offset bắt đầu về phía sau, mỗi lần trượt đúng bằng một hàng pixel (`4096` bytes).
    - Tại mỗi offset mới, tái tạo lại toàn bộ hình ảnh `1024x768`. Một trong các hình ảnh được tạo ra sẽ có điểm bắt đầu hoàn hảo, hiển thị toàn bộ màn hình từ trên xuống dưới.

---

## Kịch bản giải mã (Exploit)

Quá trình giải quyết yêu cầu hai kịch bản chính.

**Kịch bản 1: `raw_scanner.py` (Để tìm vùng dữ liệu ban đầu)**
Kịch bản này thực hiện việc quét thô trên toàn bộ file dump để tìm ra offset và các tham số gần đúng.

```python
# raw_scanner.py
# (Xem chi tiết ở các phản hồi trước)
# Mục đích: Quét file dwn.exe.dmp theo từng khoảng lớn,
# thử các độ phân giải và chế độ màu phổ biến để tìm ra
# một hình ảnh có thể nhận dạng được, dù bị lỗi.

```

**Kịch bản 2: `find_correct_offset.py` (Để tìm Offset chính xác và tái tạo ảnh hoàn chỉnh)**
Sau khi có offset cơ sở và stride đúng từ giai đoạn 1, kịch bản này sẽ tinh chỉnh lại vị trí bắt đầu.

```python
# find_correct_offset.py
import os
from PIL import Image

# --- Cấu hình ---
DUMP_FILE = 'dwn.exe.dmp'
OUTPUT_DIR = 'offset_finetune'
BASE_OFFSET = 16777216  # Offset sai tìm được từ giai đoạn 1
WIDTH = 1024
HEIGHT = 768
CORRECT_STRIDE = 4096  # Stride đúng (Width * 4 bytes/pixel)
SEARCH_ROWS = 500      # Số hàng pixel sẽ trượt để tìm kiếm

# --- Bắt đầu Script ---
if not os.path.exists(DUMP_FILE): exit()
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(DUMP_FILE, 'rb') as f:
    for row_shift in range(SEARCH_ROWS):
        current_offset = BASE_OFFSET + (row_shift * CORRECT_STRIDE)
        f.seek(current_offset)

        buffer_size_needed = HEIGHT * CORRECT_STRIDE
        source_buffer = f.read(buffer_size_needed)

        if len(source_buffer) < buffer_size_needed: break

        try:
            repaired_data = bytearray()
            min_stride = WIDTH * 4
            for y in range(HEIGHT):
                line_start = y * CORRECT_STRIDE
                line_end = line_start + min_stride
                repaired_data.extend(source_buffer[line_start:line_end])

            img = Image.frombytes('RGBA', (WIDTH, HEIGHT), bytes(repaired_data), 'raw', 'BGRA')
            img.save(os.path.join(OUTPUT_DIR, f"offset_{current_offset}.png"))
        except:
            pass

print("Hoàn thành! Kiểm tra thư mục 'offset_finetune'.")

```

**Kết quả (Flag)**

Sau khi chạy kịch bản thứ hai, thư mục `offset_finetune` sẽ chứa một loạt ảnh. Bằng cách xem lướt qua, ta có thể tìm thấy một hoặc nhiều ảnh hiển thị đầy đủ màn hình. Hộp thoại ransomware hiện rõ nội dung và cờ.

`sun{r3m0t3_pwn4g3_QQ}`

---

## Ghi chú và mẹo

- Đây là một ví dụ điển hình cho thấy dữ liệu trong bộ nhớ không phải lúc nào cũng được lưu trữ gọn gàng. Thay vì tìm kiếm file, đôi khi chúng ta phải "tái tạo" lại dữ liệu từ các khối thô.
- Các lỗi và hiện vật trực quan (như ảnh bị xé, bị nhiễu) không phải là thất bại. Chúng là những manh mối cực kỳ giá trị giúp chúng ta hiểu sai ở đâu (sai offset, sai stride, sai độ phân giải) để tinh chỉnh lại các tham số.
- Một hướng giải quyết khác, mang tính "pháp y" hơn, là sử dụng Volatility 2 với plugin `screenshot`. Công cụ này được thiết kế để hiểu cấu trúc của DWM và có thể tái tạo lại màn hình một cách tự động. Tuy nhiên, phương pháp brute-force bằng kịch bản cho thấy sự linh hoạt và sáng tạo cũng có thể dẫn đến kết quả.

---

# ENGLISH VERSION

**Category:** Forensics

**Difficulty:** Medium

---

## Challenge Overview

The challenge provides a memory dump file (`dwn.exe.dmp`), nearly 2GB in size, from the Desktop Window Manager process on a Windows workstation. The context is that a scientist, connected via RDP, saw a strange window appear and was subsequently locked out of the system. The player's task is to analyze the dump file to find out what the scientist saw.

---

## Objective

The primary objective is to reconstruct the user's screen at the time of the incident from the provided memory dump. The challenge flag is expected to be located within the content of the strange window that appeared.

---

## Required Knowledge

To solve this challenge, players need knowledge of:

- **Memory Forensics:** A basic understanding of memory dumps and why the `dwm.exe` process is critical for reconstructing the graphical user interface.
- **Raw Image Data:** Recognizing that images in memory are not always stored as structured files (like PNG, JPG) but often exist as a raw bitmap buffer.
- **Graphics Parameters:** Understanding concepts like Resolution (Width, Height), Channel Order (RGBA/BGRA), and especially Stride/Pitch (the actual number of bytes in a single row of pixels in memory).
- **Scripting (Python):** Using Python and an image processing library like Pillow to read, parse, and reconstruct an image from raw binary data.

---

## Analysis and Approach

The initial approach involves using standard file carving tools like `binwalk` or `foremost` to extract complete image files from the dump. However, this method only yields thousands of small icons and UI elements, with no complete screenshot. This reinforces the hypothesis that the target image exists as raw graphical data.

The correct solution path is an intelligent brute-force method to scan for this raw graphical data block.

1. **Phase 1: Rough Scan for a Potential Data Region**
    - Assume the image buffer lies somewhere within the 2GB dump file.
    - Write a script to "jump" through the file in large steps (e.g., 16MB at a time) to save time.
    - At each location, attempt to interpret a block of data as an image by applying common parameters:
        - **Resolution:** Try common screen resolutions (`1920x1080`, `1366x768`, `1024x768`, etc.).
        - **Channel Order:** Try both `RGBA` and `BGRA` (Windows often uses `BGRA`).
    - The result of this phase is a corrupted image (`offset_16777216_1024x768_BGRA.png`). This image has garbage data at the top and a partial view of the desktop at the bottom, which is cut off. This is a critical clue.
2. **Phase 2: Fine-Tuning the Starting Offset**
    - Analysis of the corrupted image suggests the `Stride` (bytes per row) is likely correct (`1024 * 4 = 4096`), as the vertical edges of the window are perfectly straight.
    - The problem lies with the starting `Offset`. The offset `16777216` points to the garbage data *before* the actual image buffer begins.
    - The new approach is to keep the other parameters (Width, Height, Stride) constant and "slide" the starting offset forward, one row of pixels (`4096` bytes) at a time.
    - At each new offset, reconstruct the full `1024x768` image. One of the generated images will have the perfect starting point, displaying the entire screen from top to bottom.

---

## Exploit Script

The solution requires two main scripts.

**Script 1: `raw_scanner.py` (To find the initial data region)**
This script performs a rough scan across the entire dump file to find the approximate offset and parameters.

```python
# raw_scanner.py
# (See previous responses for full code)
# Purpose: To scan dwn.exe.dmp in large chunks,
# trying common resolutions and color modes to find any
# recognizable, albeit corrupted, image.

```

**Script 2: `find_correct_offset.py` (To find the precise Offset and reconstruct the final image)**
After obtaining the base offset and correct stride from phase 1, this script fine-tunes the starting position.

```python
# find_correct_offset.py
import os
from PIL import Image

# --- Configuration ---
DUMP_FILE = 'dwn.exe.dmp'
OUTPUT_DIR = 'offset_finetune'
BASE_OFFSET = 16777216  # The incorrect offset found in phase 1
WIDTH = 1024
HEIGHT = 768
CORRECT_STRIDE = 4096  # The correct stride (Width * 4 bytes/pixel)
SEARCH_ROWS = 500      # Number of rows to slide forward while searching

# --- Start Script ---
if not os.path.exists(DUMP_FILE): exit()
os.makedirs(OUTPUT_DIR, exist_ok=True)

with open(DUMP_FILE, 'rb') as f:
    for row_shift in range(SEARCH_ROWS):
        current_offset = BASE_OFFSET + (row_shift * CORRECT_STRIDE)
        f.seek(current_offset)

        buffer_size_needed = HEIGHT * CORRECT_STRIDE
        source_buffer = f.read(buffer_size_needed)

        if len(source_buffer) < buffer_size_needed: break

        try:
            repaired_data = bytearray()
            min_stride = WIDTH * 4
            for y in range(HEIGHT):
                line_start = y * CORRECT_STRIDE
                line_end = line_start + min_stride
                repaired_data.extend(source_buffer[line_start:line_end])

            img = Image.frombytes('RGBA', (WIDTH, HEIGHT), bytes(repaired_data), 'raw', 'BGRA')
            img.save(os.path.join(OUTPUT_DIR, f"offset_{current_offset}.png"))
        except:
            pass

print("Done! Check the 'offset_finetune' directory.")

```

**Result (Flag)**

After running the second script, the `offset_finetune` directory will contain a series of images. By browsing them, one or more images will show the full, correct screen. The ransomware dialog box is clearly visible, containing the flag.

`sun{r3m0t3_pwn4g3_QQ}`

---

## Postmortem / Tips

- This is a classic example of how data in memory is not always neatly packaged. Instead of searching for files, we sometimes have to reconstruct data from raw blocks.
- Visual glitches and artifacts (like tearing, noise, or shearing) are not failures. They are extremely valuable clues that tell us what is wrong (e.g., wrong offset, wrong stride, wrong resolution) so we can fine-tune our parameters.
- An alternative, more "forensically-sound" approach would be to use Volatility 2 with its `screenshot` plugin. This tool is designed to understand the internal structures of DWM and can reconstruct the screen automatically. However, the manual scripting method demonstrates how creativity and flexibility can also lead to the solution.
