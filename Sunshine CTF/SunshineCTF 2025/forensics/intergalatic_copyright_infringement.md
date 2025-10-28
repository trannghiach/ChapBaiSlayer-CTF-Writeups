# Sunshine CTF 2025 — Intergalactic Copyright Infringement

**Thể loại:** Forensics / Network

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một file capture lưu lượng mạng duy nhất, `evidence.pcapng`. Tên của thử thách, "Vi phạm bản quyền liên thiên hà", gợi ý về một hoạt động chia sẻ file bất hợp pháp. Nhiệm vụ của người chơi là phân tích file capture này, tìm ra một file bị ẩn (khả năng cao là một hình ảnh) đang được truyền tải, và trích xuất flag từ đó.

---

## Mục tiêu

Mục tiêu chính là phân tích lưu lượng mạng, xác định luồng dữ liệu chứa file bị che giấu, sử dụng kỹ thuật "khắc file" (file carving) để trích xuất nó, và cuối cùng là xem được nội dung của file để tìm flag.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Wireshark:** Công cụ phân tích gói tin mạng cơ bản để kiểm tra, lọc và theo dõi các luồng giao tiếp.
- **Giao thức TCP:** Hiểu cách dữ liệu được truyền trong các "luồng" (streams) và cách tìm ra các luồng chứa nhiều dữ liệu nhất.
- **File Carving:** Khái niệm về việc trích xuất các file từ một khối dữ liệu thô dựa trên các header và footer đặc trưng (magic numbers).
- **Công cụ Foremost:** Một công cụ carving phổ biến trên Linux, được sử dụng để tự động hóa quá trình trích xuất file.
- **Xử lý file lỗi:** Biết rằng các chương trình khác nhau có khả năng xử lý lỗi file khác nhau (ví dụ: trình duyệt web thường "khoan dung" hơn trình xem ảnh mặc định).

---

## Phân tích và hướng tiếp cận

Cách tiếp cận vấn đề này một cách có hệ thống bao gồm việc kiểm tra tổng quan lưu lượng mạng, xác định mục tiêu, trích xuất dữ liệu thô và cuối cùng là khắc file.

1. **Khảo sát ban đầu:** Mở file `evidence.pcapng` bằng Wireshark. Sử dụng công cụ `Statistics > Protocol Hierarchy`, ta nhanh chóng nhận thấy phần lớn lưu lượng là **BitTorrent** chạy trên nền **TCP**. Điều này xác nhận giả thuyết về việc chia sẻ file và cho chúng ta biết rằng dữ liệu ta cần tìm nằm trong các luồng TCP.
2. **Xác định luồng dữ liệu chính:** Trong Wireshark, vào `Statistics > Conversations` và chọn tab `TCP`. Sắp xếp các cuộc hội thoại theo cột "Bytes" để tìm ra luồng giao tiếp đã truyền tải nhiều dữ liệu nhất. Luồng này được gọi là "luồng béo nhất" (fattest stream) và là ứng cử viên hàng đầu chứa file chúng ta cần.
3. **Trích xuất dữ liệu thô:** Chuột phải vào luồng "béo nhất" và chọn `Follow > TCP Stream`. Thao tác này sẽ tái dựng lại toàn bộ dữ liệu trao đổi trong luồng đó. Trong cửa sổ mới, lưu lại **toàn bộ cuộc hội thoại (Entire conversation)** ở định dạng **Raw** vào một file, ví dụ `raw_dump.bin`.
4. **Khắc file:** Bây giờ chúng ta có một khối dữ liệu nhị phân. Sử dụng công cụ `foremost` để tự động quét file này và trích xuất bất kỳ file nào nó nhận dạng được.
5. **Phân tích kết quả:** `foremost` sẽ tạo một thư mục output. Bên trong, chúng ta tìm thấy hai file ảnh. Một file có thể xem được nhưng nội dung bị lỗi (ảnh sọc). File còn lại không thể mở bằng trình xem ảnh mặc định của Windows. Đây là một manh mối quan trọng. Khi một chương trình không mở được file, hãy thử một chương trình khác. Trình duyệt web như Firefox có bộ giải mã hình ảnh rất mạnh mẽ và có thể bỏ qua các lỗi nhỏ trong cấu trúc file. Mở file "lỗi" này bằng Firefox sẽ hiển thị nội dung thật sự của nó.

---

## Kịch bản giải mã (Exploit)

Quá trình này chủ yếu sử dụng các công cụ GUI và dòng lệnh.

1. **Trong Wireshark:**
    - Mở `evidence.pcapng`.
    - Đi đến `Statistics > Conversations > TCP`.
    - Tìm luồng có số byte lớn nhất.
    - Chuột phải -> `Follow > TCP Stream`.
    - Trong cửa sổ Follow Stream, chọn `Raw` và `Save As...` -> `raw_dump.bin`.
2. **Trong Terminal (Linux):**
    
    ```bash
    # Sử dụng foremost để khắc file từ dữ liệu thô đã lưu
    # Lệnh này sẽ tạo một thư mục 'output' chứa các file đã khôi phục
    foremost -i raw_dump.bin
    
    # Di chuyển vào thư mục kết quả và xem các file jpg
    cd output/jpg/
    ls -l
    
    ```
    
3. **Xem file kết quả:**
    - Thư mục `output/jpg/` sẽ chứa một hoặc nhiều file `.jpg`.
    - Mở file đáng ngờ (file mà trình xem ảnh mặc định không đọc được) bằng trình duyệt Firefox.
    - Ví dụ: `firefox 0000xxxx.jpg`

---

**Kết quả (Flag)**

Sau khi mở file ảnh bằng Firefox, flag sẽ hiện ra rõ ràng trong hình.

<img width="1482" height="824" alt="image" src="https://github.com/user-attachments/assets/7bf8e969-cdc5-4ba0-9b82-d27e6db81c8d" />


`sun{4rggg_sp4c3_p1r4cy}`

---

## Ghi chú và mẹo

- Luôn bắt đầu phân tích mạng bằng việc xem `Protocol Hierarchy` và `Conversations` để có cái nhìn tổng quan. "Luồng béo nhất" thường là nơi cất giấu bằng chứng.
- Khi một file (đặc biệt là ảnh hoặc video) không mở được bằng chương trình mặc định, đừng vội kết luận nó bị hỏng hoàn toàn. Hãy thử mở nó bằng các chương trình khác như trình duyệt web (Firefox, Chrome) hoặc trình phát media VLC, vì chúng thường được thiết kế để bỏ qua các lỗi nhỏ.
- Tên thử thách và các giao thức được sử dụng thường cung cấp những manh mối quan trọng về bối cảnh. "Piracy" (Vi phạm bản quyền) và BitTorrent là một sự kết hợp rất rõ ràng.

---

# ENGLISH VERSION

**Category:** Forensics / Network

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a single network traffic capture file, `evidence.pcapng`. The challenge's name, "Intergalactic Copyright Infringement," hints at an illegal file-sharing activity. The player's task is to analyze this capture file, find a hidden file (most likely an image) being transferred, and extract the flag from it.

---

## Objective

The main goal is to analyze the network traffic, identify the data stream containing the hidden file, use file carving techniques to extract it, and finally, view the file's content to find the flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Wireshark:** A fundamental network packet analyzer for inspecting, filtering, and following communication streams.
- **TCP Protocol:** Understanding how data is transferred in "streams" and how to find the streams containing the most data.
- **File Carving:** The concept of extracting files from a raw block of data based on their characteristic headers and footers (magic numbers).
- **Foremost Tool:** A popular command-line carving tool on Linux used to automate the file extraction process.
- **Handling Corrupted Files:** Knowing that different programs have different tolerances for file errors (e.g., a web browser is often more lenient than a default image viewer).

---

## Analysis and Approach

A systematic approach to this problem involves surveying the network traffic, identifying the target, extracting the raw data, and finally, carving the file.

1. **Initial Survey:** Open `evidence.pcapng` in Wireshark. Using `Statistics > Protocol Hierarchy`, we quickly observe that the majority of the traffic is **BitTorrent** over **TCP**. This confirms the file-sharing hypothesis and tells us that our target data lies within the TCP streams.
2. **Identify the Main Data Stream:** In Wireshark, navigate to `Statistics > Conversations` and select the `TCP` tab. Sort the conversations by the "Bytes" column to find the stream that transferred the most data. This is known as the "fattest stream" and is the prime candidate to contain the file we're looking for.
3. **Extract Raw Data:** Right-click the "fattest stream" and select `Follow > TCP Stream`. This reconstructs the data exchanged within that stream. In the new window, save the **Entire conversation** in **Raw** format to a file, for example, `raw_dump.bin`.
4. **Carve the File:** We now have a binary data blob. Use the `foremost` tool to automatically scan this file and extract any recognizable files within it.
5. **Analyze the Results:** `foremost` will create an output directory. Inside, we find two image files. One is viewable but appears as a garbled, striped image. The other cannot be opened by the default Windows photo viewer. This is a critical clue. When one program fails to open a file, try another. Web browsers like Firefox have very robust image decoders that can ignore minor errors in a file's structure. Opening this "unreadable" file with Firefox reveals its true content.

---

## Exploit Script

The process primarily involves GUI tools and the command line.

1. **In Wireshark:**
    - Open `evidence.pcapng`.
    - Go to `Statistics > Conversations > TCP`.
    - Find the stream with the largest byte count.
    - Right-click -> `Follow > TCP Stream`.
    - In the Follow Stream window, select `Raw` and `Save As...` -> `raw_dump.bin`.
2. **In a Terminal (Linux):**
    
    ```bash
    # Use foremost to carve files from the saved raw data
    # This command will create an 'output' directory with recovered files
    foremost -i raw_dump.bin
    
    # Change into the results directory and view the jpg files
    cd output/jpg/
    ls -l
    
    ```
    
3. **View the Resulting File:**
    - The `output/jpg/` directory will contain one or more `.jpg` files.
    - Open the suspicious file (the one the default image viewer couldn't read) with the Firefox browser.
    - Example: `firefox 0000xxxx.jpg`

---

**Result (Flag)**

After opening the image file with Firefox, the flag is clearly visible within the image.

`sun{4rggg_sp4c3_p1r4cy}`

---

## Postmortem / Tips

- Always begin network analysis by checking `Protocol Hierarchy` and `Conversations` for a high-level overview. The "fattest stream" is often the right place to start looking for evidence.
- When a file (especially an image or video) fails to open with a default program, don't immediately assume it's completely corrupt. Try opening it with other applications like web browsers (Firefox, Chrome) or media players (VLC), as they are often designed to be fault-tolerant.
- The challenge name and protocols used often provide strong hints about the context. "Piracy" and BitTorrent are a very clear combination.
