# Sunshine CTF 2025 — Rocommunications

---

**Thể loại:** Forensics / Steganography

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một liên kết đến một vật phẩm áo sơ mi trên Roblox Catalog. Mô tả gợi ý rằng một "Robloxian lừa đảo" đang giao tiếp thông qua chiếc áo của mình. Thử thách cũng lưu ý rằng mặc dù con đường giải quyết dự kiến yêu cầu tài khoản Roblox và Roblox Studio, nhưng nó "có thể giải được mà không cần chúng". Nhiệm vụ của người chơi là truy xuất tệp hình ảnh gốc (template) của chiếc áo để tìm ra thông điệp bí mật (flag).

---

## Mục tiêu

Mục tiêu chính là tìm cách tải về tệp hình ảnh `.png` gốc của chiếc áo từ Roblox, sau đó phân tích tệp hình ảnh này để trích xuất flag được ẩn giấu bên trong.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Hệ thống tài sản (Assets) của Roblox:** Hiểu rằng một vật phẩm trên Catalog (như áo sơ mi) có một ID riêng, và tệp hình ảnh template của nó là một tài sản riêng biệt với một ID khác.
- **API Web cơ bản:** Nhận biết được lỗi xác thực (authentication error) khi cố gắng truy cập tài nguyên được bảo vệ.
- **Sử dụng công cụ của bên thứ ba:** Khả năng tìm kiếm và sử dụng các công cụ trực tuyến do cộng đồng phát triển để giải quyết các vấn đề thường gặp (trong trường hợp này là tải tài sản Roblox).
- **Phân tích hình ảnh:** Khả năng kiểm tra một tệp hình ảnh để tìm kiếm các thông tin bất thường hoặc ẩn giấu một cách trực quan.

---

## Phân tích và hướng tiếp cận

Thử thách này có hai lớp. Lớp đầu tiên là một bài toán forensics nhỏ về việc truy xuất dữ liệu, và lớp thứ hai là một bài toán steganography đơn giản.

1. **Chướng ngại vật ban đầu:** Cố gắng sử dụng các API công khai của Roblox để tải tài sản trực tiếp bằng ID vật phẩm (`110009297654947`) sẽ dẫn đến lỗi `401 Authentication Required`. Điều này cho thấy tài sản không thể được truy cập bởi người dùng ẩn danh.
2. **Phân tích gợi ý:** Mô tả của thử thách nêu rõ rằng nó "có thể giải được mà không cần" tài khoản Roblox. Điều này là một gợi ý mạnh mẽ để bỏ qua các phương pháp yêu cầu đăng nhập (như sử dụng Roblox Studio hoặc trích xuất cookie) và thay vào đó tìm một giải pháp công khai hơn.
3. **Hướng tiếp cận thay thế:** Hướng đi hợp lý nhất là tìm kiếm các công cụ trực tuyến của bên thứ ba được thiết kế để tải xuống tài sản Roblox. Các công cụ này thường hoạt động như một proxy, sử dụng phiên đã được xác thực của riêng chúng để lấy tài sản và cung cấp cho người dùng cuối.
4. **Phân tích sau khi có tệp:** Khi đã có được tệp hình ảnh `.png` của template, bước tiếp theo là kiểm tra nó. Trước khi sử dụng các công cụ steganography phức tạp, bước đầu tiên luôn là kiểm tra bằng mắt thường. Template của quần áo Roblox được chia thành nhiều phần tương ứng với các bộ phận của cơ thể nhân vật (thân, tay,...). Flag có thể được viết trực tiếp lên một trong những phần này.

---

## Kịch bản giải mã (Exploit)

Không cần viết mã, quá trình giải quyết bao gồm việc sử dụng một công cụ trực tuyến.

1. **Tìm công cụ:** Tìm kiếm trên Google với các từ khóa như "Roblox asset downloader" hoặc "download Roblox clothing template".
2. **Sử dụng công cụ:** Truy cập một trang web đáng tin cậy tìm được, ví dụ như `thecsdev.com/tool/roblox-tools/`.
3. **Nhập thông tin:** Trong phần "Clothing downloader", dán URL của vật phẩm:
`https://www.roblox.com/catalog/110009297654947/Blue-and-Black-Motorcycle-Shirt`
4. **Tải tài sản:** Công cụ sẽ xử lý yêu cầu và hiển thị hình ảnh template `.png`.
5. **Kiểm tra hình ảnh:** Lưu hình ảnh về máy và mở nó bằng một trình xem ảnh. Kiểm tra kỹ các phần khác nhau của template. Flag được viết bằng văn bản màu trắng trên một trong các thành phần của cánh tay áo.

**Kết quả (Flag)**

Flag được tìm thấy một cách trực quan trên tệp hình ảnh.

<img width="1456" height="803" alt="image" src="https://github.com/user-attachments/assets/2f404459-f693-4d60-bc27-3f99b9802160" />


`sun{w0w_1_L0v3_Squ4r3_ass3ts}`

---

## Ghi chú và mẹo

- Thử thách này là một ví dụ điển hình về việc đọc kỹ mô tả. Gợi ý "solvable without it" là chìa khóa để tiết kiệm thời gian và không đi vào các con đường phức tạp không cần thiết.
- Khi đối mặt với một rào cản truy cập (như yêu cầu đăng nhập), hãy luôn cân nhắc liệu có các công cụ hoặc dịch vụ công cộng nào đã giải quyết vấn đề đó chưa.
- Trong các thử thách steganography, hãy luôn bắt đầu với các phương pháp đơn giản nhất (nhìn bằng mắt thường, kiểm tra metadata, dùng lệnh `strings`) trước khi chuyển sang các kỹ thuật phức tạp hơn như phân tích LSB.

---

# ENGLISH VERSION

**Category:** Forensics / Steganography

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a link to a shirt item on the Roblox Catalog. The description hints that a "Rogue Robloxian" is communicating through their shirt. The challenge also notes that while the intended solve path requires a Roblox account and Roblox Studio, it is "solvable without it." The player's task is to retrieve the original image file (template) of the shirt to find the hidden message (the flag).

---

## Objective

The main goal is to find a way to download the original `.png` image template of the shirt from Roblox, and then analyze this image file to extract the flag hidden within.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **Roblox Asset System:** Understanding that a Catalog item (like a shirt) has its own ID, and its image template is a separate asset with a different ID.
- **Basic Web APIs:** Recognizing an authentication error when trying to access a protected resource.
- **Third-Party Tool Usage:** The ability to search for and use online tools developed by the community to solve common problems (in this case, downloading Roblox assets).
- **Image Analysis:** The ability to visually inspect an image file for anomalies or hidden information.

---

## Analysis and Approach

This challenge has two layers. The first is a mini-forensics problem of data retrieval, and the second is a simple steganography problem.

1. **Initial Obstacle:** Attempting to use Roblox's public APIs to download the asset directly with the item ID (`110009297654947`) results in a `401 Authentication Required` error. This indicates the asset is not accessible to anonymous users.
2. **Hint Analysis:** The challenge description explicitly states that it is "solvable without" a Roblox account. This is a strong hint to bypass methods that require logging in (like using Roblox Studio or extracting cookies) and instead look for a more public solution.
3. **Alternative Approach:** The most logical path is to search for third-party online tools designed to download Roblox assets. These tools often act as a proxy, using their own authenticated sessions to fetch assets and serve them to the end-user.
4. **Post-Acquisition Analysis:** Once the `.png` template file is obtained, the next step is to inspect it. Before using complex steganography tools, the first step should always be a visual inspection. Roblox clothing templates are divided into sections corresponding to the character's body parts (torso, arms, etc.). The flag could be written directly on one of these sections.

---

## Exploit (Solution Steps)

No scripting is required. The solution process involves using an online tool.

1. **Find a Tool:** Search on Google for keywords like "Roblox asset downloader" or "download Roblox clothing template."
2. **Use the Tool:** Navigate to a reputable site found, for example, `thecsdev.com/tool/roblox-tools/`.
3. **Input Information:** In the "Clothing downloader" section, paste the item's URL:
`https://www.roblox.com/catalog/110009297654947/Blue-and-Black-Motorcycle-Shirt`
4. **Download Asset:** The tool will process the request and display the `.png` image template.
5. **Inspect the Image:** Save the image and open it with an image viewer. Look closely at the different parts of the template. The flag is written in plain white text on one of the sleeve components.

**Result (Flag)**

The flag is found visually on the image file.

`sun{w0w_1_L0v3_Squ4r3_ass3ts}`

---

## Postmortem / Tips

- This challenge is a classic example of why you should always read the description carefully. The "solvable without it" hint is key to saving time and avoiding unnecessarily complex paths.
- When facing an access barrier (like a login requirement), always consider if public tools or services have already solved that problem.
- In steganography challenges, always start with the simplest methods first (visual inspection, checking metadata, `strings` command) before moving on to more complex techniques like LSB analysis.
