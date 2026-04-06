Trong bài toán này, ta được cung cấp một đoạn mã với lỗ hổng **tràn bộ nhớ** (buffer overflow). Mục tiêu của bài toán là lợi dụng lỗ hổng này để thay đổi giá trị của biến `winner` từ `false` thành `true`, khiến cho chương trình gọi hàm `win()` và hiển thị cờ (flag).

---

### **Phân Tích Mã Nguồn**:

Đây là mã nguồn của chương trình:

<img width="1118" height="384" alt="image" src="https://github.com/user-attachments/assets/dcc7a5b3-f9cf-4c26-8ad2-d7a60d88dcb9" />


### **Các Quan Sát Quan Trọng**:

1. **Lỗi Tràn Bộ Nhớ**:
    - Chương trình sử dụng hàm `gets()` để nhận đầu vào từ người dùng và lưu vào biến `buffer`. Hàm `gets()` không kiểm tra độ dài của đầu vào, dẫn đến **lỗi tràn bộ nhớ** khi người dùng nhập quá nhiều ký tự.
2. **Cấu Trúc Bộ Nhớ**:
    - Biến `buffer` có kích thước 16 byte (`char buffer[16]`).
    - Ngay sau `buffer`, biến `winner` có kiểu `bool` (thường 1 byte).
    - Khi người dùng nhập nhiều hơn 16 ký tự, dữ liệu sẽ **tràn ra ngoài** và ghi đè lên biến `winner`.
3. **Mục Tiêu**:
    - Mục tiêu là thay đổi giá trị của biến `winner` thành `true` (giá trị khác 0), điều này sẽ khiến hàm `win()` được gọi và hiển thị cờ (flag).

---

### **Cách Khai Thác Lỗi**:

1. **Nhập Đủ Số Ký Tự**:
    - Biến `buffer` có kích thước 16 byte, do đó 16 ký tự đầu tiên trong đầu vào sẽ được lưu vào `buffer`.
    - Ký tự thứ 17 sẽ ghi đè lên biến `winner` (1 byte).
2. **Đặt Biến `winner` Thành `true`**:
    - Biến `winner` là kiểu `bool`, vì vậy chỉ cần đặt nó thành giá trị **khác 0** để biến nó thành `true`. Một giá trị không phải là 0, như `1`, có thể được sử dụng.
3. **Tạo Đầu Vào**:
    - Đầu vào hợp lệ là một chuỗi gồm 16 ký tự (để lấp đầy bộ nhớ) và một ký tự thứ 17 (để ghi đè `winner`).

---

### **Giải Pháp Đầu Vào**:

Đầu vào bạn cần nhập là:

```
AAAAAAAAAAAAAAAA1
```

Giải thích:

- 16 ký tự đầu tiên (`AAAAAAAAAAAAAAAA`) lấp đầy `buffer`.
- Ký tự thứ 17 (`1`) ghi đè biến `winner`, làm cho `winner` trở thành `true` và chương trình sẽ gọi hàm `win()`.

---

### **Kết Quả**:

Khi nhập đúng đầu vào, chương trình sẽ thực thi hàm `win()` và hiển thị thông báo sau:

<img width="1103" height="302" alt="image" src="https://github.com/user-attachments/assets/b498c3cb-ba08-464c-a161-17aa332d8ec3" />
