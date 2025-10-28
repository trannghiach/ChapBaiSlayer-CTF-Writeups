In this series of challenges, the flag is hidden in three pieces of evidence provided: three log files and one pcap file. For the `The Source` challenge, the flag format is `deadface{X.X.X.X}`, where `X.X.X.X` is the IP address of the DEADFACE attacker. The file `error.php.log` shows repeated brute-force attempts on usernames and passwords — this is the attacker’s activity.

Flag of `The Source` challenge:
```
deadface{134.199.202.160}
```

Next, in the `Calling Card` challenge the attacker hid a message inside a simple HTTP request. We used a Wireshark filter for the HTTP protocol; the first packet contains the hidden message. After base64-decoding that packet, we obtain the message. In that packet, we also find the flag in the Hypertext Transfer Protocol field.

Command:
```bash
_ws.col.protocol == "HTTP"
```

Message:
```
I’ve gained full access to your network. Every file, every credential, every system — under my control. You didn’t notice because I didn’t want you to.
This wasn’t luck. It was precision. Your defenses were inadequate, and I’ve proven it.
This attack is brought to you by mirveal. Thanks for the secrets!
```

Flag of `Calling Card` challenge:
```
deadface{l3ts_get_Th3s3_fiL3$}
```

For the `Versions` challenge, we filtered packets with the `http.server` display filter to find HTTP packets that include a Server header. The flag appears in the format `deadface{software_version}`.

Flag of `Versions` challenge:
```
deadface{nginx_1.25.5}
```

For the `Compromised` challenge, `error.php.log` shows the first LOGIN_SUCCESS for `username=bsampsel`. Using the filter command below to isolate bsampsel logins and examining the last packet, we recover the DEADFACE attacker’s username and password used to access the system.

Command:
```bash
(_ws.col.protocol == "HTTP") && (urlencoded-form.value == "bsampsel")
```

Flag of `Compromised` challenge:
```
deadface{bsampsel_Sparkles2025!}
```

For the `A Wild User Suddenly Appeared!` challenge, our objective is to identify the created account’s `first name` and the persistence `password` installed by the DEADFACE attacker. Apply a display filter to isolate database “create user” activity (e.g., queries that contain CREATE USER or equivalent) and examine the final matching packet for the credentials.

Command:
```bash
_ws.col.info matches "create_user"
```

Flag of `A Wild User Suddenly Appeared!` challenge:
```
deadface{Dorla_SuP3RS3cr3tD34DF4C3#}
```











