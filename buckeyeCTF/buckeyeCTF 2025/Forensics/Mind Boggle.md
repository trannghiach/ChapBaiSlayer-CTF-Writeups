@l34ngyn

First, we receive a `mystery.txt` that contains meaningless characters below:

```
-[----->+<]>++.++++.---.[->++++++<]>.[---->+++<]>+.-[--->++++<]>+.>-[----->+<]>.---.+++++.++++++++++++.-----------.[->++++++<]>+.--------------.---.-.---.++++++.---.+++.+++++++++++.-------------.++.+..-.----.++...-[--->++++<]>+.-[------>+<]>..--.-[--->++++<]>+.>-[----->+<]>.---.++++++.+..++++++++++.------------.+++.-----.-.+++++..----.---.++++++.-..++.--.+.-.--.+++.---..--.++.++++++.----..+.---.+++.+++++++++++.-------------.++.+..-.----.++...-[--->++++<]>+.-[------>+<]>...--..+++.-.++.----.++.-.+++.-----.---.+++++.+.+.--..++++.------..+.+++++++++++++.>-[----->+<]>.++...-.++++.---.----.++++++.+.----.-[--->++++<]>.[---->+++<]>+.+.--.++.--.++++++.
```

Try using [this website](https://www.dcode.fr/cipher-identifier) to quickly determine the encoding type of that string. We identify this is Brainfuck language.

Brainfuck language:
<img width="1213" height="564" alt="image" src="https://github.com/user-attachments/assets/57af9933-e58e-46ae-8cc0-5a7defd0fc58" />

Using that web with the slug `/brainfuck-language` to decode that string, we receive the hex string below:

Hex:
```
596D4E305A6E7430636A467762444E664E30677A583277306557565363313955636A467762444E66644768465830567559334A35554851784D453539
```

Now, try converting the hex string to string, we receive the string below:

String:
```
YmN0Znt0cjFwbDNfN0gzX2w0eWVSc19UcjFwbDNfdGhFX0VuY3J5UHQxME59
```

It appears to be a base64 encoded string, we try using base64decoder to decode it and get the flag:

Flag:
```
bctf{tr1pl3_7H3_l4yeRs_Tr1pl3_thE_EncryPt10N}
```
