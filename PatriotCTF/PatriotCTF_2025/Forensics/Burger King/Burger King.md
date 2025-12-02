# Burger King

Category: Misc

Author: l34ngyn

In this challenge, we are given an archive named `BurgerKing.zip` and a file that seems to be a part of its contents. However, the archive is encrypted, and we don't have the password to unzip it.

![image.png](image.png)

## How to get data from compressed file without password?

In this case, I recommend using [bkcrack](https://github.com/kimci86/bkcrack). Since we know the filenames and have some known data, we can use the command below to recover the keys:

```bash
bkcrack -C BurgerKing.zip -c Hole.svg -p plain.txt
```

Then, we receive the keys like (this is not real keys):

```
Keys: a1b2c3d4 e5f6g7h8 i9j0k1l2
```

Finally, we are using these keys to get file named `Hole.svg` with bellow command:

```
bkcrack -C BurgerKing.zip -c Hole.svg -k a1b2c3d4 e5f6g7h8 i9j0k1l2 -d out.svg
```

![image.png](image%201.png)

Now, we get the flag: `CACI{Y0U_F0UND_M3!}`