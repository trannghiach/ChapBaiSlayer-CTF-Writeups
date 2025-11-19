# **based**

Category: Misc

Author: l34ngyn

In this challenge, we get a file named `flag.txt` and the hint: `“This is so based, can you help me to un-base it?”` , so I think the flag is encrypted many times with many Base algorithms like Base64.

## How can we identify different encryption algorithms?

One useful tool for identifying various encryption types is [`dcode.fr/cipher-identifier`](https://www.dcode.fr/cipher-identifier)

![image](https://github.com/user-attachments/assets/5cce5d96-4b7e-4421-ab88-fa10435f36c1)


Now we try to identify the string in flag.txt to determine what type of encoding it uses. We see that it is `Base64`, but after decoding the string, we notice some noise at the end. Removing that noise gives us the correct encoded data.

```
���������    
��
������������������ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~��������������������������������� ¡¢£¤¥¦§¨©ª«¬­®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ
```

Continue iterating through the cycle of detecting the encoding → decoding → removing noise → detecting the next encoding.

## So, when does it conclude?

I remember that the last encoding algorithm is Base91, and the hexadecimal form of the flag is shown below:

```
616D6174657572734354467B495F6C3076335F623435337D000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF
```

Now, we get the flag: `amateursCTF{I_l0v3_b453}`
