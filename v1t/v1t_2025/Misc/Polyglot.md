# v1tCTF 2025 - Polyglot
## Category: Misc

### Exploitation
- Từ mô tả của challenge:

> File can only open in Windows

![alt text](./images/image.png)


- Kiểm tra các thông tin cơ bản của hình ảnh

```shell
binwalk -e polyglot.png           

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

WARNING: Extractor.execute failed to run external extractor 'yaffshiv --auto --brute-force -f '%e' -d 'yaffs-root'': [Errno 2] No such file or directory: 'yaffshiv', 'yaffshiv --auto --brute-force -f '%e' -d 'yaffs-root'' might not be installed correctly
25317         0x62E5          YAFFS filesystem root entry, big endian, type symlink, v1 root directory
26012         0x659C          Zlib compressed data, best compression
2225627       0x21F5DB        Zlib compressed data, default compression
2231147       0x220B6B        Zlib compressed data, default compression
2232775       0x2211C7        Zlib compressed data, default compression
2233299       0x2213D3        Zlib compressed data, default compression
2233644       0x22152C        Zlib compressed data, default compression
6078442       0x5CBFEA        Zlib compressed data, default compression
6078833       0x5CC171        Zlib compressed data, default compression
6103898       0x5D235A        Zlib compressed data, default compression
6104351       0x5D251F        Zlib compressed data, default compression
6156810       0x5DF20A        Zlib compressed data, default compression
6158648       0x5DF938        Zip archive data, at least v2.0 to extract, compressed size: 142094, uncompressed size: 160694, name: angri.jpg
```

- Nhận thấy, có 1 hình ảnh được nén ở trong `polyglot.png`. Giải nén và phân tích hình ảnh này:
![alt text](./images/image2.png)


    ```shell
    strings polyglot.png
    There no flag here brother<!--

    ftypisom
    isomiso2avc1mp41
    free
    moov
    lmvhd
    trak
    \tkhd
    $edts
    elst
    mdia

    ...

    data
    Create videos with https://clipchamp.com/en/video-editor - free online video editor, video compressor, video converter.
    |skip
    tskip--><style>body{font-size:0}</style><div style=font-size:initial><!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>V1t CTF 2025</title>
    </head>
    <body>
        <p>Bro you need to be more patient just WATCH the whole thing</p>
    </body>
    </html>
    </div><!--

    ...
    ```

- Qua các thông tin như `ftypisom`, `isomiso2avc1mp41`, `free`, `moov`, `lmvhd`, `trak`, nhận thấy bên trong ảnh ẩn chứa các thông tin biểu thị rằng đây là 1 file audio (`.mp4`)
- Chỉnh sửa extension thành `.mp4`, ta lấy được password

![alt text](./images/image3.png)

- Từ đó, giải mã stenography, thu được `FLAG`
```
steghide extract -sf angri.jpg               
Enter passphrase: [HideTheDuck123@]
wrote extracted data to "flag.txt".
```

### Result
```
v1t{duck_l0v3_w4tch1ng_p2r3}
```