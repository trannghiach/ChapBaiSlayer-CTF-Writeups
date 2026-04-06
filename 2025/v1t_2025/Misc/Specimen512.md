# v1tCTF 2025 - Specimen 512
## Category: Misc

### Exploitation
- Phân tích file được cung cấp:
    - Thông tin trong file `Specimen_512.fasta`
    ```text
    >DNA_ARCHIVE_sample|size_target_mb=5
    ; hint: encoding=base64->triplet-codon (lexicographic AAA..TTT => b64 idx 0..63)
    ; pad_count=2  ; note: base64 padding removed from stream
    ; gc_hint: some decoy regions have varying GC to confuse simple heuristics
    >prelude
    CAATCTAGAACTCCAAACGAGTGTCCGCTTGAAGTTCAATTCGTAATAGATCTGACACACATTCGGAAGGATATCACCAA
    CAGACAGGACTACCCCGAACAGAAGATTATCCAGGAATCTATAAGAGATTACAGTCTAGTAGGAACAAAACTAGGACGGC
    TCTATCCCGGCGGTATTCACATGGCTTATTGAAGAATAGAACGATTTTTTATTTCCGGGACTCGTTCTATGCTAACCCGT
    TCGATGAAGAGATAAAATTGGCAACATCACTTCTTGACCTCATTCACATGGGCTCCCGGCCACGAGATGTTGCGGACGCA
    TTCGAATAGCTGCTGAGTACTCTTGTAGTATATTTCGTCCATGTATGTAGTTGTTGAATTCAAGTTCTTTTCTAATCTGA
    CTCGGCCTTTAATAGACAGCGAGTAACATACTTTATCTTCGTTATGAACCATACTTTTTTAATTCGTTGTATTAGCGACT
    ```

    - Nhận thấy đây là một challenge mã hóa base64 custom, với thông tin là các đoạn DNA. Dữ liệu thực tế chỉ chứa 4 ký tự: `A`, `C`, `G`, `T`, là 4 bazơ của DNA
    - Dữ liệu cũng đề cập đến `hint`:
    ```
    hint: encoding=base64->triplet-codon (lexicographic AAA..TTT => b64 idx 0..63)
    ```
    - Điều này có nghĩa là dữ liệu được mã hóa Base64, nhưng thay vì dùng các ký tự Base64 chuẩn (A-Z, a-z, 0-9, +, /), nó dùng một "bộ ba" (triplet) các bazơ DNA (gọi là codon) để biểu diễn (4 x 4 x 4 = 64). 64 tổ hợp codon này được sắp xếp theo thứ tự từ điển (`lexicographic`) và ánh xạ tương ứng tới 64 index của Base64
    ```
    AAA (tổ hợp đầu tiên) -> index 0 (ký tự Base64 là A)
    AAC (tổ hợp tiếp theo) -> index 1 (ký tự Base64 là B)
    ```
    - Thông tin `pad_count=2` cho biết Mã hóa Base64 thường dùng ký tự = để đệm (padding) cho đủ độ dài. Gợi ý này cho biết 2 ký tự đệm đã bị xóa. Khi chúng ta tái tạo lại chuỗi Base64, chúng ta cần thêm == vào cuối

- Từ các thông tin thu được, có thể rút ra cách giải quyết vấn đề:
    - Lấy chuỗi DNA trong file
    - Ánh xạ thông tin theo bộ mã hóa
    - Script:
    ```python
    import base64
    from itertools import product

    input_file = "Specimen_512.fasta"
    output_file = "secret.bin"

    # 1. Mapping
    bases = 'ACGT'
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    # Create 64 codon
    codons = [''.join(p) for p in product(bases, repeat=3)]

    # Create map
    decoding_map = {codon: b64_chars[i] for i, codon in enumerate(codons)}

    # 2. Extract DNA
    print(f"[+] Reading file {input_file}...")
    dna_sequence = ""
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(';') and not line.startswith('>'):
                    dna_sequence += line
    except FileNotFoundError:
        print(f"[-] Error: Cannot find file {input_file}")
        exit()

    print(f"[+] Extracted {len(dna_sequence)} DNA bazo.")

    # 3. Translate DNA to Base64
    base64_string = ""
    print("[+] Transalting DNA to Base64...")
    try:
        for i in range(0, len(dna_sequence), 3):
            codon = dna_sequence[i:i+3]
            if len(codon) == 3: # Ensure 1 codon has 3 characters
                base64_string += decoding_map[codon]
    except KeyError as e:
        print(f"[-] Error: Invalid codon: {e}.")
        exit()

    # 4. Add Padding
    base64_string += "=="
    print("[+] Added padding '=='.")

    # 5. Decode Base64
    print("[+] Decoding Base64...")
    try:
        decoded_data = base64.b64decode(base64_string)

        with open(output_file, 'wb') as f:
            f.write(decoded_data)

        print(f"---")
        print(f"[+] Finish! Secret data has been save to file: {output_file}")

    except Exception as e:
        print(f"[-] Decode Base64 failed: {e}")
    ```
    
- Sau khi chạy script, thu được file secret.bin. Kiểm tra file này:
```shell
binwalk -e secret.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
534288        0x82710         Zip archive data, at least v2.0 to extract, compressed size: 40, uncompressed size: 38, name: flag.txt
534366        0x8275E         Zip archive data, at least v2.0 to extract, compressed size: 48, uncompressed size: 50, name: readme.txt

WARNING: One or more files failed to extract: either no utility was found or it's unimplemented
```

- Đến đây, chỉ cần trích xuất 2 file và đọc flag:
```
dd if=secret.bin of=secret.zip bs=1 skip=534288               
769525+0 records in
769525+0 records out
769525 bytes (770 kB, 751 KiB) copied, 1.56922 s, 490 kB/s
```


### Result
```
v1t{30877432d1026706d7e805da846a32c3}
```