```markdown
# Lost Some Binary - Write Up

## Challenge Overview
Challenge này yêu cầu khôi phục flag từ dữ liệu binary được mã hóa. Tên challenge "Lost Some Binary" gợi ý rằng một số bits đã bị mất hoặc ẩn đi.

## Binary Data
```

```html
01001000 01101001 01101001 01101001 00100000 01101101 01100001 01101110 00101100 01101000 01101111 01110111 00100000 01110010 00100000 01110101 00100000 00111111 01001001 01110011 00100000 01101001 01110100 00100000 00111010 00101001 00101001 00101001 00101001 01010010 01100001 01110111 01110010 00101101 01011110 01011110 01011011 01011101 00100000 00100000 01001100 01010011 01000010 01111011 00111110 00111100 01111101 00100001 01001100 01010011 01000010 01111110 01111110 01001100 01010011 01000010 01111110 01111110 00101101 00101101 00101101 01110110 00110001 01110100 00100000 00100000 01111011 00110001 00110011 00110101 00111001 00110000 00110000 01011111 00110001 00110011 00110011 00110111 00110000 01111101
```

```html
## Solution Steps

### Step 1: Decode Binary to ASCII
Mỗi byte (8 bits) được decode thành ASCII character:
Decoded: 'Hiii man,how r u ?Is it :))))Rawr-^^[] LSB{><}!LSBLSB---v1t {135300_13370}'

Text này chứa hint "LSB" xuất hiện 3 lần, gợi ý về **LSB (Least Significant Bit) steganography**.

### Step 2: Extract LSB from Each Character
Lấy bit LSB (bit cuối cùng, phải nhất) từ mỗi ký tự ASCII:
Pos | Char | ASCII | Binary | LSB
0 | H | 72 | 01001000 | 0
1 | i | 105 | 01101001 | 1
2 | i | 105 | 01101001 | 1
3 | i | 105 | 01101001 | 1
4 | | 32 | 00100000 | 0
5 | m | 109 | 01101101 | 1
6 | a | 97 | 01100001 | 1
7 | n | 110 | 01101110 | 0
...
### Step 3: Group LSB Bits into Bytes and Decode
Chia 79 bits thành nhóm 8 bits (cần pad 1 bit cuối): 
```

```html
#!/usr/bin/env python3
# Lost Some Binary - Exploit
# Single file to decode binary and extract LSB flag

import re
import html

# Read the binary data
binary_data = """01001000 01101001 01101001 01101001 00100000 01101101 01100001 01101110 00101100 01101000 01101111 01110111 00100000 01110010 00100000 01110101 00100000 00111111 01001001 01110011 00100000 01101001 01110100 00100000 00111010 00101001 00101001 00101001 00101001 01010010 01100001 01110111 01110010 00101101 01011110 01011110 01011011 01011101 00100000 00100000 01001100 01010011 01000010 01111011 00111110 00111100 01111101 00100001 01001100 01010011 01000010 01111110 01111110 01001100 01010011 01000010 01111110 01111110 00101101 00101101 00101101 01110110 00110001 01110100 00100000 00100000 01111011 00110001 00110011 00110101 00111001 00110000 00110000 01011111 00110001 00110011 00110011 00110111 00110000 01111101"""

print("[*] Lost Some Binary - Challenge Exploit")
print("[*] Step 1: Decode binary to ASCII")
print()

# Split by spaces and convert each byte
binary_bytes = binary_data.split()
decoded_text = ''.join(chr(int(b, 2)) for b in binary_bytes)

print(f"Decoded ASCII: {repr(decoded_text)}")
print(f"Length: {len(decoded_text)} characters")
print()

print("[*] Character-by-character breakdown:")
print("Pos | Char | ASCII | Binary    | LSB")
print("-" * 45)
for idx, char in enumerate(decoded_text):
    ascii_val = ord(char)
    binary_val = bin(ascii_val)[2:].zfill(8)
    lsb_val = ascii_val & 1
    # Show printable or hex representation
    if char.isprintable():
        char_display = char
    else:
        char_display = f"0x{ascii_val:02x}"
    print(f"{idx:3d} | {char_display:^4s} | {ascii_val:3d}  | {binary_val} | {lsb_val}")
print()

print("[*] Step 2: Extract LSB (Least Significant Bit) from each character")
print()

# Extract LSB from each character
lsb_bits = ''.join(str(ord(c) & 1) for c in decoded_text)

print(f"LSB stream ({len(lsb_bits)} bits):")
print(f"Full LSB bits: {lsb_bits}")
print(f"\nLSB bits displayed in groups of 8:")
for i in range(0, len(lsb_bits), 8):
    chunk = lsb_bits[i:i+8]
    print(f"  Bits {i:2d}-{i+7:2d}: {chunk}")
print()

print("[*] Step 3: Decode LSB bits to characters")
print()

# Pad to make divisible by 8
original_len = len(lsb_bits)
print(f"Original bits: {original_len}")
print(f"Need to pad: {8 - (original_len % 8)} bits to reach {((original_len + 7) // 8) * 8}")
print()

# Try different padding strategies
padding_strategies = {
    'zeros': '0' * (8 - (original_len % 8)),
    'ones': '1' * (8 - (original_len % 8)),
    'trim': '',  # Don't pad, just trim
}

for strategy_name, padding in padding_strategies.items():
    print(f"[*] Trying padding strategy: {strategy_name}")
    
    if strategy_name == 'trim':
        # Trim to nearest byte boundary
        bits_to_use = lsb_bits[:((original_len // 8) * 8)]
    else:
        bits_to_use = lsb_bits + padding
    
    if len(bits_to_use) % 8 != 0:
        print(f"  Skipping (not divisible by 8)")
        continue
    
    print(f"  Using {len(bits_to_use)} bits")
    
    # Decode
    try:
        decoded_attempt = ''.join(chr(int(bits_to_use[i:i+8], 2)) for i in range(0, len(bits_to_use), 8))
        # Only show if it contains printable content
        printable_chars = ''.join(c if c.isprintable() or c in '\n\t' else f'[{ord(c):02x}]' for c in decoded_attempt)
        print(f"  Result: {repr(decoded_attempt)}")
        print(f"  Display: {printable_chars}")
        
        # Extract potential flag (anything that looks like v1t{...})
        flag_match = re.search(r'v1t\{[^}]*\}', printable_chars)
        if flag_match:
            print(f"  [+] FOUND FLAG: {flag_match.group()}")
        
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print()

print()
print("[*] " + "="*80)
print("[*] Alternative approach: Look at the LSB bits manually")
print("[*] " + "="*80)
print()

# The first 32 bits clearly spell v1t{
# Let's see what comes next
print("LSB bits breakdown:")
for i in range(0, len(lsb_bits), 8):
    chunk = lsb_bits[i:i+8]
    byte_val = int(chunk, 2)
    char = chr(byte_val) if 32 <= byte_val < 127 else f'[{byte_val:3d}]'
    print(f"  Bits {i:2d}-{i+7:2d}: {chunk} -> {byte_val:3d} -> {repr(char)}")

print()
print("First 4 bytes clearly decode to: 'v1t{'")
print()
print("The rest of the LSB bits (bits 32 onwards) are:")
remaining_bits = lsb_bits[32:]
print(f"  {remaining_bits}")
print()

# Try decoding remaining with different interpretations
print("Trying to decode remaining bits as ASCII:")
for i in range(0, len(remaining_bits), 8):
    chunk = remaining_bits[i:i+8]
    if len(chunk) == 8:
        byte_val = int(chunk, 2)
        char = chr(byte_val) if 32 <= byte_val < 127 else f'0x{byte_val:02x}'
        print(f"  {chunk} -> {byte_val:3d} -> {char}")
    else:
        print(f"  {chunk} (incomplete byte, {len(chunk)} bits)")

print()

# Try HTML entity decoding
print("[*] " + "="*80)
print("[*] Trying HTML entity decoding:")
print("[*] " + "="*80)
print()

html_decoded = html.unescape(decoded_text)
print(f"HTML decoded text: {repr(html_decoded)}")
print()

# Extract potential flags from HTML decoded
html_flags = re.findall(r'\{[^}]+\}', html_decoded)
if html_flags:
    print(f"Potential flags from HTML: {html_flags}")
    for flag_candidate in html_flags:
        print(f"  Try: v1t{flag_candidate}")
print()

# Try all combinations
print("[+] " + "="*80)
print("[+] ALL POSSIBLE FLAGS TO TRY:")
print("[+] " + "="*80)
candidates = [
    "v1t{><}",
    "v1t{>}",
    "v1t{<}",
    "v1t{<>}",
    "v1t{135300_13370}",
    "v1t{135300}",
    "v1t{13370}",
]

for candidate in candidates:
    print(candidate)

```

```html
LSB bits breakdown:
  Bits  0- 7: 01110110 -> 118 -> 'v'
  Bits  8-15: 00110001 ->  49 -> '1'
  Bits 16-23: 01110100 -> 116 -> 't'
  Bits 24-31: 01111011 -> 123 -> '{'
  Bits 32-39: 01001100 ->  76 -> 'L'
  Bits 40-47: 01010011 ->  83 -> 'S'
  Bits 48-55: 01000010 ->  66 -> 'B'
  Bits 56-63: 00111010 ->  58 -> ':'
  Bits 64-71: 00111110 ->  62 -> '>'
  Bits 72-79: 01111101 -> 125 -> '}'
 Flag: v1t{LSB:>}
```
