## 

```markdown
# Shamir's Duck - Write Up

## Challenge Overview
Challenge này yêu cầu khôi phục một secret message từ Shamir's Secret Sharing (SSS). Được cho 6 shares từ 6 người khác nhau, nhưng chỉ cần 3 shares để reconstruct secret (k=3 threshold scheme).

## Shares Provided
```

Bob: ef73fe834623128e6f43cc923927b33350314b0d08eeb386

Sang: 2c17367ded0cd22e15220a2b2a6cede16e2ed64d1898bbad

Khoi: e05fd9646ff27414510dec2e46032469cd60d632606c8181

Long: 0c4de736ced3f8412307729b8bea56cc6dc74abce06a0373

Dung: afe15ff509b15eb48b0e9d72fc2285094f6233ec98914312

Steve: cb1a439f208aa76e89236cb496abaf20723191c188e23f54

## Solution Steps

### 1. Understand Shamir's Secret Sharing

- SSS là một cryptographic technique chia một secret thành nhiều shares
- Bất kỳ k shares nào cũng có thể khôi phục secret
- Ít hơn k shares không thể khôi phục được
- Trong challenge này k=3, nên cần 3 shares bất kỳ

### 2. Lagrange Interpolation

Secret được khôi phục bằng Lagrange interpolation tại điểm x=0:

$$f(0) = \sum_{i=1}^{k} y_i \prod_{j=1, j \neq i}^{k} \frac{x_j}{x_j - x_i}$$

Công thức này được tính modulo một prime number p.

### 3. Key Discovery

- Cần tìm prime modulo được sử dụng
- Thử các secp256k1 và Curve25519 primes
- Prime `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F` là secp256k1 prime

### 4. Combine Shares

Sử dụng 3 shares bất kỳ (ví dụ: Bob, Sang, Khoi):

- Gán x-coordinates: Bob=1, Sang=2, Khoi=3
- Convert hex shares thành decimal: y₁, y₂, y₃
- Áp dụng Lagrange interpolation tại x=0

### 5. Decode Result

- Kết quả là một số nguyên lớn
- Convert sang hexadecimal
- Decode bytes thành ASCII/UTF-8 string

## Implementation

Exploit script thử tất cả C(6,3)=20 tổ hợp của 3 shares từ 6 người với các candidate primes. Khi tìm được kết quả chứa format `v1t{...}`, đó là flag.

```html
#!/usr/bin/env python3
# Shamir's Secret Sharing Exploit
# Combines 3 shares to recover the secret message

import binascii

# Shamir's shares from the challenge
shares = {
    'Bob': 'ef73fe834623128e6f43cc923927b33350314b0d08eeb386',
    'Sang': '2c17367ded0cd22e15220a2b2a6cede16e2ed64d1898bbad',
    'Khoi': 'e05fd9646ff27414510dec2e46032469cd60d632606c8181',
    'Long': '0c4de736ced3f8412307729b8bea56cc6dc74abce06a0373',
    'Dung': 'afe15ff509b15eb48b0e9d72fc2285094f6233ec98914312',
    'Steve': 'cb1a439f208aa76e89236cb496abaf20723191c188e23f54'
}

def lagrange_interpolate(x, x_values, y_values, prime):
    """
    Lagrange interpolation at point x
    Reconstructs polynomial value at x given points
    """
    result = 0
    n = len(x_values)
    
    for i in range(n):
        numerator = 1
        denominator = 1
        
        for j in range(n):
            if i != j:
                numerator = (numerator * (x - x_values[j])) % prime
                denominator = (denominator * (x_values[i] - x_values[j])) % prime
        
        # Compute modular inverse of denominator
        inv_denominator = pow(denominator, prime - 2, prime)
        result = (result + y_values[i] * numerator * inv_denominator) % prime
    
    return result

def recover_secret(selected_shares, prime):
    """
    Recover secret using Lagrange interpolation
    selected_shares: dict with 'name': hex_value pairs
    """
    x_values = []
    y_values = []
    
    # Use participant indices as x-coordinates (1, 2, 3, ...)
    participant_names = list(shares.keys())
    
    for name, hex_value in selected_shares.items():
        idx = participant_names.index(name)
        x = idx + 1  # 1-indexed
        y = int(hex_value, 16)
        
        x_values.append(x)
        y_values.append(y)
    
    # Reconstruct at x=0 (the secret)
    secret = lagrange_interpolate(0, x_values, y_values, prime)
    
    return secret

# Try with different large primes (common in Shamir schemes)
primes_to_try = [
    2**256 - 2**32 - 977,  # secp256k1 prime
    2**256 - 89,
    2**521 - 1,
    2**255 - 19,  # Curve25519 prime
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
]

# Also try extracting a reasonable prime from the data
hex_shares = list(shares.values())
max_val = max(int(h, 16) for h in hex_shares)

# Find a prime larger than the largest share
def find_prime_for_range(max_val):
    """Find a suitable prime for the given value range"""
    candidate = max_val + 1
    while candidate < max_val * 10:
        if is_prime(candidate):
            return candidate
        candidate += 1
    return None

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = 2 + (n - 3) % (n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Try all combinations of 3 shares from 6 people
from itertools import combinations

all_names = list(shares.keys())
all_combinations = list(combinations(all_names, 3))

print(f"[*] Total combinations to try: {len(all_combinations)}")
print()

found = False
found_results = []

# Try all combinations
for combo_idx, selected_names in enumerate(all_combinations):
    selected = {name: shares[name] for name in selected_names}
    
    print(f"[*] Combo {combo_idx + 1}/{len(all_combinations)}: {', '.join(selected_names)}")
    
    # Try different primes
    for prime in primes_to_try:
        try:
            secret = recover_secret(selected, prime)
            
            # Convert to hex and remove '0x' prefix
            secret_hex = hex(secret)[2:]
            
            # Make sure length is even for proper byte conversion
            if len(secret_hex) % 2 == 1:
                secret_hex = '0' + secret_hex
            
            try:
                secret_bytes = bytes.fromhex(secret_hex)
                decoded = secret_bytes.decode('utf-8', errors='ignore').strip('\x00')
                
                # Check if it looks like a valid flag
                if ('{' in decoded and 'v1t' in decoded and '}' in decoded):
                    result = {
                        'combo': ', '.join(selected_names),
                        'prime': hex(prime),
                        'hex': secret_hex,
                        'flag': decoded
                    }
                    found_results.append(result)
                    print(f"  [+] FOUND: {decoded}")
                    found = True
            except:
                pass
                
        except Exception as e:
            pass

if found_results:
    print("\n" + "="*80)
    print("[+] ALL VALID FLAGS FOUND:")
    print("="*80)
    for result in found_results:
        print(f"\nCombo: {result['combo']}")
        print(f"Prime: {result['prime']}")
        print(f"Hex: {result['hex']}")
        print(f"Flag: {result['flag']}")
else:
    print("\n[!] No valid flags found with standard primes")

```

<img width="625" height="107" alt="Image" src="https://github.com/user-attachments/assets/6529f0c5-83d7-4df9-bb57-a01a2a9c8d06" />
