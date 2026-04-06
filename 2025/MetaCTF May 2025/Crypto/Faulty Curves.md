Thử thách này cung cấp mã nguồn của một hệ thống mã hóa và một file output chứa kết quả của nhiều phiên mã hóa/giải mã. Phân tích mã nguồn cho thấy hệ thống sử dụng mật mã đường cong elliptic (ECC) và có một lỗ hổng nghiêm trọng: kẻ tấn công có thể lật một bit của khóa bí mật trong quá trình giải mã và nhận được kết quả lỗi. Đây là một kịch bản lý tưởng để áp dụng kỹ thuật **Phân tích Lỗi Vi sai (Differential Fault Analysis - DFA)**.

### **1. Phân Tích Mã Nguồn và Sơ Đồ Mật Mã**

Đầu tiên, chúng ta cần hiểu rõ các thành phần của hệ thống:

- **Đường cong Elliptic:** Chương trình sử dụng các tham số của đường cong secp192r1, một đường cong tiêu chuẩn được định nghĩa trên trường hữu hạn GF(p).
- **Khóa:**
    - **Khóa Bí mật (d):** Là chuỗi flag được chuyển đổi thành một số nguyên lớn. Đây chính là mục tiêu chúng ta cần tìm.
    - **Khóa Công khai (Q):** Được tính bằng phép nhân vô hướng Q = d * G, với G là điểm gốc (generator point) của nhóm.
- **Mã hóa ElGamal trên ECC:**
    
    Đây là một biến thể của sơ đồ ElGamal. Để mã hóa một điểm tin nhắn M trên đường cong, hệ thống thực hiện:
    
    1. Chọn một số ngẫu nhiên k.
    2. Tính C1 = k * G.
    3. Tính C2 = M + k * Q.
    4. Bản mã là cặp điểm (C1, C2).
- **Giải mã:** Phép giải mã thông thường sẽ là M = C2 - d * C1.

### **2. Phân Tích Lỗ Hổng: Tấn Công Gây Lỗi (Fault Attack)**

Đây là điểm mấu chốt của thử thách. Thay vì thực hiện giải mã đúng, chương trình cố tình gây ra lỗi:

```html
from random import *  
from Crypto.Util.number import * 
flag = b'REDACTED'
#DEFINITION
p = 0xffffffffffffffffffffffffffffffff000000000000000000000001
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe)
b = K(0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4)
E = EllipticCurve(K, (a, b))
G = E(0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)
E.set_order(0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d * 0x1)
#DAMAGE 

def fault(val,index): 
	val = list(val)
	if val[index] == '1': 
		val[index] = '0'
	else: 
		val[index] = '1'
	return ''.join(val)

my_priv = bin(bytes_to_long(flag))[2:]
ms = []
C1s = []
C2s = []
decs = []

count = 0 

while count < len(my_priv):
	try: 
		k = randint(2, G.order()-2)
		Q = int(my_priv,2)*G
		M = randint(2,G.order()-2)
		M = E.lift_x(Integer(M));ms.append((M[0],M[1]))
		
		C1 = k*G;C1s.append((C1[0],C1[1]))
		C2 = M + k*Q;C2s.append((C2[0],C2[1]))

		ind = len(my_priv)-1-count
		new_priv = fault(my_priv,ind)
		new_priv = int(new_priv,2)
		dec = (C2 - (new_priv)*C1);decs.append((dec[0],dec[1]))
		count +=1 
	except: 
		pass

with open('out.txt','w') as f: 
	f.write(f'ms={ms}\n')
	f.write(f'C1s={C1s}\n')
	f.write(f'C2s={C2s}\n')
	f.write(f'decs={decs}')
```

1. Một vòng lặp chạy qua tất cả các bit của khóa bí mật d.
2. Trong mỗi vòng lặp i, một **khóa bí mật lỗi (d')** được tạo ra bằng cách lật (flip) bit thứ i của d (0 thành 1, 1 thành 0).
3. Hệ thống sử dụng khóa lỗi này để "giải mã": Dec = C2 - d' * C1.
4. Giá trị Dec (kết quả giải mã lỗi), cùng với các giá trị M, C1, C2 được ghi lại.

### **3. Xây Dựng Phương Trình Tấn Công**

Chúng ta có hai phương trình quan trọng cho mỗi vòng lặp:

1. **Giải mã đúng (lý thuyết):** M = C2 - d * C1
2. **Giải mã lỗi (đã cho):** Dec = C2 - d' * C1

Bằng cách lấy phương trình (2) trừ đi phương trình (1), chúng ta có thể loại bỏ M và C2, chỉ để lại mối liên hệ giữa các giá trị đã biết và hiệu của các khóa:

Dec - M = (C2 - d' * C1) - (C2 - d * C1)

Dec - M = (d - d') * C1

Đây chính là **phương trình vi sai** mà chúng ta sẽ khai thác. Mọi điểm M, Dec, C1 đều được cung cấp trong file out.txt.

Bây giờ, hãy phân tích hiệu (d - d'). Chương trình lật bit thứ j (tính từ bit có trọng số thấp nhất - LSB).

- **Nếu bit gốc b_j là 1:** Khóa lỗi d' sẽ có bit j là 0. Do đó, d' = d - 2^j, suy ra d - d' = 2^j.
- **Nếu bit gốc b_j là 0:** Khóa lỗi d' sẽ có bit j là 1. Do đó, d' = d + 2^j, suy ra d - d' = -2^j.

Thay thế vào phương trình tấn công, chúng ta có hai khả năng cho mỗi bit j:

1. Nếu Dec - M = (2^j) * C1, thì bit b_j **là 1**.
2. Nếu Dec - M = -(2^j) * C1, thì bit b_j **là 0**.

Bằng cách kiểm tra hai đẳng thức này cho mỗi vòng lặp j từ 0 đến n-1 (với n là độ dài bit của khóa), chúng ta có thể khôi phục lại toàn bộ các bit của khóa bí mật.

```html
# Dữ liệu từ file out.txt
ms_coords = [
C1s_coords = [
C2s_coords = [
decs_coords = [

# 1. Định nghĩa lại đường cong
p = 0xffffffffffffffffffffffffffffffff000000000000000000000001
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe)
b = K(0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4)
E = EllipticCurve(K, (a, b))
G = E(0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21, 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34)

# 2. Chuyển đổi tọa độ thành các điểm trên đường cong E
ms = [E(x, y) for x, y in ms_coords]
C1s = [E(x, y) for x, y in C1s_coords]
decs = [E(x, y) for x, y in decs_coords]

# 3. Khôi phục flag
binary_flag = ""
num_bits = len(ms)

print(f"Bắt đầu khôi phục {num_bits} bit của flag...")

for i in range(num_bits):
    M = ms[i]
    C1 = C1s[i]
    D = decs[i]
    
    # Phương trình tấn công: D - M = (+/- 2^i) * C1
    
    # Tính vế trái
    Diff = D - M
    
    # Tính (2^i) * C1
    TestPoint = (2^i) * C1
    
    # So sánh để tìm bit
    if Diff == TestPoint:
        # d - d' = 2^i   => bit gốc là 1
        binary_flag = '1' + binary_flag
        print(f"Bit {i} (LSB): 1")
    elif Diff == -TestPoint:
        # d - d' = -2^i  => bit gốc là 0
        binary_flag = '0' + binary_flag
        print(f"Bit {i} (LSB): 0")
    else:
        print(f"LỖI: Không tìm thấy bit {i}! Có gì đó không đúng.")
        break

# 4. Chuyển đổi flag và in ra
if len(binary_flag) == num_bits:
    print("\nKhôi phục thành công chuỗi nhị phân!")
    print(f"Binary Flag: {binary_flag}")
    
    flag_int = int(binary_flag, 2)
    flag_bytes = long_to_bytes(flag_int)
    
    print("\n" + "="*50)
    print(f"🎉 FLAG: {flag_bytes.decode()} 🎉")
    print("="*50)
```

Ta sẽ chạy nó trên [SageMathCell](https://sagecell.sagemath.org/)

<img width="1890" height="530" alt="image" src="https://github.com/user-attachments/assets/ae25f74d-a86e-41f3-968d-cd2c86516df7" />



Khi có chuỗi nhị phân → Ta tiến hành giải flag

<img width="659" height="193" alt="image" src="https://github.com/user-attachments/assets/976b0bde-4766-4427-9b50-8eb824eebefe" />
