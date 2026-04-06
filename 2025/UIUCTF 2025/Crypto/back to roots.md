Challenge này yêu cầu chúng ta tìm lại một số bí mật K chỉ dựa vào phần thập phân của căn bậc hai của nó. Lỗ hổng nằm ở chỗ K có một khoảng giá trị xác định (10^10 đến 10^11), điều này cho phép ta giới hạn được khoảng giá trị của phần nguyên của sqrt(K). Vì khoảng giá trị này rất nhỏ, chúng ta có thể duyệt (brute-force) qua tất cả các khả năng của phần nguyên, kết hợp nó với phần thập phân đã bị rò rỉ (leak) để tìm lại K, sau đó dùng K để tạo khóa AES và giải mã cờ.

<img width="717" height="472" alt="image" src="https://github.com/user-attachments/assets/00f49608-d6b3-48c6-8667-9f0470e1564e" />


Ta hãy kiểm tra đoạn code được cung cấp trước: 

```html
from random import randint
from decimal import Decimal, getcontext
from hashlib import md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from secret import FLAG

K = randint(10**10, 10**11)
print('K', K)
leak = int( str( Decimal(K).sqrt() ).split('.')[-1] )

print(f"leak = {leak}")
ct = AES.new(
	md5(f"{K}".encode()).digest(),
	AES.MODE_ECB
).encrypt(pad(FLAG, 16))

print(f"ct = {ct.hex()}")
```

**Hãy xem xét kỹ cách chương trình hoạt động:**
**Tạo số bí mật K:**

```html
K = randint(10**10, 10**11)
```

K là một số nguyên nằm trong khoảng từ 10 tỷ đến 100 tỷ. Đây là một không gian quá lớn để brute-force trực tiếp.

**Tạo thông tin rò rỉ (leak):**

```html
from decimal import Decimal, getcontext
...
leak = int( str( Decimal(K).sqrt() ).split('.')[-1] )
```

Chương trình sử dụng thư viện decimal để tính căn bậc hai của K với độ chính xác cao (mặc định là 28 chữ số). Kết quả được chuyển thành chuỗi, ví dụ: "123456.789...".split('.')[-1] lấy phần nằm sau dấu thập phân, ví dụ: "789...".int(...) chuyển chuỗi số thập phân này thành một số nguyên. Đây chính là giá trị leak mà chúng ta nhận được.

**Tạo khóa và mã hóa:**

```html
ct = AES.new(
	md5(f"{K}".encode()).digest(),
	AES.MODE_ECB
).encrypt(pad(FLAG, 16))
```

Khóa AES là 16 byte kết quả của hàm hash MD5 của chuỗi ký tự của K. Nếu tìm được K, chúng ta sẽ có khóa.
**Xác định lỗ hổng:** 

Lỗ hổng nằm ở mối quan hệ giữa K và leak.
Ta có sqrt(K) = I.F, trong đó I là phần nguyên và F là phần thập phân.
leak chính là F được biểu diễn dưới dạng một số nguyên.
Ta có thể tìm được khoảng giá trị của I. Vì **10^10 <= K < 10^11**, ta có:
**sqrt(10^10) <= sqrt(K) < sqrt(10^11)**
**100000 <= sqrt(K) < 316227.76.**
Điều này có nghĩa là phần nguyên I của sqrt(K) phải nằm trong khoảng [100000, 316227]. Đây là một khoảng giá trị rất nhỏ (chỉ khoảng 216,000 số), hoàn toàn có thể duyệt qua bằng một script.

**Exploit:** 

Xác định các tham số:
leak = 4336282047950153046404 (có 22 chữ số).
ct = 7863c63a4bb2c782eb67f32928a1deceaee0259d096b192976615fba644558b2ef62e48740f7f28da587846a81697745
Duyệt (Brute-force) phần nguyên I:
Lặp I trong khoảng từ 100000 đến 316228.
Tái tạo K:
Với mỗi giá trị I, chúng ta xây dựng một ứng cử viên cho sqrt(K):
sqrt_candidate ≈ **I + (leak / 10**22)**
(Chúng ta chia cho 10******22 vì leak có 22 chữ số).
Bình phương ứng cử viên này để có được K:
K_candidate ≈ (I + leak / 10**22) ** 2
Vì K phải là một số nguyên, nên K_candidate thực sự sẽ là kết quả làm tròn của phép tính trên.
Xác minh K:
Với mỗi K_candidate tìm được, ta phải kiểm tra xem nó có đúng là K gốc không. 

Cách làm là chạy lại chính quy trình tạo leak của challenge:
Tính **leak_test = int(str(Decimal(K_candidate).sqrt()).split('.')[-1]).**
Nếu leak_test khớp với leak ban đầu, chúng ta đã tìm thấy K chính xác!
Giải mã:
Khi đã có K đúng, ta tạo khóa và giải mã ct để lấy cờ.

```html
from decimal import Decimal, getcontext
from hashlib import md5
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# --- Dữ liệu từ output.txt ---
leak = 4336282047950153046404
ct = bytes.fromhex("7863c63a4bb2c782eb67f32928a1deceaee0259d096b192976615fba644558b2ef62e48740f7f28da587846a81697745")

# --- Thiết lập môi trường ---
# Độ chính xác mặc định của Decimal là 28, đủ để có 22 chữ số thập phân
# sau phần nguyên 6 chữ số. Ta có thể tăng lên một chút để chắc chắn.
getcontext().prec = 30 
leak_decimal = Decimal(leak) / Decimal(10**22)

found_K = -1

# --- Bắt đầu brute-force ---
# sqrt(10**10) = 100000
# sqrt(10**11) ≈ 316227
print("Bắt đầu duyệt phần nguyên I...")
for i in range(100000, 316228):
    # Xây dựng ứng viên cho K
    sqrt_candidate = Decimal(i) + leak_decimal
    K_candidate = round(sqrt_candidate**2)

    # Xác minh K_candidate bằng cách tạo lại leak
    # Phải đặt độ chính xác lại thành 28 để mô phỏng đúng challenge
    getcontext().prec = 28
    leak_test = int(str(Decimal(K_candidate).sqrt()).split('.')[-1])
    
    # So sánh
    if leak_test == leak:
        found_K = K_candidate
        print(f"\n[+] ĐÃ TÌM THẤY K! K = {found_K}")
        break
    
    # Đặt lại độ chính xác cho vòng lặp tiếp theo
    getcontext().prec = 30

# --- Giải mã ---
if found_K != -1:
    print("\nĐang tạo khóa và giải mã...")
    # Tạo khóa từ K
    key = md5(f"{found_K}".encode()).digest()
    
    # Tạo đối tượng giải mã
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Giải mã và unpad
    flag_padded = cipher.decrypt(ct)
    flag = unpad(flag_padded, 16)

    print("\n-------------------------")
    print("FLAG LÀ:")
    print(flag.decode())
    print("-------------------------")
else:
    print("\n[-] Không tìm thấy K. Đã có lỗi xảy ra.")
```

Chạy đoạn script → Lấy được FLAG

<img width="322" height="230" alt="image" src="https://github.com/user-attachments/assets/e59dae75-f3e7-410f-a736-c977bd8a1741" />
