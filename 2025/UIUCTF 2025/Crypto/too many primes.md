Đây là một bài toán thuộc dạng Multi-prime RSA.
Lỗ hổng chính nằm ở cách modulus N được tạo ra: thay vì là tích của hai số nguyên tố siêu lớn, N lại là tích của một chuỗi các số nguyên tố 128-bit liên tiếp nhau. Điều này làm cho việc phân tích N ra thừa số trở nên khả thi. Ta chỉ cần tìm được một thừa số bất kỳ, sau đó dùng nó làm "điểm neo" để tìm ra tất cả các thừa số còn lại, từ đó tính toán khóa bí mật và giải mã.

Khi nhận được đề bài, chúng ta có các thông tin sau:
Tên challenge: **too many primes** (quá nhiều số nguyên tố).
Mô tả: "RSA thông thường dùng hai số nguyên tố - theo tôi là quá ít, nên tôi đã thêm vào một vài số nữa."

<img width="709" height="436" alt="image" src="https://github.com/user-attachments/assets/b2e9dd84-28a3-44c8-93fe-4d08c9e4e5b3" />


Với source code được cung cấp như sau:

```html
from sympy import nextprime, randprime
from sympy.core.random import seed
from math import prod, gcd
from Crypto.Util.number import bytes_to_long
# from secret import phi_N, FLAG

p = randprime(2**127, 2**128)
N = 1
while N < 2**2048:
	N *= p
	p = nextprime(p)

assert gcd(phi_N, 65537) == 1

pt = bytes_to_long(FLAG)
ct = pow(pt, 65537, N)
print("N = ", N)
print("ct = ", ct)
# N =  34546497157207880069779144631831207265231460152307441189118439470134817451040294541962595051467936974790601780839436065863454184794926578999811185968827621504669046850175311261350438632559611677118618395111752688984295293397503841637367784035822653287838715174342087466343269494566788538464938933299114092019991832564114273938460700654437085781899023664719672163757553413657400329448277666114244272477880443449956274432819386599220473627937756892769036756739782458027074917177880632030971535617166334834428052274726261358463237730801653954955468059535321422372540832976374412080012294606011959366354423175476529937084540290714443009720519542526593306377
# ct =  32130352215164271133656346574994403191937804418876038099987899285740425918388836116548661879290345302496993945260385667068119439335225069147290926613613587179935141225832632053477195949276266017803704033127818390923119631817988517430076207710598936487746774260037498876812355794218544860496013734298330171440331211616461602762715807324092281416443801588831683678783343566735253424635251726943301306358608040892601269751843002396424155187122218294625157913902839943220894690617817051114073999655942113004066418001260441287880247349603218620539692362737971711719433735307458772641705989685797383263412327068222383880346012169152962953918108171850055943194
```

**Ta sẽ cùng phân tích 1 chút đoạn mã này:**

Đoạn mã quan trọng nhất là vòng lặp tạo ra N:

```html
p = randprime(2**127, 2**128) # Tạo một số nguyên tố 128-bit ngẫu nhiên
N = 1
while N < 2**2048:
    N *= p
    p = nextprime(p) 
```

→ Điểm mấu chốt: p được cập nhật thành số nguyên tố LIỀN SAU nó

**Từ đây, ta rút ra các nhận định quan trọng:**
N là tích của nhiều số nguyên tố (khoảng 16 số, vì 2048 / 128 = 16).
Các số nguyên tố này không ngẫu nhiên mà tạo thành một chuỗi liên tiếp.
Đây chính là một biến thể của RSA, được gọi là Multi-prime RSA.\

**Xác Định Lỗ Hổng:** 

Độ an toàn của RSA dựa trên độ khó của việc phân tích N ra thừa số nguyên tố.
**RSA tiêu chuẩn: N = p * q** với p và q là hai số nguyên tố rất lớn (ví dụ: 1024-bit). Việc phân tích là bất khả thi với công nghệ hiện tại.
Challenge này: N = p1 * p2 * p3 * ... * pk. Mặc dù N vẫn là số 2048-bit, nhưng nó được cấu thành từ các thừa số "nhỏ" hơn rất nhiều (128-bit).
**Điểm yếu chí mạng:** Việc tìm một thừa số 128-bit từ một số 2048-bit là hoàn toàn khả thi với các công cụ online như FactorDB. Một khi có một thừa số, và biết rằng các thừa số khác nằm liền kề nó, ta có thể khôi phục lại toàn bộ.

**Exploit:** 

Lấy các tham số công khai: N và ct đã được cung cấp trong file. e là giá trị tiêu chuẩn 65537.
Phân tích N: Sử dụng một công cụ online để tìm một thừa số nguyên tố bất kỳ của N.
Tìm tất cả các thừa số: Từ thừa số đã tìm được (gọi là p_anchor), viết một script để tìm các thừa số liền trước (prevprime) và liền sau (nextprime) cho đến khi tìm đủ bộ.
Tính toán các giá trị RSA:
Tính phi(N) = **(p1 - 1) * (p2 - 1) * ... * (pk - 1).**
Tính khóa bí mật d bằng cách tìm nghịch đảo modular của e theo phi(N). Công thức: **d = pow(e, -1, phi_N).**
Giải mã: Dùng khóa bí mật d để giải mã ct và lấy cờ. Công thức: **message = pow(ct, d, N).**

**Thực thi từng bước:** 

**Bước 1:** Phân tích N với FactorDB 

Truy cập: http://factordb.com/ Dán giá trị của N vào ô tìm kiếm. FactorDB sẽ chạy và sau một lúc sẽ trả về một thừa số. Đây chính là "điểm neo" (p_anchor) của chúng ta.
**Bước 2:** Viết Script để tìm tất cả thừa số và giải mã
Chúng ta sẽ viết một script Python thực hiện các bước còn lại trong kế hoạch.
Logic chính: Khởi tạo một danh sách factors với p_anchor. Bắt đầu từ p_anchor, liên tục gọi nextprime() và kiểm tra xem số mới có phải là ước của N không. Nếu có, thêm vào danh sách. Nếu không, dừng vòng lặp tìm xuôi.
Bắt đầu từ p_anchor, liên tục gọi prevprime() và kiểm tra tương tự. Nếu có, thêm vào danh sách. Nếu không, dừng vòng lặp tìm ngược.
Sau khi có đủ các thừa số, tính phi(N), d, và giải mã.

```html
from sympy import nextprime, prevprime
from Cryptodome.Util.number import long_to_bytes
import math

# Các giá trị từ challenge
N = 34546497157207880069779144631831207265231460152307441189118439470134817451040294541962595051467936974790601780839436065863454184794926578999811185968827621504669046850175311261350438632559611677118618395111752688984295293397503841637367784035822653287838715174342087466343269494566788538464938933299114092019991832564114273938460700654437085781899023664719672163757553413657400329448277666114244272477880443449956274432819386599220473627937756892769036756739782458027074917177880632030971535617166334834428052274726261358463237730801653954955468059535321422372540832976374412080012294606011959366354423175476529937084540290714443009720519542526593306377
ct = 32130352215164271133656346574994403191937804418876038099987899285740425918388836116548661879290345302496993945260385667068119439335225069147290926613613587179935141225832632053477195949276266017803704033127818390923119631817988517430076207710598936487746774260037498876812355794218544860496013734298330171440331211616461602762715807324092281416443801588831683678783343566735253424635251726943301306358608040892601269751843002396424155187122218294625157913902839943220894690617817051114073999655942113004066418001260441287880247349603218620539692362737971711719433735307458772641705989685797383263412327068222383880346012169152962953918108171850055943194
e = 65537

# Thừa số tìm được từ FactorDB, đóng vai trò là "điểm neo"
p_anchor = 242444312856123694689611504831894231099

factors = [p_anchor]

# --- Logic tìm kiếm 2 chiều ---
print("Bắt đầu tìm kiếm các thừa số...")

# 1. Tìm xuôi (về phía các số nguyên tố lớn hơn)
p_current = p_anchor
while True:
    p_current = nextprime(p_current)
    if N % p_current == 0:
        factors.append(p_current)
    else:
        break

# 2. Tìm ngược (về phía các số nguyên tố nhỏ hơn)
p_current = p_anchor
while True:
    p_current = prevprime(p_current)
    if N % p_current == 0:
        factors.append(p_current)
    else:
        break

print(f"Đã tìm thấy tổng cộng {len(factors)} thừa số.")

# 3. Xác minh và tính toán
if math.prod(factors) == N:
    print("Xác minh thành công: Tích các thừa số bằng N.")
    phi_N = math.prod(p - 1 for p in factors)
    
    print("Đang tính khóa bí mật d...")
    d = pow(e, -1, phi_N)

    print("Đang giải mã...")
    pt = pow(ct, d, N)
    
    flag = long_to_bytes(pt)

    print("\n-------------------------")
    print("FLAG LÀ:")
    print(flag.decode())
    print("-------------------------")
else:
    print("Lỗi nghiêm trọng: Tích các thừa số không bằng N.")
```

Chạy đoạn script → Tìm được Flag

<img width="374" height="211" alt="image" src="https://github.com/user-attachments/assets/5d20de51-f303-47a5-adf9-c1a577290f46" />
