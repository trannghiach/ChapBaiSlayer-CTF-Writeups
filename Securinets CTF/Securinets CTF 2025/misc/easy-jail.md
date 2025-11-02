# Securinest CTF - Easy Jail
## Category: Misc

### Exploitation
- Dựa vào source code được cung cấp, thấy rằng:
    - User chỉ được nhập vào chuỗi a-z, các ký tự `[]`, `()` và `~><*+`. Đồng thời, độ dài input không được quá 150 
    ```Python
    print("Welcome to the shifting jail! Enter text using only a-z, []()~><*+")
    ```
    
    ```Python
    if len(user_in) > 150:
                raise ValueError(f"Input exceeds 150 characters")
    ```
    
    - Class `ProtectedFlag` che giấu giá trị thật sự của Flag, nhằm khiến user không thể lấy giá trị bằng các cách thông thường
    ```Python
    class ProtectedFlag:
        def __init__(self, value):
            self._value = value

        def __str__(self):
            return "variable protected, sryy"

        def __repr__(self):
            return "variable protected, sryy"

        def __getitem__(self, index):
            try:
                return self._value[index]
            except Exception:
                return "variable protected, sryy"
    ```
    - Các hàm biến đổi chuỗi đầu vào, trong đó logic của `shift_mapping` đã được giấu đi
    ```Python
    def shift_mapping(mapping):
        # well guess how it was done >_<

    def make_initial_mapping():
        letters = list(string.ascii_lowercase)
        shuffled = letters[:]
        random.shuffle(shuffled)
        return dict(zip(letters, shuffled))
    ```
    
- Đầu tiên, kiểm tra cách hoạt động của `mapping` và `shift_mapping`, nhận thấy đây là mã hóa Caesar, nhưng giá trị của `k` được thay đổi sau mỗi lần input được nhập vào
![image](https://hackmd.io/_uploads/rkxgRtkpgg.png)

- Tuy nhiên, giá trị của `k` lại có thể đoán được (+-1)

- Từ đây, có thể suy được cách giải như sau:
    - Nhập vào chuỗi a-z để tìm được các hoán vị tương ứng của nó
    ![image](https://hackmd.io/_uploads/rJb8CFJTxe.png)

    - Với chuỗi thu được, so khớp để tìm ra chuỗi khớp với `flag`
    - Như đã biết, flag không thể lấy bình thường. Vì vậy, ta phải trích xuất các ký tự trong `flag` bằng cách sử dụng các ký tự đề cho. Ví dụ payload:
        ```
        Lấy ký tự 0 -> 4 của flag: flag[[]<[]]+flag[[]<[[]]]+flag[([]<[[]])+([]<[[]])]+flag[([]<[[]])+([]<[[]])+([]<[[]])]
        Lấy ký tự của flag (Trường hợp chuỗi quá dài): flag[(([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]]))*(([]<[[]])+([]<[[]]))+([]<[[]])]
        ```
    - Kết quả thu được
    ![image](https://hackmd.io/_uploads/ry7DlckTlx.png)


- Sau khi brute force, thu được từng ký tự. Sau đó, ghép nối chúng lại, thu được `FLAG`

- Script:
```Python
import string

# 2 chuỗi dùng để so khớp
SRC = "abcdefghijklmnopqrstuvwxyz"
DST = "deylifoqvtauzxjnsmwbphrkcg"

# Thay thế số thứ tự phù hợp để lấy giá trị.
get_1 = "flag[(([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]]))*(([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]])+([]<[[]]))+([]<[[]])+([]<[[]])]"     # VD: flag[5*5+1+1]


def make_maps(src, dst):
    return dict(zip(src, dst)), dict(zip(dst, src))

def preimage_of_target(inv_map, target="flag"):
    return "".join(inv_map[ch] for ch in target)

def replace(s, shift_string):
    return s.replace("flag", shift_string)     


if __name__ == "__main__":
    m, inv = make_maps(SRC, DST)
    pre = preimage_of_target(inv, "flag")
    plus1 = shift_str(pre, 1)
    minus1 = shift_str(pre, -1)

    print("Preimage for 'flag':", pre)
    
    print("Replace in get_1:", replace(get_1, pre))
```

### Result
```
Securinets{H0p3_Y0u_L0ST_1t!}
```