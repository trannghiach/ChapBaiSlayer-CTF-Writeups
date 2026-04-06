Trong thử thách này, chúng ta phải khai thác một lỗi tràn bộ nhớ (buffer overflow) trong một chương trình C, với cơ chế bảo vệ **canary** để ngăn chặn lỗi tràn bộ nhớ. Mục tiêu là thay đổi biến `earnedFlag` thành `true` mà không làm thay đổi giá trị của canary. Khi `earnedFlag` được thay đổi, chương trình sẽ gọi hàm `win()` và hiển thị flag.

### **Mã Nguồn Phân Tích**:

Dưới đây là phần mã nguồn quan trọng trong chương trình:

```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

void win() {
    printf("Well done, you've earned the flag!\n");
    FILE *flag_file = fopen("flag.txt", "r");
    if (flag_file != NULL) {
        char flag_content[100];
        while (fgets(flag_content, sizeof(flag_content), flag_file) != NULL) {
            printf("%s", flag_content);
        }
        fclose(flag_file);
    } else {
        printf("flag.txt file not found\n");
    }
}

void hexdump(void *addr, int len) {
    unsigned char *pc = (unsigned char*)addr;
    for (int i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0) printf("  ");
            for (int j = i - 16; j < i; j++) {
                if (j >= 0 && j < len) printf("%c", (pc[j] >= 32 && pc[j] <= 126) ? pc[j] : '.');
            }
            printf("\n");
            printf("%04x ", i);
        }
        printf(" %02x", pc[i]);
    }
}

int main() {
    struct {
        char mine[64];    // Buffer for user input
        int canary;       // Canary variable to prevent overflow
        bool earnedFlag;  // Flag to track if the user earned the flag
    } mineshaft;
    char debris[256];  // Extra buffer space

    mineshaft.canary = 0x44524942;  // "BIRD" in little endian
    mineshaft.earnedFlag = false;   // Initially false

    memset(mineshaft.mine, 0, sizeof(mineshaft.mine));  // Zero out the mine buffer

    printf("Welcome to the MetaCTF bitcoin mine, we have a flag you can earn, but it's guarded by our trusty canary!\n\n");

    while (1) {
        printf("Place some characters into the mine: ");
        gets(mineshaft.mine);  // Dangerous: allows buffer overflow

        if (mineshaft.canary != 0x44524942) {  // Check if the canary was altered
            printf("Oh no, the canary died! We need to evacuate immediately!\n\n");
            return 0;
        } else {
            printf("Canary is alive.\n");
            if (mineshaft.earnedFlag) {  // If the flag is earned, display it
                win();
            } else {
                printf("Looks like you haven't earned your flag yet though...\n\n");
            }
        }
    }
}
```

---

### **Phân Tích**:

1. **Canary Protection**:
    - **Canary** có giá trị là `0x44524942`, tương ứng với chuỗi `"BIRD"` trong bộ nhớ little-endian. Mục tiêu của **canary** là bảo vệ bộ nhớ khỏi các lỗi tràn bộ nhớ, tức là nếu giá trị này bị thay đổi, chương trình sẽ dừng lại với thông báo "canary died".
2. **Buffer Overflow**:
    - Bộ đệm `mine[64]` có thể chứa tối đa 64 ký tự. Nếu người dùng nhập quá 64 ký tự, nó sẽ ghi đè lên các vùng bộ nhớ khác, bao gồm cả biến `canary` và biến `earnedFlag`.
    - **`earnedFlag`** là kiểu `bool` và có thể được thay đổi bằng cách ghi đè giá trị của nó.
3. **Mục Tiêu**:
    - Mục tiêu là thay đổi **`earnedFlag`** thành `true` mà không thay đổi giá trị của **canary**. Khi `earnedFlag` thành `true`, chương trình sẽ gọi hàm `win()` và hiển thị flag.

---

### **Kỹ Thuật Khai Thác**:

1. **Điền 64 Ký Tự**:
    - Để lấp đầy bộ đệm `mine[64]`, bạn sẽ nhập vào 64 ký tự bất kỳ (chẳng hạn như ký tự "A").
2. **Giữ Nguyên Giá Trị Canary**:
    - Sau khi nhập 64 ký tự đầu tiên, bạn cần giữ nguyên giá trị của **canary**. Điều này có nghĩa là sau 64 ký tự "A", bạn cần nhập tiếp **4 ký tự "BIRD"** (tương ứng với giá trị `0x42 0x49 0x52 0x44`).
3. **Thay Đổi `earnedFlag`**:
    - Cuối cùng, bạn cần thay đổi **`earnedFlag`** bằng cách ghi đè lên nó. Vì `earnedFlag` là kiểu `bool`, bạn chỉ cần nhập một giá trị không phải 0 (ví dụ: `1`) để thay đổi nó thành `true`.

---

### **Payload**:

Payload bạn cần nhập là:

```html
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABIRDa
```

<img width="661" height="256" alt="image" src="https://github.com/user-attachments/assets/c2daae42-4972-4daa-ba54-1d8904a50a90" />
