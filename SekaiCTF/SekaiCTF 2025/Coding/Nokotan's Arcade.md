**Thể loại:** Quy hoạch động (Dynamic Programming), Cấu trúc dữ liệu (Sweep-line)

### 1. Tóm tắt bài toán

Chúng ta cần lập một lịch trình chơi game Maimai trong một ngày n phút để tối đa hóa tổng "điểm uy tín" (popularity). Có m người chơi, mỗi người có một khung thời gian [li, ri] họ có mặt và một điểm uy tín pi cho mỗi ván game họ chơi. Mỗi ván game kéo dài t phút và không thể bị gián đoạn.

### 2. Phân tích & Hướng tiếp cận ban đầu: Quy hoạch động

Bài toán có cấu trúc tối ưu: lịch trình tốt nhất cho i phút đầu tiên có liên quan đến các lịch trình tốt nhất cho những khoảng thời gian ngắn hơn. Điều này gợi ý mạnh mẽ đến việc sử dụng **Quy hoạch động (Dynamic Programming - DP)**.

Hãy định nghĩa trạng thái DP của chúng ta:

dp[i] = tổng điểm uy tín tối đa có thể đạt được tính đến hết phút thứ i.

Mục tiêu cuối cùng là tìm dp[n].

Để tính dp[i], chúng ta xét những gì có thể xảy ra tại phút i:

- **Lựa chọn 1: Không có game nào kết thúc tại phút i.**
    
    Trong trường hợp này, máy game hoặc là đang rảnh, hoặc đang giữa một ván game. Điểm uy tín tối đa không thay đổi so với phút trước đó. Do đó: dp[i] = dp[i-1].
    
- **Lựa chọn 2: Một game vừa kết thúc đúng tại phút i.**
    
    Nếu một game kéo dài t phút kết thúc tại i, nó phải bắt đầu tại thời điểm s = i - t + 1. Để tối đa hóa lợi nhuận, chúng ta nên chọn người chơi có điểm uy tín pi cao nhất trong số tất cả những người có thể chơi trong khoảng thời gian [s, i].
    
    Giá trị thu được từ lựa chọn này sẽ là dp[i-t] (tổng điểm tối đa trước khi game bắt đầu) cộng với điểm uy tín của ván game vừa chơi.
    

Công thức truy hồi DP của chúng ta là:

dp[i] = max(dp[i-1], dp[i-t] + best_p[i - t + 1])

Trong đó, best_p[s] là điểm uy tín lớn nhất của một người chơi có thể **bắt đầu** game tại thời điểm s.

### 3. Nút thắt của bài toán

Thách thức lớn nhất nằm ở việc tính mảng best_p một cách hiệu quả. Một cách tiếp cận ngây thơ là duyệt qua tất cả m người chơi cho mỗi thời điểm bắt đầu s từ 1 đến n. Điều này sẽ có độ phức tạp O(n * m), quá chậm với n, m <= 10^5.

### 4. Tối ưu hóa bằng Kỹ thuật Dòng quét (Sweep-line)

Chúng ta cần một cách nhanh hơn để xác định best_p[s]. Hãy thay đổi góc nhìn: một người chơi (li, ri, pi) có thể bắt đầu một ván game tại bất kỳ thời điểm s nào trong khoảng [li, ri - t + 1].

Bài toán con của chúng ta trở thành: với mỗi người chơi, họ đóng góp giá trị pi của mình vào một khoảng thời gian bắt đầu khả dụng. Chúng ta cần tìm giá trị lớn nhất tại mỗi điểm. Đây là một bài toán hoàn hảo cho kỹ thuật **Dòng quét (Sweep-line)**.

**Ý tưởng của Dòng quét:**

Chúng ta sẽ "quét" một đường thẳng qua dòng thời gian từ s=1 đến n. Trong quá trình quét, chúng ta sẽ duy trì một tập hợp các người chơi "đang khả dụng" (những người có thể bắt đầu game tại thời điểm s hiện tại).

1. **Biến đổi thành "Sự kiện":**
    
    Với mỗi người chơi (li, ri, pi), ta tạo ra hai sự kiện:
    
    - **Sự kiện THÊM:** Tại thời điểm time = li, người chơi này trở nên khả dụng. Ta thêm pi vào tập hợp những người đang khả dụng.
    - **Sự kiện XÓA:** Tại thời điểm time = (ri - t + 1) + 1, người chơi này không còn khả dụng để bắt đầu game nữa. Ta xóa pi khỏi tập hợp.
2. **Xử lý các sự kiện:**
    - Tạo một danh sách chứa tất cả các sự kiện (2 * m sự kiện).
    - Sắp xếp danh sách này theo time.
    - Sử dụng một cấu trúc dữ liệu có thể thêm/xóa phần tử và tìm phần tử lớn nhất một cách hiệu quả. std::multiset trong C++ là lựa chọn lý tưởng.
3. **Thuật toán Dòng quét:**
    
    a. Khởi tạo một multiset rỗng active_popularities.
    
    b. Duyệt qua các thời điểm bắt đầu s từ 1 đến n.
    
    c. Tại mỗi s, xử lý tất cả các sự kiện có time == s:
    
    - Nếu là sự kiện THÊM, insert(pi) vào multiset.
    - Nếu là sự kiện XÓA, erase(pi) khỏi multiset.
    
    d. Sau khi xử lý các sự kiện, nếu multiset không rỗng, giá trị best_p[s] chính là phần tử lớn nhất trong multiset (*active_popularities.rbegin() trong C++).
    

### 5. Thuật toán cuối cùng

1. **Bước 1: Tạo và sắp xếp sự kiện**
    - Đọc n, m, t.
    - Tạo ra 2*m sự kiện THÊM/XÓA từ m người chơi.
    - Sắp xếp mảng sự kiện.
    - **Độ phức tạp:** O(m log m).
2. **Bước 2: Chạy Dòng quét**
    - Duyệt s từ 1 đến n.
    - Sử dụng một multiset để duy trì những người chơi khả dụng.
    - Tính và lưu trữ mảng best_p (hoặc best_popularity_at_start).
    - **Độ phức tạp:** O(n * log m) (do các thao tác trên multiset).
3. **Bước 3: Chạy Quy hoạch động**
    - Khởi tạo mảng dp.
    - Dùng công thức dp[i] = max(dp[i-1], dp[i-t] + best_p[i - t + 1]) để điền vào mảng dp.
    - **Độ phức tạp:** O(n).
4. **Kết quả:**
    - In ra dp[n].

### 6. Phân tích độ phức tạp

- **Thời gian:** O(m log m + n log m). Với n, m cùng bậc, có thể viết là O((n+m) log m).
- **Không gian:** O(n + m) để lưu mảng dp, best_p và các sự kiện.

```html
#include <iostream>
#include <vector>
#include <algorithm>
#include <set> // Sử dụng multiset để lưu trữ và truy vấn hiệu quả

// Cấu trúc để biểu diễn một "sự kiện" trên dòng thời gian
// Sự kiện có thể là một người chơi bắt đầu khả dụng hoặc không còn khả dụng
struct Event {
    int time;
    int popularity;
    int type; // 1 cho sự kiện THÊM, -1 cho sự kiện XÓA

    // Toán tử so sánh để sắp xếp các sự kiện
    // Ưu tiên sắp xếp theo thời gian, sau đó xử lý sự kiện THÊM trước sự kiện XÓA
    bool operator<(const Event& other) const {
        if (time != other.time) {
            return time < other.time;
        }
        return type > other.type; // Xử lý THÊM (1) trước XÓA (-1)
    }
};

int main() {
    // Tăng tốc độ nhập/xuất trong C++
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    // === Bước 1: Đọc dữ liệu đầu vào ===
    int n, m, t;
    std::cin >> n >> m >> t;

    std::vector<Event> events;
    for (int i = 0; i < m; ++i) {
        int l, r, p;
        std::cin >> l >> r >> p;

        // Một người chơi chỉ có thể tham gia nếu thời gian họ ở lại đủ cho một ván game
        if (r - l + 1 >= t) {
            // Thời điểm muộn nhất một người chơi có thể BẮT ĐẦU game là r - t + 1
            int latest_start_time = r - t + 1;
            
            // Sự kiện THÊM: Người chơi p trở nên khả dụng để bắt đầu game tại thời điểm 'l'
            events.push_back({l, p, 1});

            // Sự kiện XÓA: Người chơi p không còn khả dụng để bắt đầu game từ thời điểm 'latest_start_time + 1'
            events.push_back({latest_start_time + 1, p, -1});
        }
    }

    // Sắp xếp các sự kiện để xử lý theo thứ tự thời gian
    std::sort(events.begin(), events.end());

    // === Bước 2: Dùng Dòng quét để tính điểm uy tín tốt nhất cho mỗi thời điểm bắt đầu ===
    
    // mảng best_popularity_at_start[s] lưu điểm uy tín cao nhất của một game có thể BẮT ĐẦU tại thời điểm s.
    std::vector<long long> best_popularity_at_start(n + 2, 0);
    
    // Dùng multiset để theo dõi điểm uy tín của những người chơi hiện đang khả dụng.
    // Multiset tự động sắp xếp và cho phép các phần tử trùng lặp.
    std::multiset<int> active_popularities;
    
    int event_idx = 0;
    // Quét qua tất cả các thời điểm bắt đầu 's' có thể
    for (int s = 1; s <= n; ++s) {
        // Xử lý tất cả các sự kiện xảy ra tại thời điểm 's'
        while (event_idx < events.size() && events[event_idx].time == s) {
            if (events[event_idx].type == 1) { // Sự kiện THÊM
                active_popularities.insert(events[event_idx].popularity);
            } else { // Sự kiện XÓA
                // Phải dùng find để đảm bảo chỉ xóa một bản sao của giá trị
                active_popularities.erase(active_popularities.find(events[event_idx].popularity));
            }
            event_idx++;
        }

        // Nếu có người chơi khả dụng, người tốt nhất là người có điểm uy tín cao nhất
        if (!active_popularities.empty()) {
            best_popularity_at_start[s] = *active_popularities.rbegin(); // rbegin() trỏ đến phần tử lớn nhất
        }
    }

    // === Bước 3: Quy hoạch động ===
    
    // dp[i] sẽ lưu điểm uy tín tối đa kiếm được tính đến hết phút 'i'
    std::vector<long long> dp(n + 1, 0);

    for (int i = 1; i <= n; ++i) {
        // Lựa chọn 1: Không có game nào kết thúc tại phút 'i'.
        // Điểm tối đa bằng với điểm tối đa tính đến phút 'i-1'.
        dp[i] = dp[i - 1];

        // Lựa chọn 2: Một game kết thúc đúng tại phút 'i'.
        // Game này phải bắt đầu tại thời điểm 'i - t + 1'.
        int start_time = i - t + 1;

        // Kiểm tra xem thời điểm bắt đầu có hợp lệ không
        if (start_time >= 1) {
            long long popularity_gain = best_popularity_at_start[start_time];
            if (popularity_gain > 0) {
                 // Tổng điểm sẽ bằng điểm thu được từ game này cộng với điểm tối đa
                 // đã kiếm được trước khi game bắt đầu (tức là đến hết phút i - t).
                long long previous_state_dp = dp[i - t];
                dp[i] = std::max(dp[i], previous_state_dp + popularity_gain);
            }
        }
    }

    // Kết quả cuối cùng là điểm tối đa kiếm được trong cả ngày
    std::cout << dp[n] << std::endl;

    return 0;
}
```
