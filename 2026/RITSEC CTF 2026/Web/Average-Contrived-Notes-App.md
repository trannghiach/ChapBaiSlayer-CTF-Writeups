# RITSEC CTF 2026 - Average Contrived Notes App

[ENGLISH BELOW VIETNAMESE]

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/c0455185-d1a5-4793-b25c-dcf5ed557e37" />

`RS{wh00ps_m4yb3_th4t_sh0uldn7_h4v3_b33n_4_l1nk}`

# Writeup Average Contrived Notes App

## Tóm tắt challenge

Thoạt nhìn đây giống một web notes app bình thường, nhưng lỗi thật sự không phải kiểu XSS hay SQL injection quen thuộc.

Cách solve đúng là một dạng **rò rỉ thông tin ở phía trình duyệt**:

- bot admin lưu flag thành một note
- sau đó bot truy cập URL do attacker cung cấp
- attacker không thể đọc trực tiếp trang notes do same-origin policy
- nhưng attacker vẫn có thể quan sát các tác dụng phụ của trình duyệt, ví dụ:
    - "query search này có ra kết quả không?"
    - "trang có focus vào một element cụ thể không?"

Chỉ cần như vậy là đủ để khôi phục flag từng ký tự một.

Loại tấn công này thường được gọi là **XS-Leak** hoặc **XS-Search**.

Nguồn nghiên cứu chính dẫn tới hướng này:

- PortSwigger, `XS-Leak: Leaking IDs using focus`https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki, `ID Attribute`https://xsleaks.dev/docs/attacks/id-attribute/

## Các file quan trọng

File chính của challenge:

- [index.js](https://www.notion.so/home/foqs/ctf/index.js)
- [bot.js](https://www.notion.so/home/foqs/ctf/bot.js)
- [templates/index.html](https://www.notion.so/home/foqs/ctf/templates/index.html)
- [Dockerfile](https://www.notion.so/home/foqs/ctf/Dockerfile)

Các file tôi tự viết trong quá trình solve:

- [attacker_server.py](https://www.notion.so/home/foqs/ctf/attacker_server.py)
- [bruteforce_flag.py](https://www.notion.so/home/foqs/ctf/bruteforce_flag.py)

## Mục tiêu

Lấy được flag mà bot đã lưu vào notes của chính nó.

## Bước 1: Đọc bot thật kỹ

File quan trọng nhất là [bot.js](https://www.notion.so/home/foqs/ctf/bot.js).

Bot làm đúng chuỗi hành động sau:

1. Mở site của challenge.
2. Gõ flag vào ô nhập note.
3. Lưu note.
4. Mở một URL do attacker gửi lên.

Điều này có nghĩa là:

- bot đang có session hợp lệ trên note app
- flag đã được lưu vào notes trước khi bot mở trang attacker
- code của attacker chạy trong lúc flag note đã tồn tại

Đây là cốt lõi của challenge.

## Bước 2: Kiểm tra các hướng dễ trước

Hướng tự nhiên đầu tiên là stored XSS:

- có nhét được `<script>alert(1)</script>` vào note không?
- có phá được HTML attribute không?
- có render được JavaScript trên trang notes không?

Sau khi đọc [index.js](https://www.notion.so/home/foqs/ctf/index.js) và [templates/index.html](https://www.notion.so/home/foqs/ctf/templates/index.html), hướng đó gần như bị chặn:

- nội dung note được sanitize ở server
- note được render bằng `textContent`, không phải `innerHTML`
- link được gán bằng property, không phải nối chuỗi HTML

Vậy challenge này nhiều khả năng **không** phải dạng "tiêm JS vào notes page".

## Bước 3: Chú ý cấu hình browser rất lạ

[Dockerfile](https://www.notion.so/home/foqs/ctf/Dockerfile) chạy Chromium với một số flag làm yếu cơ chế isolation.

Đây là một hint rất mạnh.

Trong một challenge web thông thường, ta hiếm khi phải quan tâm đến các flag kiểu này.
Nếu tác giả cố ý giảm isolation của browser, rất có thể họ muốn người chơi nghĩ theo hướng **browser behavior exploit**, không phải bug backend bình thường.

Từ đây, mô hình tư duy đúng là:

- "mình có lẽ phải leak dữ liệu qua các side effect của browser"

## Bước 4: Hiểu cấu trúc trang search

Bây giờ nhìn kỹ [templates/index.html](https://www.notion.so/home/foqs/ctf/templates/index.html).

Trang notes render kết quả search với các `id` có thể đoán được:

- nếu không có kết quả, trang tạo element có id `note-none`
- nếu có kết quả, trang tạo các element như `note-0`, `note-1`, ...

Chi tiết này nghe nhỏ, nhưng thật ra là chìa khóa.

Tại sao?

Vì nếu ta điều hướng trang tới fragment như:

```
/#note-0
```

thì browser có thể sẽ cố focus hoặc scroll tới element đó.

Như vậy sẽ có một khác biệt quan sát được:

- nếu element tồn tại và focusable, sẽ có side effect
- nếu element không tồn tại, sẽ không có gì xảy ra

Đây chính là một XS-Leak primitive.

Ý tưởng này không phải đoán mò:

- PortSwigger mô tả việc điều hướng target sang `#some-id` để kiểm tra xem element có tồn tại/focus được hay không, rồi phát hiện việc đó thông qua `blur` hoặc focus behavior:
https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki cũng tài liệu hóa đúng lớp tấn công này trong mục `ID Attribute`:
https://xsleaks.dev/docs/attacks/id-attribute/

## Bước 5: Vì sao search endpoint quan trọng

Ứng dụng cho phép search notes bằng query string.

Tức là ta có thể hỏi:

- có note nào chứa `RS{a` không?
- có note nào chứa `RS{b` không?
- có note nào chứa `RS{wh` không?

Nếu search có kết quả, trang sẽ có `note-0`.
Nếu không có, trang chỉ có `note-none`.

Nếu attacker phân biệt được hai trạng thái này từ cross-origin, thì có thể brute-force flag.

## Bước 6: Đây là XS-Search

Tấn công trở thành:

1. Đoán một phần của flag.
2. Mở `/?search=<guess>`.
3. Điều hướng tiếp tới `#note-0`.
4. Quan sát xem browser có hành xử như thể `note-0` tồn tại không.
5. Nếu có, substring mình đoán nằm trong flag note.
6. Mở rộng prefix từng ký tự một.

Đây là lý do challenge khó:

- same-origin policy chặn đọc trực tiếp
- nhưng side effect của browser vẫn làm rò rỉ từng bit thông tin

Đây chính là kiểu XS-Search thay vì web exploit truyền thống.

## Bước 7: Những hướng thử đầu tiên nhưng không đủ

Trước khi chốt oracle cuối cùng, có vài hướng khá hấp dẫn nhưng chưa đi tới lời giải:

- XSS trực tiếp trong note
- lợi dụng `/image` và `/script`
- tìm cách đọc response header cross-origin
- dùng popup nhưng chưa có signal focus đủ mạnh

Endpoint `/image` và `/script` rất đáng nghi vì set header `x-meow-meow` trước khi fail, nhưng trên thực tế primitive sạch và ổn định nhất vẫn là focus leak từ search result.

## Bước 8: Vì sao phải có host của riêng mình

Bot mở một URL do attacker cung cấp, nên ta cần một trang public mà bot có thể load.

Ban đầu, các lựa chọn host miễn phí khá phiền:

- có trang tự chèn CSP
- có trang escape HTML
- có chỗ chỉ dùng được trong context hạn chế như top-level SVG

Giải pháp thực tế cuối cùng là host một attacker page ở local rồi expose nó qua reverse tunnel.

Đó là vai trò của [attacker_server.py](https://www.notion.so/home/foqs/ctf/attacker_server.py).

Server này phục vụ:

- `/` trang probe của attacker
- `/log` endpoint nhận beacon
- `/result` nơi lưu kết quả đơn giản cho brute-forcer
- `/healthz` để kiểm tra tunnel còn sống không

## Bước 9: Xây positive và negative oracle

Muốn solve challenge, ta cần một tín hiệu nhị phân:

- positive = search match
- negative = search không match

Trang attacker tạo:

- một ô input local để giữ focus
- một iframe trỏ vào trang target

Sau đó nó làm:

1. load target với một query search
2. kéo focus về lại trang attacker
3. đổi iframe sang cùng trang nhưng thêm `#note-0`
4. kiểm tra xem focus có chuyển vào iframe không

Nếu focus chuyển sang iframe:

- `note-0` có khả năng tồn tại
- tức là search match

Nếu focus vẫn nằm ở input local:

- `note-0` không focus được
- tức là search không match

Chiến lược phát hiện này dựa trực tiếp trên cơ chế từ PortSwigger và XS-Leaks Wiki:

- PortSwigger dùng focus transfer và `blur` làm signal:
https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki cũng mô tả cách dùng iframe + fragment + focus behavior:
https://xsleaks.dev/docs/attacks/id-attribute/

## Bước 10: Xác minh oracle trên target thật

Tôi không muốn chỉ dựa vào lý thuyết, nên phải kiểm tra trên instance thật.

Tôi dùng hai control.

### Positive control

Dùng một query chắc chắn match flag note:

```
/
then
/#note-0
```

Kết quả: focus chuyển vào iframe.

### Negative control

Dùng một query gần như chắc chắn không tồn tại:

```
/?search=zzzzzzzzzz
then
/?search=zzzzzzzzzz#note-none
```

Kết quả: focus ở lại trên input local.

Như vậy oracle đã được xác minh là thật.

Bước xác minh này rất quan trọng, vì tài liệu bên ngoài chỉ nói rằng cơ chế browser này tồn tại về mặt nguyên lý.
Trên target thật vẫn phải xác nhận:

- trang có thực sự tạo các `id` đoán được không
- element liên quan có thực sự focusable không
- browser của bot có còn lộ signal đó không
- attacker page có quan sát được ổn định không

## Bước 11: Vì sao oracle này leak được flag

Giả sử đã biết flag bắt đầu bằng `RS{`.

Ta thử:

- `RS{a`
- `RS{b`
- `RS{c`
- ...

Nếu một candidate cho ra positive, thì ký tự đó đúng trong prefix.

Sau đó tiếp tục:

- `RS{wa`
- `RS{wb`
- `RS{wc`
- ...

Mỗi lần positive là lộ thêm một ký tự.

Vì bot lưu toàn bộ flag thành một note duy nhất, substring search là đủ.

## Bước 12: Charset được phép

Hint của challenge nói phần thân flag có dạng:

```
RS{[\\w\\d!?:]*}
```

Trên thực tế, chỉ cần brute-force các ký tự:

- chữ hoa
- chữ thường
- chữ số
- `_`
- `!`
- `?`
- `:`
- và cuối cùng là `}`

[bruteforce_flag.py](https://www.notion.so/home/foqs/ctf/bruteforce_flag.py) dùng đúng charset đó.

## Nghiên cứu hỗ trợ khác

Ngoài focus-based XS-Search là hướng thắng cuối cùng, tôi cũng kiểm tra hành vi cookie vì flow của bot là cross-site và nhiều challenge loại này bị ảnh hưởng bởi SameSite.

Nguồn tham khảo hữu ích:

- MDN, `Set-Cookie` / `SameSite`https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
- web.dev, `SameSite cookies explained`https://web.dev/articles/samesite-cookies-explained

Đây là nghiên cứu hỗ trợ, không phải mấu chốt cuối cùng.
Primitive thắng trực tiếp vẫn là focus/fragment leak.

## Bước 13: Brute-forcer làm gì

[bruteforce_flag.py](https://www.notion.so/home/foqs/ctf/bruteforce_flag.py) tự động hóa quá trình:

1. Bắt đầu từ prefix đã biết, ví dụ `RS{wh`.
2. Thử các ký tự tiếp theo.
3. Với mỗi candidate:
    - submit một bot job trỏ tới attacker page
    - yêu cầu attacker page search candidate đó
    - poll `/result` cho tới khi có terminal event
4. Nếu positive, nối thêm ký tự vào prefix.
5. Lặp lại cho tới khi gặp `}`.

## Bước 14: Vì sao quá trình extract khá mệt

Logic exploit thì đúng.

Cái mệt là phần vận hành:

- domain của reverse tunnel chết hoặc đổi
- local attacker server đôi lúc phải restart
- bot endpoint thỉnh thoảng chậm hoặc drop request

Đó là lý do brute-force quá nhanh thì không ổn định.

Một brute-forcer chậm hơn, có resume, thường đáng tin hơn.

## Bước 15: Kết quả recover một phần trên instance thật

Trong quá trình extract live, tôi đã xác nhận được các ký tự thật của flag:

- `RS{w`
- sau đó `RS{wh`

Vậy nên cách solve này không phải giả thuyết.
Nó đã recover được prefix thật của flag trên service live.

## Ý tưởng exploit cuối cùng trong một đoạn

Bot lưu flag thành note rồi mở trang attacker. Trang attacker load note app trong iframe với một query search cho substring đang đoán. Sau đó attacker điều hướng iframe tới `#note-0`. Nếu search match thì `note-0` tồn tại và target page cướp focus vào iframe. Nếu không match thì focus vẫn nằm ở input local của attacker. Như vậy ta có một oracle 1 bit cho câu hỏi "có note nào chứa substring này không?". Lặp oracle này trên charset cho phép sẽ recover được flag từng ký tự.

## Bản giải thích cực dễ hiểu

Nếu bạn mới làm web exploitation, có thể hiểu challenge này như sau:

- mình không đọc trực tiếp được trang
- mình chỉ nhìn phản ứng của browser
- trang phản ứng khác nhau khi search có kết quả và khi search không có kết quả
- sự khác nhau nhỏ đó làm lộ bí mật

Đây là bài học rất thường gặp ở các challenge browser khó:

> same-origin policy chặn việc đọc trực tiếp, nhưng không chặn mọi side effect
> 

## Quy trình solve thực tế

1. Chạy attacker server:

```bash
python3 attacker_server.py
```

1. Expose server ra public qua reverse tunnel.
2. Kiểm tra tunnel còn sống:

```bash
curl -iLsS <https://YOUR-TUNNEL/healthz>
```

1. Resume brute-force từ prefix hiện có:

```bash
python3 bruteforce_flag.py 'RS{wh' '<https://YOUR-TUNNEL>'
```

1. Nếu tunnel chết, mở tunnel mới rồi resume bằng host mới.

## Những bài học từ challenge này

- Không phải challenge web nào cũng là injection.
- Bản thân hành vi của browser cũng có thể bị khai thác.
- Cấu trúc DOM có thể trở thành side channel.
- Search endpoint rất nguy hiểm trong bot challenge.
- Một leak chỉ 1 bit vẫn đủ nếu lặp lại nhiều lần.

## Tài liệu tham khảo

Nguồn mô tả trực tiếp mechanic chính:

- PortSwigger, `XS-Leak: Leaking IDs using focus`https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki, `ID Attribute`https://xsleaks.dev/docs/attacks/id-attribute/

Nguồn hỗ trợ về browser/cookie:

- MDN, `Set-Cookie` / `SameSite`https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
- web.dev, `SameSite cookies explained`https://web.dev/articles/samesite-cookies-explained

Nguồn quan trọng nhất dùng để solve thực sự là hai tài liệu đầu về **focus/fragment ID leak**.

## Kết luận

Đây là một challenge browser-side rất hay.

Không có XSS dễ.
Không có exfil trực tiếp đơn giản.
Thay vào đó, lời giải là:

- hiểu bot
- hiểu DOM mà target render ra
- tìm một side effect của browser
- biến nó thành oracle yes/no
- rồi brute-force flag bằng search query lặp đi lặp lại

Đó là lý do challenge này khó, và cũng là lý do nó là một bài XS-Leak rất tốt.

# Average Contrived Notes App Writeup

## Challenge Summary

This challenge looks like a normal note-taking web app at first, but the real bug is not a classic XSS or SQL injection.

The intended solution is a **browser-side information leak**:

- the admin bot stores the flag as a note
- then the bot visits an attacker-controlled URL
- the attacker cannot directly read the page because of the browser same-origin policy
- but the attacker can still ask the browser questions like:
    - "does this search produce a result?"
    - "did the page focus a specific element?"

That is enough to recover the flag one character at a time.

This class of attack is usually called an **XS-Leak** or **XS-Search**.

The main outside research that pointed me in this direction was:

- PortSwigger, `XS-Leak: Leaking IDs using focus`https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki, `ID Attribute`https://xsleaks.dev/docs/attacks/id-attribute/

## Files

Main files in the challenge:

- [index.js](https://www.notion.so/home/foqs/ctf/index.js)
- [bot.js](https://www.notion.so/home/foqs/ctf/bot.js)
- [templates/index.html](https://www.notion.so/home/foqs/ctf/templates/index.html)
- [Dockerfile](https://www.notion.so/home/foqs/ctf/Dockerfile)

Auxiliary files I built while solving:

- [attacker_server.py](https://www.notion.so/home/foqs/ctf/attacker_server.py)
- [bruteforce_flag.py](https://www.notion.so/home/foqs/ctf/bruteforce_flag.py)

## Goal

Steal the flag that the bot writes into its own notes.

## Step 1: Read The Bot Carefully

The most important file is [bot.js](https://www.notion.so/home/foqs/ctf/bot.js).

The bot does this:

1. Opens the challenge site.
2. Types the flag into the note input box.
3. Saves the note.
4. Opens a URL supplied by the attacker.

That means:

- the bot has a valid authenticated session on the note app
- the bot has already stored the flag in its notes
- our attacker page runs after the flag note exists

This is the core setup of the challenge.

## Step 2: Check For Easy Bugs First

The obvious first attempt is stored XSS:

- can we make a note like `<script>alert(1)</script>`?
- can we break out of HTML attributes?
- can we inject JavaScript in rendered notes?

After reading [index.js](https://www.notion.so/home/foqs/ctf/index.js) and [templates/index.html](https://www.notion.so/home/foqs/ctf/templates/index.html), that path looks blocked:

- note content is sanitized on the server
- note text is rendered with `textContent`, not `innerHTML`
- links are assigned as properties, not string-concatenated HTML

So the challenge is probably not "get JavaScript into the notes page."

## Step 3: Notice The Weird Browser Setup

The [Dockerfile](https://www.notion.so/home/foqs/ctf/Dockerfile) launches Chromium with several flags that weaken isolation.

That is a big hint.

In a normal app challenge, you usually do not need to care about Chromium isolation flags.
If the author is disabling isolation, they probably want a **browser behavior exploit**, not a backend bug.

So at this point the right mental model is:

- "I probably need to leak information through browser side effects."

## Step 4: Understand The Search Page Structure

Now look closely at [templates/index.html](https://www.notion.so/home/foqs/ctf/templates/index.html).

The notes page renders search results with predictable IDs:

- if there are no results, the page creates an element with id `note-none`
- if there are results, it creates elements like `note-0`, `note-1`, etc.

That sounds minor, but it is actually the key.

Why?

Because if we can navigate the page to a fragment like:

```
/#note-0
```

then the browser may try to focus or scroll to that element.

That creates an observable difference:

- if the element exists and is focusable, something happens
- if the element does not exist, nothing happens

This is an XS-Leak primitive.

This idea did not come from nowhere. It matches a known browser side-channel:

- PortSwigger showed that navigating a target page to `#some-id` can reveal whether a focusable element with that ID exists, because the target may steal focus and trigger `blur`style signals on the attacker page:
https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- The XS-Leaks Wiki documents the same class of attack under `ID Attribute`, including cross-origin iframe usage:
https://xsleaks.dev/docs/attacks/id-attribute/

## Step 5: Why The Search Endpoint Matters

The application lets us search notes using a query string.

That means we can ask:

- does any note contain `RS{a`?
- does any note contain `RS{b`?
- does any note contain `RS{wh`?

If the search result exists, the page includes `note-0`.
If it does not, we only get `note-none`.

So if we can distinguish those two situations from another origin, we can brute-force the flag.

## Step 6: This Is XS-Search

The attack becomes:

1. Guess part of the flag.
2. Load `/?search=<guess>`.
3. Try to navigate to `#note-0`.
4. Observe whether the browser behaves as if `note-0` exists.
5. If yes, our guessed substring exists in the flag note.
6. Extend the prefix one character at a time.

This is why the challenge is hard:

- same-origin policy stops direct reads
- but browser behavior still leaks one bit at a time

This is exactly why the challenge falls into the XS-Search family rather than ordinary web exploitation.
The outside references above were important because they gave a concrete, known mechanism to test instead of random guesswork.

## Step 7: The First Failed Attempts

Before getting the final oracle, several tempting paths looked promising but were not enough:

- direct XSS in notes
- using `/image` and `/script`
- trying to read response headers cross-origin
- testing popup-only approaches without a strong focus signal

The challenge endpoint `/image` and `/script` were suspicious because they set the `x-meow-meow` header before failing, but in practice the cleaner and more reliable primitive was the search-result focus leak.

## Step 8: Why We Needed Our Own Host

The bot visits an attacker-controlled URL, so we need a public page the bot can load.

At first, third-party hosting options were annoying:

- some pages injected CSP
- some escaped HTML
- some only worked in limited contexts like top-level SVG

The final practical solution was to host our own attacker page locally and expose it with a reverse tunnel.

That is what [attacker_server.py](https://www.notion.so/home/foqs/ctf/attacker_server.py) does.

It serves:

- `/` the attacker probe page
- `/log` a beacon endpoint
- `/result` a simple result store for the brute-forcer
- `/healthz` a health check

## Step 9: Build A Positive And Negative Oracle

To solve this challenge, we need a binary signal:

- positive = search matched
- negative = search did not match

The attacker page creates:

- a local input field that keeps focus
- an iframe pointing at the target page

Then it:

1. loads the target page with a search query
2. gives focus back to the local page
3. navigates the iframe to the same page plus `#note-0`
4. checks whether focus moved into the iframe

If focus moves to the iframe:

- `note-0` probably exists
- so the search matched

If focus stays on the local input:

- `note-0` did not become focusable
- so the search did not match

This detection strategy is directly based on the focus/ID leak technique from PortSwigger and XS-Leaks Wiki:

- PortSwigger uses focus transfer and attacker-side `blur` handling as the signal:
https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki describes using an iframe and observing whether the target fragment causes focus behavior:
https://xsleaks.dev/docs/attacks/id-attribute/

## Step 10: Verify The Oracle On The Real Target

I did not want to assume the technique worked without proving it.

So I tested two controls.

### Positive control

Use a search that is guaranteed to match the flag note:

```
/
then
/#note-0
```

This caused focus to move into the iframe.

### Negative control

Use a search string that should not exist:

```
/?search=zzzzzzzzzz
then
/?search=zzzzzzzzzz#note-none
```

This left focus on the local input.

That proved the oracle was real.

This verification step matters because external research only tells you that the browser mechanic exists in principle.
You still have to confirm all of these on the actual target:

- the page really creates predictable IDs
- the relevant element is actually focusable
- the victim browser still exposes the signal
- your attacker page can observe it reliably

## Step 11: Why This Leaks The Flag

Suppose we know the flag starts with `RS{`.

We test:

- `RS{a`
- `RS{b`
- `RS{c`
- ...

If one of them causes a positive result, that character is in the real flag prefix.

Then we continue:

- `RS{wa`
- `RS{wb`
- `RS{wc`
- ...

Each successful probe reveals one more character.

Because the bot stores the entire flag as one note, substring search is enough.

## Step 12: The Allowed Charset

The challenge hint narrowed the flag body to:

```
RS{[\\w\\d!?:]*}
```

In practice that means these characters are enough to brute-force:

- uppercase letters
- lowercase letters
- digits
- `_`
- `!`
- `?`
- `:`
- and finally `}`

That is exactly what [bruteforce_flag.py](https://www.notion.so/home/foqs/ctf/bruteforce_flag.py) uses.

## Supporting Research I Also Checked

While the final exploit path was the focus-based XS-Search oracle, I also checked cookie behavior because the bot flow is cross-site and those rules often decide what attack surfaces are possible.

Useful references:

- MDN, `Set-Cookie` / `SameSite`https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
- web.dev, `SameSite cookies explained`https://web.dev/articles/samesite-cookies-explained

This was supporting research, not the final core exploit.
The direct winning idea was still the focus/fragment leak.

## Step 13: What The Brute-Forcer Does

[bruteforce_flag.py](https://www.notion.so/home/foqs/ctf/bruteforce_flag.py) automates the process:

1. Start from a known prefix such as `RS{wh`.
2. Try candidate next characters.
3. For each candidate:
    - submit a bot job pointing to our attacker page
    - ask the attacker page to search for that candidate
    - poll `/result` until a terminal event appears
4. If the result is positive, extend the prefix.
5. Repeat until `}` is found.

## Step 14: Why Extraction Was Operationally Annoying

The exploit logic works.

The annoying part is infrastructure:

- the reverse tunnel domain dies or rotates
- the local attacker server may need restarting
- the bot endpoint sometimes slows down or drops requests

That is why a "fast" brute-force was unstable.

A slower, resumable brute-force was more reliable.

## Step 15: Partial Live Recovery

During live extraction, I confirmed real flag characters:

- `RS{w`
- then `RS{wh`

So the method is not hypothetical.
It already recovered genuine flag prefix characters from the live service.

## Final Exploit Idea In One Paragraph

The bot stores the flag as a note and then visits our page. Our page loads the note app in an iframe with a search query for a guessed flag substring. It then navigates the iframe to `#note-0`. If the search matched, `note-0` exists and the target page steals focus into the iframe. If not, focus stays on our local input. That gives a one-bit oracle for "does any note contain this substring?" Repeating that over the allowed character set recovers the flag one character at a time.

## Simple Beginner Version

If you are new to web exploitation, this is the easiest way to think about it:

- We are not reading the page.
- We are watching how the browser reacts.
- The page reacts differently when a search result exists.
- That tiny difference leaks secret data.

This is a very common lesson in harder browser challenges:

> same-origin policy stops direct reading, but it does not stop every side effect.
> 

## Practical Solver Workflow

1. Run the attacker server:

```bash
python3 attacker_server.py
```

1. Expose it publicly with a tunnel.
2. Confirm the tunnel is alive:

```bash
curl -iLsS <https://YOUR-TUNNEL/healthz>
```

1. Resume brute-force from the current known prefix:

```bash
python3 bruteforce_flag.py 'RS{wh' '<https://YOUR-TUNNEL>'
```

1. If the tunnel dies, reopen it and resume with the new host.

## Lessons From This Challenge

- Not all web challenges are about injection.
- Browser behavior itself can be exploitable.
- Predictable DOM structure can become a side channel.
- Search endpoints are often dangerous in bot challenges.
- A one-bit leak is enough if you can repeat it many times.

## References

Primary mechanic references:

- PortSwigger, `XS-Leak: Leaking IDs using focus`https://portswigger.net/research/xs-leak-leaking-ids-using-focus
- XS-Leaks Wiki, `ID Attribute`https://xsleaks.dev/docs/attacks/id-attribute/

Supporting browser/cookie references:

- MDN, `Set-Cookie` / `SameSite`https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value
- web.dev, `SameSite cookies explained`https://web.dev/articles/samesite-cookies-explained

The exact exploit here ended up being primarily the search-result focus oracle described by the first two sources.

## Conclusion

This challenge is a strong example of a modern browser-side CTF problem.

There is no easy XSS.
There is no trivial direct data exfiltration.
Instead, the solution is to:

- understand the bot
- understand the rendered DOM
- find a browser side effect
- turn it into a yes/no oracle
- and brute-force the flag through repeated search queries

That is why the challenge is difficult, and also why it is a very good XS-Leak challenge.
