# Sunshine CTF 2025 — Hail Mary

**Thể loại:** Scripting / Optimization (Black-Box)

**Độ khó:** Dễ–Trung bình

---

## Tổng quan thử thách

Máy chủ mô phỏng “phòng thí nghiệm tiến hóa” cho taumoeba. Mỗi lượt gửi (**một “thế hệ”**) bạn phải nộp **100 cá thể**, mỗi cá thể là **vector 10 số thực trong [0,1]** (định dạng JSON). Máy chủ chấm điểm **tỷ lệ sống sót** và trả về:

- `average` (giá trị thực 0..1 cho cả quần thể),
- `scores` (danh sách 100 điểm 0..1 cho từng cá thể — thực tế có).

Mục tiêu: đạt **average ≥ 0.95** trong **≤ 100 thế hệ** để nhận flag.

---

## Mục tiêu

Tối ưu hoá tham số di truyền sao cho **điểm trung bình** của 100 mẫu đạt ngưỡng 95% trở lên. Khai thác việc máy chủ **lấy trung bình tuyến tính** của các điểm cá thể.

---

## Kiến thức cần thiết

- **Black-box optimization / Evolution Strategy (ES):** Khai phá và cập nhật phân phối tìm kiếm khi chỉ có phản hồi điểm.
- **Xử lý JSON / socket:** Gửi payload `{"samples":[[...10 floats...], ...]}` và parse phản hồi.
- **Nhận diện thuộc tính chấm điểm:** `average` là **trung bình** các `scores`, không có phạt trùng lặp.

---

## Phân tích và hướng tiếp cận

1. **Mô hình hoá:** Không gian tìm kiếm là ([0,1]^{10}). Mỗi thế hệ có **batch size = 100** → phù hợp ES.
2. **Chiến lược ES tối thiểu:**
    - Duy trì một **vector mean** và **độ nhiễu Gaussian (\sigma)**.
    - Sinh 100 biến thể quanh `mean`, clip về [0,1].
    - Nếu có `scores`, cập nhật `mean` theo **top-K weighted**; tinh chỉnh (\sigma).
3. **Nước “chốt bài” (finisher):**
    - Khi quan sát **một cá thể** đạt (\ge 0.95) (qua `scores`), gửi **100 bản sao** cá thể đó.
        
        Vì **average = mean(s) = s*** (100 số giống nhau), average lập tức ≥ 0.95 ⇒ nhận flag.
        
    - Đây là điểm mấu chốt: **không cần biết chính xác công thức chấm**, chỉ cần biết average là **trung bình** không phạt trùng lặp.

---

## Kịch bản giải (Exploit)

Script rút gọn dưới đây thực hiện ES + tự động “finisher” khi phát hiện cá thể đạt ngưỡng.

*(Comment bằng tiếng Anh để dễ tái dụng.)*

```python
#!/usr/bin/env python3
# Minimal ES + immediate finisher for SunshineCTF "Hail Mary"
# Comments in English only.

import socket, json, random, time

HOST, PORT = "chal.sunshinectf.games", 25201
POP, DIM = 100, 10
TARGET = 0.95           # server uses 0..1 scale for scores/average
SIGMA0 = 0.18
TOPK = 10
TIMEOUT = 6.0
MAXGEN = 100

def clip01(x): return 0.0 if x < 0 else (1.0 if x > 1 else x)
def mutate(v, s): return [clip01(x + random.gauss(0, s)) for x in v]
def pack(samples): return (json.dumps({"samples": samples}) + "\n").encode()
def pct(x): return f"{x*100:.2f}%"

def recv_all(sock, t=0.25):
    """Read a short burst from server."""
    sock.settimeout(TIMEOUT)
    time.sleep(t)
    chunks = []
    while True:
        try:
            buf = sock.recv(8192)
            if not buf: break
            chunks.append(buf.decode(errors="ignore"))
            if len(buf) < 8192: break
        except socket.timeout:
            break
    return "".join(chunks)

def parse_json_block(txt):
    """Extract the last {...} JSON block if present."""
    l, r = txt.rfind("{"), txt.rfind("}")
    if l != -1 and r != -1 and r > l:
        try: return json.loads(txt[l:r+1])
        except Exception: pass
    return {}

def es_mean(samples, scores, k=TOPK):
    """Weighted mean of top-k samples by score."""
    idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    wsum = sum(max(1e-9, scores[i]) for i in idx)
    mean = [0.0]*DIM
    for i in idx:
        w = max(1e-9, scores[i]) / wsum
        for j in range(DIM):
            mean[j] += samples[i][j] * w
    return mean

def main():
    random.seed()
    mean = [random.random() for _ in range(DIM)]
    sigma = SIGMA0
    best_gene, best_global = mean[:], 0.0

    s = socket.socket(); s.settimeout(TIMEOUT); s.connect((HOST, PORT))
    _ = recv_all(s)  # banner (ignored)

    for gen in range(1, MAXGEN + 1):
        # propose population
        samples = [mutate(mean, sigma) for _ in range(POP)]
        s.sendall(pack(samples))
        resp = recv_all(s)
        data = parse_json_block(resp)

        avg = float(data.get("average", 0.0))          # 0..1
        scores = data.get("scores") if isinstance(data.get("scores"), list) else None

        best_in_gen = None
        if scores and len(scores) == POP:
            ib = max(range(POP), key=lambda i: scores[i])
            best_in_gen = scores[ib]
            if best_in_gen > best_global:
                best_global, best_gene = best_in_gen, samples[ib][:]

        # log one line per generation
        print(f"[GEN {gen:02d}] avg={pct(avg)} "
              f"best_in_gen={pct(best_in_gen) if best_in_gen is not None else 'N/A'} "
              f"best_global={pct(best_global)} sigma={sigma:.3f} "
              f"action={'finish' if best_global>=TARGET else 'update'}")

        # finisher: clone the best individual to force average >= TARGET
        if best_global >= TARGET:
            clones = [best_gene[:] for _ in range(POP)]
            s.sendall(pack(clones))
            fin = recv_all(s, t=0.5)
            fdata = parse_json_block(fin)
            favg = fdata.get("average", None)
            print("[FINISH] sent 100x best | avg_after=" +
                  (pct(float(favg)) if isinstance(favg, (int, float)) else "N/A"))
            pv = fin.strip().replace("\n", " ")
            print("[SERVER PREVIEW]", pv[:300] + ("..." if len(pv) > 300 else ""))
            s.close()
            return

        # ES update or average-only fallback
        if scores and len(scores) == POP:
            mean = es_mean(samples, scores)
            improved = (best_in_gen is not None and abs(best_in_gen - best_global) < 1e-12)
            sigma = max(0.03, min(0.35, sigma * (1.10 if improved else 0.90)))
        else:
            alt = mutate(mean, sigma)
            ab = [mutate(mean, sigma) for _ in range(POP//2)] + \
                 [mutate(alt,  sigma) for _ in range(POP-POP//2)]
            s.sendall(pack(ab)); _ = recv_all(s)
            mean = mutate(mean, sigma*0.3)
            sigma = max(0.04, sigma*0.93)

    # Last resort: clone best observed
    clones = [best_gene[:] for _ in range(POP)]
    s.sendall(pack(clones))
    fin = recv_all(s, t=0.5)
    print("[LAST RESORT PREVIEW]", fin[:300])

if __name__ == "__main__":
    main()

```

**Kết quả (Flag)**

Chạy script, log thực tế mẫu (rút gọn):

```
[GEN 06] avg=89.41% best_in_gen=95.58% best_global=95.58% sigma=0.290 action=finish
[FINISH] sent 100x best | avg_after=N/A
[SERVER PREVIEW] Success! Earth has been saved! Here is your flag: sun{wh4t_4_gr34t_pr0j3ct}

```

Flag: `sun{wh4t_4_gr34t_pr0j3ct}`

---

## Ghi chú và mẹo

- Mấu chốt: **average là trung bình các cá thể** và **không phạt trùng lặp** ⇒ phát hiện cá thể ≥ 0.95 là có thể **clone 100×** để chốt.
- Nếu máy chủ **không** trả `scores` theo mẫu, vẫn có thể dùng **A/B testing** + random walk để đẩy `average` lên; nhưng khi `scores` có sẵn thì ES hội tụ rất nhanh.
- Luôn parse `average` theo **scale 0..1** (nếu cần hiển thị %, nhân ×100 cho dễ nhìn).

---

# ENGLISH VERSION

**Category:** Scripting / Optimization (Black-Box)

**Difficulty:** Easy–Medium

---

## Overview

You submit **100 individuals** per generation, each is a **10-float vector in [0,1]** (JSON). The server returns:

- `average` (0..1), and
- `scores` (100 per-sample scores, 0..1 — present in practice).

Goal: reach **average ≥ 0.95** within **≤ 100 generations**.

---

## Objective

Drive the population’s average to ≥ 0.95. Exploit the fact that the server computes a **plain mean** over per-sample scores.

---

## Analysis & Approach

- Use a **minimal Evolution Strategy**: maintain a mean vector and a Gaussian noise `sigma`; sample 100 mutations around the mean; update the mean using **top-K weighted** if per-sample `scores` are provided.
- **Finisher:** once any individual reaches ≥ 0.95, submit **100 clones** of that individual. Since `average = mean(scores)`, cloning forces `average = s* ≥ 0.95` → flag.

---

## Exploit Script

See the Python script above (ES + immediate finisher; one-line logs per generation).

**Sample run (trimmed):**

```
[GEN 06] avg=89.41% best_in_gen=95.58% best_global=95.58% sigma=0.290 action=finish
[FINISH] sent 100x best | avg_after=N/A
[SERVER PREVIEW] Success! Earth has been saved! Here is your flag: sun{wh4t_4_gr34t_pr0j3ct}

```

**Flag:** `sun{wh4t_4_gr34t_pr0j3ct}`

---

## Postmortem / Tips

- The key insight is linear averaging with **no diversity penalty**. Detect one ≥ 0.95 individual → clone 100× to force the average.
- Without per-sample `scores`, use **A/B bandit-like exploration** and a small random walk on the mean; with scores, ES converges quickly.
- Treat server `average` as **0..1**; multiply by 100% only for display.
