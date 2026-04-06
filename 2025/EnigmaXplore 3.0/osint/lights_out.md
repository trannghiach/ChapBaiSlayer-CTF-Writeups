## Metadata

- **Challenge:** Lights out and here we go!
- **Category:** OSINT
- **Difficulty:** Medium
- **Event:** EnXp CTF
- **Solver:** not solved in time
- **Analyst:** Aurelinth
- **Target:** Grand Hotel Terme Riolo (Italy)
- **Date:** 2025-10-11

---

## Executive summary

<img width="853" height="1024" alt="image" src="https://github.com/user-attachments/assets/1aca6e46-da5a-49c2-bf08-69e38a3de130" />


Challenge cung cấp mô tả về một sự kiện đua xe cổ, trong đó xuất hiện chiếc Porsche 935 restomod của Torwesten Racing. Dựa trên chi tiết “A British Knight was quickest at 1:15.484” (ẩn ý đến Sir Lewis Hamilton và thời gian lập tại Imola 2020), đội giải xác định được đường đua là **Autodromo Enzo e Dino Ferrari (Imola)**. Từ đó, sử dụng Overpass Turbo để truy vấn các khách sạn quanh trường đua, lọc ra **Grand Hotel Terme Riolo** và thu được flag `EnXp{GRAND_HOTEL_TERME_RIOLO}`.

---

## Scope & preconditions

- Phạm vi: sử dụng hoàn toàn dữ liệu công khai (OpenStreetMap, Google Maps, Booking,...)
- Không yêu cầu credential hay brute-force.
- Flag format: `EnXp{HOTEL_NAME}`

---

## Recon / initial observations

**Challenge description:**

> I went to see an event earlier this year and saw this car there. A British Knight was quickest at 1:15.484 to lap the circuit. I stayed at a hotel which looked like a mansion from the front, about 15 minutes from the place.
> 
- Ảnh đính kèm: Porsche 935 DP935 với livery Torwesten Racing.
- “A British Knight” → ám chỉ Sir Lewis Hamilton (tay đua người Anh, có tước hiệu Knight) → đường đua có vòng 1:15.484 là **Imola (2020 Emilia Romagna GP)**.
- Địa điểm được xác định: **Autodromo Enzo e Dino Ferrari, Imola, Italy.**

---

## Exploitation — step-by-step

### Bước 1 — Xác định toạ độ đường đua Imola

```
Latitude: 44.34391
Longitude: 11.71672

```

### Bước 2 — Dò khách sạn quanh Imola bằng Overpass Turbo

Truy vấn sử dụng:

```
[out:json][timeout:60];
(
  node["tourism"="hotel"](around:20000,44.34391,11.71672);
  way["tourism"="hotel"](around:20000,44.34391,11.71672);
  relation["tourism"="hotel"](around:20000,44.34391,11.71672);
);
out tags center;

```

Truy vấn trả về **42 đối tượng** dạng `hotel` quanh Imola.

<img width="807" height="767" alt="image" src="https://github.com/user-attachments/assets/756ed614-9c34-44ab-b400-d5355e3c8a14" />


### Bước 3 — Lọc tên có khả năng là “mansion-like” (Grand, Villa, Terme...)

Sau khi kiểm tra thủ công 42 node, đội phát hiện một node có:

```
name = Grand Hotel Terme Riolo
addr:city = Riolo Terme
```

### Bước 4 — Kiểm tra trên Google Maps

- **Tên chính xác:** Grand Hotel Terme Riolo
- **Địa chỉ:** Via Firenze, 15, 48025 Riolo Terme RA, Italy
- **Khoảng cách:** ~11–12 km (~15 phút lái xe từ Imola Circuit)
- **Mặt tiền:** kiến trúc dinh thự cổ, hoàn toàn khớp mô tả trong challenge.

<img width="1151" height="681" alt="image" src="https://github.com/user-attachments/assets/cc79628d-234c-4f7a-bff2-09408176e02b" />


### Bước 5 — Xây dựng flag

Theo format đề bài: `EnXp{HOTEL_NAME}`

→ `EnXp{GRAND_HOTEL_TERME_RIOLO}`

Flag được xác nhận chính xác.

---

## Artifacts

- **Flag:** `EnXp{GRAND_HOTEL_TERME_RIOLO}`
- **File:** car.jpg (ảnh Torwesten Porsche 935)
- **Công cụ:** Overpass Turbo, Google Maps

---

## Remediation recommendations

Không áp dụng (OSINT challenge). Tuy nhiên, trong bối cảnh thực tế, cần tránh để lộ dữ liệu định vị hoặc hình ảnh có metadata khi công bố nội dung sự kiện công khai.

---

## Timeline

- Phát hiện ban đầu (Sachsenring): 2025-10-10
- Mô tả challenge được cập nhật (hint “British Knight”): 2025-10-11
- Giải thành công: 2025-10-11

---

## Appendix

**Truy vấn Overpass gốc:**

```
[out:json][timeout:60];
(
  node["tourism"="hotel"](around:20000,44.34391,11.71672);
  way["tourism"="hotel"](around:20000,44.34391,11.71672);
  relation["tourism"="hotel"](around:20000,44.34391,11.71672);
);
out tags center;

```

---

# English Version

## Metadata

- **Challenge:** Lights out and here we go!
- **Category:** OSINT
- **Difficulty:** Medium
- **Event:** EnXp CTF
- **Solver:** not solved in time
- **Analyst:** Aurelinth
- **Target:** Grand Hotel Terme Riolo (Italy)
- **Date:** 2025-10-11

---

## Executive summary

The challenge provided a description of a historic racing event featuring a Torwesten Racing Porsche 935 restomod. The line “A British Knight was quickest at 1:15.484” was the key clue — it referenced Sir Lewis Hamilton’s fastest lap at Imola in 2020, leading to the identification of the **Autodromo Enzo e Dino Ferrari (Imola)** circuit. Using Overpass Turbo to query hotels around the track, the solver found **Grand Hotel Terme Riolo**, yielding the flag `EnXp{GRAND_HOTEL_TERME_RIOLO}`.

---

## Scope & preconditions

- Scope: strictly OSINT, using public data only (OpenStreetMap, Google Maps, Booking, etc.)
- No credentials or brute-force required.
- Flag format: `EnXp{HOTEL_NAME}`

---

## Recon / initial observations

**Updated challenge description:**

> I went to see an event earlier this year and saw this car there. A British Knight was quickest at 1:15.484 to lap the circuit. I stayed at a hotel which looked like a mansion from the front, about 15 minutes from the place.
> 
- Attached image: Porsche 935 DP935 with Torwesten Racing livery.
- “A British Knight” → refers to Sir Lewis Hamilton (British driver, Knighted), whose 1:15.484 lap time was recorded at **Imola (2020 Emilia Romagna GP)**.
- Thus, the circuit was identified as **Autodromo Enzo e Dino Ferrari, Imola, Italy.**

---

## Exploitation — step-by-step

### Step 1 — Determine the coordinates of Imola Circuit

```
Latitude: 44.34391
Longitude: 11.71672

```

### Step 2 — Query nearby hotels using Overpass Turbo

```
[out:json][timeout:60];
(
  node["tourism"="hotel"](around:20000,44.34391,11.71672);
  way["tourism"="hotel"](around:20000,44.34391,11.71672);
  relation["tourism"="hotel"](around:20000,44.34391,11.71672);
);
out tags center;

```

The query returned **42 hotel objects** around Imola.

### Step 3 — Filter for “mansion-like” names (Grand, Villa, Terme...)

After manually reviewing the 42 nodes, one entry stood out:

```
name = Grand Hotel Terme Riolo
addr:city = Riolo Terme

```

### Step 4 — Verify using Google Maps

- **Official name:** Grand Hotel Terme Riolo
- **Address:** Via Firenze, 15, 48025 Riolo Terme RA, Italy
- **Distance:** ~11–12 km (~15-minute drive from Imola Circuit)
- **Facade:** classical mansion-like architecture, perfectly matching the challenge description.

### Step 5 — Construct the flag

Following the required format `EnXp{HOTEL_NAME}`:

→ `EnXp{GRAND_HOTEL_TERME_RIOLO}`

The flag was verified as correct.

---

## Artifacts

- **Flag:** `EnXp{GRAND_HOTEL_TERME_RIOLO}`
- **File:** car.jpg (Torwesten Porsche 935)
- **Tools used:** Overpass Turbo, Google Maps

---

## Remediation recommendations

Not applicable (OSINT challenge). In real-world scenarios, avoid publishing metadata or identifiable geolocation information in media related to public events.

---

## Timeline

- Initial hypothesis (Sachsenring): 2025-10-10
- Challenge description updated (hint “British Knight”): 2025-10-11
- Flag obtained: 2025-10-11

---

## Appendix

**Original Overpass query:**

```
[out:json][timeout:60];
(
  node["tourism"="hotel"](around:20000,44.34391,11.71672);
  way["tourism"="hotel"](around:20000,44.34391,11.71672);
  relation["tourism"="hotel"](around:20000,44.34391,11.71672);
);
out tags center;

```
