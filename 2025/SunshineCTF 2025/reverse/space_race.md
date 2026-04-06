# Sunshine CTF 2025 — Space Race

**Thể loại:** Reverse Engineering / Protocol & Network

**Độ khó:** Trung bình

---

## Tổng quan thử thách

Thử thách cung cấp ba tệp: `server` (Go, static, không strip), `client.py` (pygame, **chưa** cài đặt phần điều khiển), và `Dockerfile` chạy `server` qua `socat` (TCP).

Máy chủ phát liên tục **telemetry** dạng JSON-line và chờ client gửi lại các khung “CAN” cũng ở dạng JSON-line để điều khiển rover. Hoàn thành đường đua sẽ khiến máy chủ đưa flag trong trường `flag` của gói telemetry.

---

## Mục tiêu

- Phân tích nhị phân Go để suy ra **định dạng khung CAN** mà máy chủ chấp nhận.
- Viết client/patch điều khiển gửi đúng khung (throttle/steer/brake/stop/reset).
- Tự động lái rover về đích → nhận flag.

---

## Kiến thức cần thiết

- Đọc disassembly Go (mẫu gọi `bufio.(*Reader).ReadBytes`, `encoding/json.Unmarshal`, `encoding/hex.Decode`, `fmt.Sprintf`…), nhận diện luồng xử lý input.
- JSON-line qua TCP, đóng gói hex → bytes → cấu trúc khung.
- Điều khiển cơ bản (P-controller) để giữ rover ở giữa đường (`x≈0`) và quản lý ga/phanh.

---

## Phân tích và hướng tiếp cận

Từ phần disassembly `main.main` (đoạn quan trọng):

1. Server đọc từng **dòng** từ stdin → `json.Unmarshal` vào object có trường `t` và `frame`.
2. Với `t == "can"`, server `hex.Decode(frame)` thành bytes và parse theo cấu trúc:
    
    ```
    raw[0] = a0
    raw[1] = b1
    raw[2] = len_nibble   (độ dài payload = raw[2] & 0x0F, 0..8)
    raw[3..] = payload (len_nibble byte)
    
    ```
    
3. Tính **CAN ID hiệu dụng**:
    
    ```
    id = ((a0 & 0x07) << 8) | b1
    
    ```
    
    → High byte lấy 3 bit thấp của `a0`; low byte = `b1`.
    
    Muốn đi vào dải `0x20X` mà server xử lý: **chọn a0 sao cho (a0 & 7) = 0x02**.
    
    Dùng lựa chọn tối giản: `a0 = 0x02`, `b1` chính là low-byte (01..05).
    
4. Bảng lệnh (ID) server hỗ trợ:
    - `0x201` (a0=0x02, b1=0x01, len=1, data 0..100) → **THROTTLE** (%)
    - `0x202` (a0=0x02, b1=0x02, len=1, data int8 −100..100) → **STEER**
    - `0x203` (a0=0x02, b1=0x03, len=0) → **BRAKE** (giảm vận tốc: *0.65)
    - `0x204` (a0=0x02, b1=0x04, len=0) → **STOP/SLOW** (zero steer/throttle, giảm momentum)
    - `0x205` (a0=0x02, b1=0x05, len=0) → **RESET** (đặt lại trạng thái)
5. Ràng buộc hợp lệ: tổng bytes ≥ 3; `len≤8` và `3+len≤tổng`.
    
    Với `0x201/0x202` cần đúng 1 byte payload; `0x203..0x205` **không** có payload.
    

---

## Kịch bản giải mã (Exploit)

### Khung mẫu (HEX liền, không khoảng trắng)

- Throttle 100%: `02010164`
- Steer 0: `02020100`
- Steer +40: `02020128`
- Steer −40: `020201D8` *(int8 −40 = 0xD8)*
- Brake: `020300`
- Stop: `020400`
- Reset: `020500`

Mỗi khung bọc trong JSON-line (một dòng/khung):

```json
{"t":"can","frame":"02010164"}

```

### Bot tự lái (Python) — `solve.py`

- Reset/Stop để ổn định.
- P-controller trên `x` để giữ giữa đường; ga ~88%, phanh nhẹ gần đích.

```python
#!/usr/bin/env python3
import socket, json, sys, threading, queue, time

def pack(a0, b1, data=b""):
    ln = len(data) & 0x0F
    raw = bytes([a0, b1, ln]) + data
    return {"t":"can","frame": raw.hex()}

def throttle(p): p=max(0,min(100,p)); return pack(0x02,0x01,bytes([p]))
def steer(p):   p=max(-100,min(100,p)); return pack(0x02,0x02,bytes([(p+256)%256]))
def brake():    return pack(0x02,0x03)
def stop():     return pack(0x02,0x04)
def reset_cmd():return pack(0x02,0x05)

class Net:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.r = self.sock.makefile('r', buffering=1, encoding='utf-8', newline='\n')
        self.q = queue.Queue(); self.alive = True
        self.wlock = threading.Lock()
        threading.Thread(target=self.reader, daemon=True).start()
    def reader(self):
        try:
            for line in self.r:
                line=line.strip()
                if not line: continue
                try: self.q.put(json.loads(line))
                except: pass
        except: pass
        self.alive=False
    def send(self, obj):
        data = (json.dumps(obj)+"\n").encode()
        with self.wlock: self.sock.sendall(data)

def main():
    host, port = "chal.sunshinectf.games", 25102
    if len(sys.argv)==3: host, port = sys.argv[1], int(sys.argv[2])
    net = Net(host, port)

    net.send(reset_cmd()); time.sleep(0.05)
    net.send(stop());      time.sleep(0.05)

    last_send=0.0; target_th=88; Kp=1.8; t0=time.time()
    while net.alive:
        try: telem = net.q.get(timeout=1.0)
        except queue.Empty: continue
        if telem.get("t")!="telemetry": continue
        if telem.get("flag"):
            print("[*] FLAG:", telem["flag"]); return

        s=float(telem.get("s",0.0))
        x=float(telem.get("x",0.0))
        vel=float(telem.get("vel",0.0))
        length=float(telem.get("track",{}).get("length",1.0))

        now=time.time()
        if now-last_send>0.05:  # ~20 Hz
            cmd_steer=int(max(-100,min(100, -Kp*x)))
            net.send(steer(cmd_steer))
            if s/max(1.0,length)>0.92 and vel>8.0:
                net.send(brake())
            else:
                net.send(throttle(target_th))
            last_send=now

        if int((now-t0)*2)%10==0:
            print(f"s={s:.1f}/{length:.0f}  x={x:.2f}  vel={vel:.2f}")

if __name__=="__main__": main()

```

**Chạy:**

`python3 solve.py`

hoặc chỉ định: `python3 solve.py chal.sunshinectf.games 25102`

---

**Kết quả (Flag)**

Sau khi bot điều khiển ổn định tới đích, server phát flag trong telemetry. Kết quả thực tế:

`sun{r3d_r0v3r_c0m3_0v3r}`

---

## Ghi chú và mẹo

- Lỗi phổ biến: **sai byte order** hai byte đầu → server bỏ qua lệnh (s không tăng). Đúng là: `id = ((a0 & 7)<<8) | b1` và **mỗi khung** phải là **một dòng JSON** kết thúc `\n`.
- `0x201/0x202` đòi **đúng 1 byte** payload; `0x203..205` không payload.
- Nếu map có obstacle khó, có thể thêm thành phần D hoặc giới hạn |x| để phanh/stop tạm.

---

# ENGLISH VERSION

**Category:** Reverse Engineering / Protocol & Network

**Difficulty:** Medium

---

## Challenge Overview

You’re given `server` (Go, static, not stripped), `client.py` (pygame with controls unimplemented), and a `Dockerfile` that exposes the Go server via `socat`.

The server emits **telemetry** as JSON-lines and expects the client to send **CAN** control frames (also as JSON-lines). Reaching the finish line makes the server include the flag in the telemetry’s `flag` field.

---

## Objective

- Reverse the Go binary to learn the **exact CAN frame format**.
- Implement a client/patch that sends valid frames (throttle/steer/brake/stop/reset).
- Autopilot the rover to the finish line to obtain the flag.

---

## Required Knowledge

- Reading Go disassembly (typical patterns: `bufio.(*Reader).ReadBytes`, `encoding/json.Unmarshal`, `encoding/hex.Decode`).
- JSON-lines over TCP and hex-to-bytes packing.
- Basic control (P-controller) to keep the rover centered (`x≈0`) and manage throttle/brake.

---

## Analysis and Approach

From `main.main`:

1. The server reads **one line** at a time → `json.Unmarshal` into an object with `t` and `frame`.
2. When `t == "can"`, it `hex.Decode`s `frame` into bytes and parses:
    
    ```
    raw[0] = a0
    raw[1] = b1
    raw[2] = len_nibble   (payload length = raw[2] & 0x0F, 0..8)
    raw[3..] = payload
    
    ```
    
3. The **effective CAN ID** is computed as:
    
    ```
    id = ((a0 & 0x07) << 8) | b1
    
    ```
    
    To hit the `0x20X` range handled by the server, ensure **(a0 & 7) == 0x02**.
    
    Minimal choice: `a0 = 0x02`, with `b1` as the low byte.
    
4. Supported command IDs:
    - `0x201` (a0=0x02, b1=0x01, len=1, data 0..100) → **THROTTLE** (%)
    - `0x202` (a0=0x02, b1=0x02, len=1, data int8 −100..100) → **STEER**
    - `0x203` (a0=0x02, b1=0x03, len=0) → **BRAKE** (*0.65 speed)
    - `0x204` (a0=0x02, b1=0x04, len=0) → **STOP/SLOW**
    - `0x205` (a0=0x02, b1=0x05, len=0) → **RESET**
5. Validity: total bytes ≥ 3; `len≤8` and `3+len≤total`.
    
    `0x201/0x202` require **exactly 1** payload byte; `0x203..0x205` have **no** payload.
    

---

## Exploit Script

### Canonical frames (HEX, no spaces)

- Throttle 100%: `02010164`
- Steer 0: `02020100`
- Steer +40/−40: `02020128` / `020201D8`
- Brake/Stop/Reset: `020300` / `020400` / `020500`

Each sent as a **single JSON line**:

```json
{"t":"can","frame":"02010164"}

```

### Autopilot (Python) — `solve.py`

P-controller on lateral error `x`; throttle ~88%; apply gentle brake near the finish:

```python
#!/usr/bin/env python3
import socket, json, sys, threading, queue, time

def pack(a0, b1, data=b""):
    ln = len(data) & 0x0F
    raw = bytes([a0, b1, ln]) + data
    return {"t":"can","frame": raw.hex()}

def throttle(p): p=max(0,min(100,p)); return pack(0x02,0x01,bytes([p]))
def steer(p):   p=max(-100,min(100,p)); return pack(0x02,0x02,bytes([(p+256)%256]))
def brake():    return pack(0x02,0x03)
def stop():     return pack(0x02,0x04)
def reset_cmd():return pack(0x02,0x05)

class Net:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.r = self.sock.makefile('r', buffering=1, encoding='utf-8', newline='\n')
        self.q = queue.Queue(); self.alive = True
        self.wlock = threading.Lock()
        threading.Thread(target=self.reader, daemon=True).start()
    def reader(self):
        try:
            for line in self.r:
                line=line.strip()
                if not line: continue
                try: self.q.put(json.loads(line))
                except: pass
        except: pass
        self.alive=False
    def send(self, obj):
        data = (json.dumps(obj)+"\n").encode()
        with self.wlock: self.sock.sendall(data)

def main():
    host, port = "chal.sunshinectf.games", 25102
    if len(sys.argv)==3: host, port = sys.argv[1], int(sys.argv[2])
    net = Net(host, port)

    net.send(reset_cmd()); time.sleep(0.05)
    net.send(stop());      time.sleep(0.05)

    last_send=0.0; target_th=88; Kp=1.8; t0=time.time()
    while net.alive:
        try: telem = net.q.get(timeout=1.0)
        except queue.Empty: continue
        if telem.get("t")!="telemetry": continue
        if telem.get("flag"):
            print("[*] FLAG:", telem["flag"]); return

        s=float(telem.get("s",0.0))
        x=float(telem.get("x",0.0))
        vel=float(telem.get("vel",0.0))
        length=float(telem.get("track",{}).get("length",1.0))

        now=time.time()
        if now-last_send>0.05:
            cmd_steer=int(max(-100,min(100, -Kp*x)))
            net.send(steer(cmd_steer))
            if s/max(1.0,length)>0.92 and vel>8.0:
                net.send(brake())
            else:
                net.send(throttle(target_th))
            last_send=now

        if int((now-t0)*2)%10==0:
            print(f"s={s:.1f}/{length:.0f}  x={x:.2f}  vel={vel:.2f}")

if __name__=="__main__": main()

```

**Result (Flag)**

Once the rover finishes, the server includes the flag in telemetry. Actual run output:

`sun{r3d_r0v3r_c0m3_0v3r}`

---

## Postmortem / Tips

- Most failures came from a **wrong two-byte mapping**: the server uses `id=((a0&7)<<8)|b1`. Use `a0=0x02`, `b1=low`, and ensure **one JSON per line**.
- `0x201/0x202` require 1-byte payload; `0x203..0x205` require none.
- If the remote map is harsher, add derivative damping or temporary stop/brake when |x| exceeds a threshold.
