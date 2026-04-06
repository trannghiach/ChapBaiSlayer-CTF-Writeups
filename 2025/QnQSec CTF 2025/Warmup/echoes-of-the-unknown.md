# QnQSec CTF 2025 — Echoes of the Unknown

## Metadata

- Challenge: choes of the Unknown
- Author: x.two
- Category: Steganography
- Difficulty: Easy
- Event: QnQSec
- Solver: foqs
- Analyst: Aurelinth
- Target: Local file `alien.wav`
- Date: 2025-10-17

---

## Executive summary

A mono 16‑bit 22.05 kHz WAV file (`alien.wav`) hides a flag rendered as visible characters in the time–frequency domain. Plotting a spectrogram reveals the plaintext string `QnQSec{h1dd3n_1n_4ud1o}` without further decoding. The challenge demonstrates basic audio steganography by drawing text in the spectrogram.

---

## Scope & preconditions

- In-scope: the provided audio file `alien.wav`.
- No accounts or credentials required.
- No network interaction; offline analysis only.
- Organizer restrictions: none relevant beyond standard rules.

---

## Recon / initial observations

- File parameters (via Python `wave`):
    - Channels: 1 (mono)
    - Sample width: 16-bit
    - Sample rate: 22,050 Hz
    - Frames: 109,861 (~4.98 s)
- These properties are typical for LSB stego or spectrogram art. Given the short duration and challenge title, a visual spectrogram was prioritized.

**Quick commands**

```bash
# Option 1: SoX/ffmpeg spectrogram (CLI)
sox alien.wav -n spectrogram -o spectro.png
# or ffmpeg
ffmpeg -i alien.wav -lavfi showspectrumpic=s=1920x1080:legend=1 spectro.png

```

**Python mini-proof (used here)**

```python
import wave, numpy as np, matplotlib.pyplot as plt
with wave.open('alien.wav','rb') as w:
    sr=w.getframerate(); n=w.getnframes()
    x=np.frombuffer(w.readframes(n), dtype=np.int16).astype(np.float32)/32768
plt.figure(figsize=(14,6))
plt.specgram(x, NFFT=2048, Fs=sr, noverlap=1024, mode='psd')
plt.title('Spectrogram — alien.wav'); plt.xlabel('Time (s)'); plt.ylabel('Frequency (Hz)')
plt.colorbar(label='Power Spectral Density')
plt.tight_layout(); plt.savefig('alien_spectrogram.png', dpi=200)

```

The rendered spectrogram shows clear Latin characters across mid frequencies spelling:

<img width="2588" height="1180" alt="image" src="https://github.com/user-attachments/assets/bcb23021-62b1-4e5d-9a8c-6e5112d3e167" />


```
QnQSec{h1dd3n_1n_4ud1o}

```

---

## Vulnerability 1 — Spectrogram text embedding (Severity: Low)

**Description:** The audio contains deliberately crafted frequency components over time to trace readable characters when visualized as a spectrogram. No cryptography or bit‑plane extraction is required; the data is visually exposed.

**Root cause:** The waveform was generated/edited such that frequency sweeps and tones align to form glyphs. Any standard spectrogram tool will reveal the content.

**Reproduction / PoC:**

1. Open `alien.wav` in Audacity or Sonic Visualiser.
2. Switch view to spectrogram; adjust window size (≈2048), overlap (≈50%), and dynamic range until text becomes crisp.
3. Read the flag directly from the image: `QnQSec{h1dd3n_1n_4ud1o}`.

**Impact:** Anyone with the file can recover the secret without special tooling or keys.

---

## Exploitation — full chain (step-by-step)

1. Inspect file parameters to confirm PCM WAV and duration.
2. Generate spectrogram via Python/Matplotlib (NFFT 2048, 50% overlap) or CLI tools.
3. Observe mid‑band text; transcribe exactly: `QnQSec{h1dd3n_1n_4ud1o}`.
4. Submit flag.

**Expected output:**

```
QnQSec{h1dd3n_1n_4ud1o}
```

---

## Artifacts

- Flag: `QnQSec{h1dd3n_1n_4ud1o}`
- Files produced: `alien_spectrogram.png` (spectrogram export)
- Notes: Python snippet above reproducible offline.

---

## Remediation recommendations

- If secrecy is intended, avoid plain spectrogram art. Consider:
    - Encrypt payload prior to embedding.
    - Use LSB steganography with error‑resilient encoding (and keys).
    - Add decoy textures/noise to hinder optical reading.
    - Vary windows/scales so plaintext isn’t legible without precise parameters.
- For challenge design variety, combine spectrogram art with a secondary decoding step (e.g., Morse in overtones or DSSS watermark).

---

## Timeline & disclosure

- 2025‑10‑17 — File received and analyzed; flag recovered via spectrogram.

---

## Appendix

- Full Python PoC included above.

---

# TIẾNG VIỆT

## Tóm tắt ngắn

File WAV mono 16‑bit 22.05 kHz chứa flag được vẽ trực tiếp trong miền thời gian–tần số. Vẽ spectrogram sẽ hiện ngay chuỗi `QnQSec{h1dd3n_1n_4ud1o}` mà không cần giải mã thêm.

---

## Phạm vi & điều kiện tiền đề

- Phạm vi: file `alien.wav` do BTC cung cấp.
- Không cần tài khoản/credential.
- Phân tích offline, không có tương tác mạng.

---

## Recon / quan sát ban đầu

- Thông số file:
    - Kênh: 1 (mono)
    - Độ rộng mẫu: 16‑bit
    - Tần số lấy mẫu: 22.05 kHz
    - Số frame: ~109,861 (≈4.98 s)
- Đây là cấu hình hay dùng cho LSB hoặc hình ảnh spectrogram; ưu tiên kiểm tra spectrogram trước.

**Lệnh nhanh**

```bash
sox alien.wav -n spectrogram -o spectro.png
# hoặc ffmpeg
ffmpeg -i alien.wav -lavfi showspectrumpic=s=1920x1080:legend=1 spectro.png

```

**PoC Python**

```python
import wave, numpy as np, matplotlib.pyplot as plt
with wave.open('alien.wav','rb') as w:
    sr=w.getframerate(); n=w.getnframes()
    x=np.frombuffer(w.readframes(n), dtype=np.int16).astype(np.float32)/32768
plt.figure(figsize=(14,6))
plt.specgram(x, NFFT=2048, Fs=sr, noverlap=1024, mode='psd')
plt.title('Spectrogram — alien.wav'); plt.xlabel('Time (s)'); plt.ylabel('Frequency (Hz)')
plt.colorbar(label='Power Spectral Density')
plt.tight_layout(); plt.savefig('alien_spectrogram.png', dpi=200)

```

Đọc trực tiếp trên spectrogram thấy rõ:

```
QnQSec{h1dd3n_1n_4ud1o}

```

---

## Lỗ hổng 1 — Ẩn chữ trong spectrogram (Mức độ: Thấp)

**Mô tả:** Tín hiệu được thiết kế để khi hiển thị spectrogram sẽ tạo thành ký tự Latin; không cần trích xuất bit hay giải mã.

**Nguyên nhân gốc rễ:** Pha/tần số được điều khiển theo thời gian để vẽ glyph; mọi công cụ spectrogram chuẩn đều nhìn thấy.

**PoC / Reproduce:**

1. Mở `alien.wav` trong Audacity/Sonic Visualiser.
2. Chọn chế độ spectrogram; chỉnh Window ≈2048, Overlap ≈50% và dynamic range.
3. Đọc flag: `QnQSec{h1dd3n_1n_4ud1o}`.

**Tác hại:** Ai có file đều phục hồi được nội dung.

---

## Chain exploit — chi tiết từng bước

1. Kiểm tra định dạng WAV/PCM và thời lượng.
2. Xuất spectrogram bằng Python hoặc CLI.
3. Quan sát và chép chính xác chuỗi chữ ở dải tần giữa.
4. Nộp flag.

**Kết quả mong đợi:** `QnQSec{h1dd3n_1n_4ud1o}`

---

## Bằng chứng & artifacts

- Flag: `QnQSec{h1dd3n_1n_4ud1o}`
- File tạo ra: `alien_spectrogram.png`

---

## Khuyến nghị sửa chữa

- Nếu muốn che giấu tốt hơn:
    - Mã hóa nội dung trước khi nhúng.
    - Dùng LSB có khóa + mã sửa lỗi.
    - Thêm nhiễu/texture đánh lạc hướng.
    - Buộc thông số hiển thị chính xác mới đọc được.
- Để tăng độ thú vị: kết hợp chữ trong spectrogram với bước giải mã thứ cấp (Morse/DTMF/phase coding).

---

## Timeline & disclosure

- 2025‑10‑17 — Nhận file và trích xuất flag qua spectrogram.

---

## Phụ lục

- Đã kèm PoC Python ở trên.
