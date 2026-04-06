# Writeup: Song Inside a Shell - Forensics (Hard)

**Category:** Forensics / Steganography
**Difficulty:** Hard
**Tools Used:** Python (`wave`, `struct`, `numpy`, `scipy`), Audacity

---

## 1. Tóm tắt thử thách (Overview)
Bài toán cung cấp một file âm thanh dạng sóng biển (`song-inside-a-shell.wav`). Nghe thoáng qua, file chỉ có tiếng sóng biển bình thường. Tuy nhiên, theo gợi ý (hoặc qua quá trình phân tích kỹ thuật giấu tin), có một đoạn âm thanh được giấu bên trong bằng kỹ thuật thao tác trên các kênh âm thanh (Stereo Channels). Mục tiêu là trích xuất âm thanh ẩn này để tìm Flag.

## 2. Phân tích & Giải thuật (Phase Cancellation)
Trong các file âm thanh Stereo (2 kênh), tiếng ồn môi trường (như tiếng sóng biển) thường được phân bổ đều ở cả hai kênh Trái (Left) và Phải (Right). Kẻ giấu tin có thể chèn một tín hiệu bí mật bằng cách làm lệch pha hoặc chèn thông tin có sự chênh lệch biên độ giữa hai kênh này.

Dựa vào đặc điểm này, ta áp dụng kỹ thuật **Phase Cancellation** (Triệt tiêu pha) bằng công thức đơn giản:
> **Hidden Signal = Left Channel - Right Channel**

Khi trừ hai kênh cho nhau, những âm thanh giống hệt nhau ở cả hai kênh (tiếng sóng biển) sẽ triệt tiêu về 0. Những âm thanh có sự khác biệt (thông điệp bị giấu) sẽ lộ diện.

## 3. Hiện thực hóa bằng Python
Để tự động hóa quá trình trích xuất, ta sử dụng Python với thư viện `wave` và `struct` để can thiệp trực tiếp vào từng byte dữ liệu của file WAV.

```python
import wave
import struct

def extract_hidden_sound(input_wav, output_wav):
    with wave.open(input_wav, 'rb') as wav_in:
        n_channels = wav_in.getnchannels()
        sampwidth = wav_in.getsampwidth()
        n_frames = wav_in.getnframes()
        framerate = wav_in.getframerate()
        raw_data = wav_in.readframes(n_frames)
        
    # Bước 1: Giải mã dữ liệu Raw (Giả định file 16-bit)
    # File âm thanh bản chất là chuỗi các con số biểu diễn biên độ sóng.
    # Ký hiệu '<' chỉ định Little-Endian, 'h' là số nguyên short 16-bit.
    fmt = f"<{n_frames * n_channels}h" 
    samples = struct.unpack(fmt, raw_data)
    
    # Bước 2: Tách kênh Stereo
    # Dữ liệu WAV Stereo xen kẽ L-R-L-R-L-R...
    # samples[0::2] lấy các phần tử chẵn (Left), samples[1::2] lấy lẻ (Right).
    left = samples[0::2]
    right = samples[1::2]
    
    # Bước 3: Kỹ thuật Subtraction (Left - Right)
    # Trừ giá trị biên độ hai kênh để triệt tiêu tiếng sóng biển.
    # Dùng hàm max/min kết hợp giới hạn (-32768 đến 32767) để tránh lỗi tràn số (Integer Overflow) của chuẩn 16-bit.
    diff = [max(min(l - r, 32767), -32768) for l, r in zip(left, right)]
    
    # Bước 4: Đóng gói và lưu file Mono mới
    with wave.open(output_wav, 'wb') as wav_out:
        wav_out.setnchannels(1) # Chuyển về Mono vì chỉ còn 1 luồng tín hiệu
        wav_out.setsampwidth(sampwidth)
        wav_out.setframerate(framerate)
        # Pack mảng số nguyên trở lại thành bytes và lưu file
        wav_out.writeframes(struct.pack(f"<{n_frames}h", *diff))
        print(f"[+] Đã trích xuất âm thanh ẩn ra file: {output_wav}")

extract_hidden_sound("song-inside-a-shell.wav", "hidden-voice.wav")
```
## 4. Xử lý hậu kỳ (Post-Processing) & Lấy Flag
Sau khi chạy script trên, file `hidden-voice.wav` chứa thông điệp nhưng âm lượng cực kỳ nhỏ và nghe rất "creepy" (như ngôn ngữ ngoài hành tinh). Điều này xảy ra do biên độ sau khi trừ (subtraction) còn lại rất thấp, và tác giả đã **đảo ngược (reverse)** âm thanh để tăng độ khó.

### Cách giải quyết triệt để bằng Audacity
Thay vì dùng code lật ngược toàn file, quá trình hậu kỳ cần được thực hiện thủ công để đảm bảo độ chính xác:

1. **Khuếch đại (Normalize):** Đưa file `hidden-voice.wav` vào phần mềm Audacity. Bôi đen toàn bộ track, sử dụng **Effect > Normalize** để kéo âm lượng lên mức nghe rõ.
2. **Lật ngược cục bộ (Reverse):** File `hidden-voice.wav` chỉ tồn tại một đoạn âm thanh duy nhất. Bôi đen chính xác khoảng thời gian và sử dụng **Effect > Reverse** để đảo ngược file.
3. **Làm chậm (Slow down):** Tác giả đã tua nhanh giọng đọc để làm méo tiếng. Quét khối đoạn âm thanh, dùng **Effect > Change Tempo** (giảm tốc độ, giữ nguyên cao độ) để giọng nói trở lại bình thường. Khoảng làm chậm khuyến nghị là 20%.

Sau các bước làm sạch và điều chỉnh nhịp độ, đoạn âm thanh lộ rõ tiếng đọc Flag. Tuy nhiên, trong quá trình nghe sẽ phát hiện ra 2 điều:

1. Có một khoảng nghỉ giữa đoạn ghi âm.
2. Sau khoảng nghỉ đó xuất hiện tiền tố `RS` tại phía sau đoạn ghi âm ?

Việc tiền tố của flag xuất hiện ở sau, không phải đầu trong đoạn âm thanh có thể liên tưởng đến việc tác giả đã cắt flag, sau đó đẩy phần đuôi lên đọc trước. 

Chính vì vậy, để nghe chính xác flag, ta cần bắt đầu nghe từ đoạn nghỉ giữa 2 đoạn, nghe đến cuối đoạn, sau đó nghe lại đầu đoạn âm thanh.

Với trình tự nghe như trên, Flag có được sẽ là `RS{listen_to_the_voice_of_the_sea}`.
