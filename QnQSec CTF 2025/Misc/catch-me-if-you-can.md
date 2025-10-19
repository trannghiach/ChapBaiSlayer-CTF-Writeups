# QnQSec CTF 2025 — Catch me if you can
- **Category:** Forensics / Steganography
- **Tags:** GIF analysis, QR code, Base64 decoding, Python scripting, Automated analysis
- Author: x.two

---

## 1. Challenge Summary

The "Catch me if you can" challenge from QnQSec CTF 2025 involved locating a hidden flag within a dynamic GIF file, `qrs.gif`. The challenge description, "You can look all day, but can you catch it before it slips away?", strongly hinted at a fleeting presence of the flag, requiring rapid or automated detection.

![qrs](https://github.com/user-attachments/assets/40305c0d-60d3-4215-a462-b41f50f9a94a)

---

## 2. Initial Analysis & Reconnaissance

1. **`qrs.gif` Examination:** Given the dynamic nature of a GIF and the "slips away" hint, manual frame-by-frame analysis for visual anomalies was deemed impractical. This immediately suggested the need for an automated approach.
2. **Provided QR Code Script:** The provided Python script, utilizing `Pillow` for GIF frame iteration and `OpenCV`'s `QRCodeDetector`, confirmed that the flag was likely encoded within QR codes embedded in individual GIF frames. This script's output, `qr_decode_results_fast.csv`, containing Base64 strings, indicated a multi-layered obfuscation.

---

## 3. The Vulnerability

The core vulnerability lay in the transient appearance of a QR code containing the Base64-encoded flag within a specific frame of the `qrs.gif`. This short duration prevented manual detection, necessitating an automated process to systematically scan each frame, detect the QR code, and then decode its contents.

---

## 4. Exploitation Steps

1. **Extracting and Decoding QR Codes from GIF:** The initial Python script was executed against `qrs.gif`. This script meticulously processed each frame, converting it to an OpenCV-compatible format, and then applying `cv2.QRCodeDetector` to identify and decode any embedded QR codes. The raw Base64 strings, along with their frame index, were then logged into `qr_decode_results_fast.csv`.
2. **Base64 Decoding of CSV Contents:** The `decoded` column in `qr_decode_results_fast.csv` contained Base64-encoded strings. To reveal their true content, my Python script (provided in our previous interaction) was used to read this CSV file, perform a Base64 decode operation on each string, and print the results.
3. **Flag Identification:** Upon reviewing the output from the Base64 decoding script, the flag was distinctly identified within Frame 196, contrasting with the numerous decoy messages.

---

## 5. Final Exploit / Payload

The relevant decoded lines from the `qr_decode_results_fast.csv` were:

```swift
[-] Frame 195: Decoded successfully: search elsewhere
[+] Frame 196: Decoded successfully (POTENTIAL FLAG!): QnQSec{C4TCH_M3_1F_Y0U_C4N}
[-] Frame 197: Decoded successfully: decoy_payload_3
[-] Frame 198: Decoded successfully: maybe next time
```

**Flag:** `QnQSec{C4TCH_M3_1F_Y0U_C4N}`

---

## 6. Key Takeaways & Lessons Learned

- **Automated Multimedia Analysis:** Challenges involving dynamic multimedia formats like GIFs often require scripting to systematically analyze individual components (frames) that are otherwise imperceptible to human observation. This highlights the importance of tools like `Pillow` and `OpenCV` in forensic contexts.
- **Layered Obfuscation:** The flag was hidden behind two layers of obfuscation: first, embedded within a QR code in a specific GIF frame, and second, Base64-encoded. A methodical approach to deconstructing each layer is crucial.
- **Leveraging Challenge Hints:** The hint "slips away" was a critical meta-clue, guiding towards the necessity of automated, rapid analysis to 'catch' the transient flag.
