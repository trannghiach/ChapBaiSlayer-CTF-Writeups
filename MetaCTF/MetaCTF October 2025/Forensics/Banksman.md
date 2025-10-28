In this challenge, we receive a PDF file and need to extract something hidden inside it. First, let’s use the `pdfid` command to scan the file **report.pdf**. Command:
```bash
pdfid report.pdf
```
Result:
<img width="743" height="466" alt="image" src="https://github.com/user-attachments/assets/1f090c50-e58a-4a1a-96a2-a8190dbf6b06" />

We can see that there is an object containing the keyword `/JS` or `/JavaScript`, which indicates a malicious payload inserted into the file. We use [pdf-parser](https://blog.didierstevens.com/programs/pdf-tools/) to extract this object. Command:
```bash
python pdf-parser.py --search JS report.pdf > JS-report.txt
```

Then we use the Python script below to decode the base64-encoded object and inspect the JavaScript injected into the PDF.
Code:
```python
import re
def extract_js_hex_to_ascii(pdf_text, output_file="decoded_output.txt"):
    pattern = re.compile(r"/JS\s*<([0-9A-Fa-f\s]+)>", re.MULTILINE)
    matches = pattern.findall(pdf_text)

    if not matches:
        print("No /JS <...> found.")
        return

    with open(output_file, "w", encoding="utf-8") as output:
        for i, hex_data in enumerate(matches, 1):
            cleaned_hex = re.sub(r"\s+", "", hex_data)
            try:
                decoded = bytes.fromhex(cleaned_hex).decode('latin-1', errors='replace')
            except UnicodeDecodeError:
                decoded = bytes.fromhex(cleaned_hex).decode('utf-16be', errors='replace')

            output.write(f"\n--- Block {i} ---\n{decoded}\n---------------\n")
            print(f"Decoded block {i}")

    print(f"Done! Output saved to: {output_file}")

with open("JavaScript-report.txt", "rb") as f:
    content = f.read().decode('latin-1', errors='ignore')

extract_js_hex_to_ascii(content)
```

The decoded JavaScript code:
```JS
function setversion() {
}
function debug(s) {}
function base64ToStream(b) {
	var enc = new ActiveXObject("System.Text.ASCIIEncoding");
	var length = enc.GetByteCount_2(b);
	var ba = enc.GetBytes_4(b);
	var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
	ba = transform.TransformFinalBlock(ba, 0, length);
	var ms = new ActiveXObject("System.IO.MemoryStream");
	ms.Write(ba, 0, (length / 4) * 3);
	ms.Position = 0;
	return ms;
}

var serialized_obj = "..."

var entry_class = 'TestClass';

try {
	setversion();
	var stm = base64ToStream(serialized_obj);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}
```

We extract the variable `var serialized_obj` into a .bin file and use the strings and grep commands to retrieve the flag. Command:
```bash
strings -e l decoded-base64.bin | grep "CTF{"
```
Flag:
```
MetaCTF{I_4m_n0t_@_m1n3r_1_@m_a_b4nk5m4n}
```
