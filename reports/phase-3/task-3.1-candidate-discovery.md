# Task 3.1–3.3 — Deterministic Candidate Discovery & Early Rejection

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 3.1, Task 3.2, Task 3.3 |
| **Title** | Source/Sink Rules, Early Rejection & Candidate Report |
| **Status** | ✅ Complete |
| **Phase** | Phase 3: Deterministic Candidate Discovery |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Phase 3 is to implement [harness/candidate_finder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/candidate_finder.py) — a deterministic candidate discovery engine that scans WebGoat Java source code for security-sensitive source/sink patterns without calling any LLM.

The module executes three micro-tasks:
1. **Task 3.1 (Source/Sink Rules)**: Scans 15 security categories for untrusted input ingestion and dangerous operations.
2. **Task 3.2 (Early Rejection)**: Filters or de-prioritizes candidates that use parameterized queries, explicit sanitization, or constant-only inputs.
3. **Task 3.3 (Candidate Report)**: Exports all candidates to machine-readable JSONL (`results/<experiment-id>/candidates.jsonl`), validated via [scripts/validate_jsonl.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/validate_jsonl.py).

---

## 2. Implementation Details

### 2.1 15 Security Rule Categories (Task 3.1)
`CandidateFinder` enforces rules across 15 categories matching `CONTEXT.md`:

| # | Category | Rule ID | Example Target Pattern |
| :--- | :--- | :--- | :--- |
| 1 | `database` | `sqli_string_concat`, `sqli_statement_execute` | SQL query string concatenation, raw `Statement.executeQuery` |
| 2 | `html_template` | `xss_raw_write`, `xss_thymeleaf_unescaped` | ServletResponse unencoded `write()`, Thymeleaf `th:utext` |
| 3 | `command_execution` | `cmd_runtime_exec` | `Runtime.getRuntime().exec()`, `ProcessBuilder` |
| 4 | `file_handling` | `file_path_traversal`, `file_zip_slip` | `new File(path + var)`, `ZipEntry.getName()` |
| 5 | `xml_parsing` | `xml_xxe_parser` | `DocumentBuilderFactory`, `SAXParserFactory` |
| 6 | `deserialization` | `deserialization_unsafe` | `ObjectInputStream.readObject()`, `XMLDecoder`, `XStream` |
| 7 | `http_client` | `ssrf_http_connection` | `URL.openStream()`, `RestTemplate`, `WebClient` |
| 8 | `redirect` | `redirect_open` | `sendRedirect()`, `RedirectView`, `redirect:` |
| 9 | `authentication` | `auth_custom_check` | `UserDetailsService`, `PasswordEncoder` |
| 10 | `authorization` | `access_control_annotation` | `@PreAuthorize`, `@Secured`, `@RolesAllowed` |
| 11 | `session` | `session_cookie_handling` | `HttpSession`, `Cookie`, CSRF token handling |
| 12 | `cryptography` | `crypto_weak_algorithm` | `MessageDigest.getInstance("MD5")`, `Cipher.getInstance("DES")` |
| 13 | `cryptography` | `crypto_hardcoded_secret` | Hardcoded password/key string assignment |
| 14 | `logging_sensitive` | `logging_sensitive` | Logging passwords or tokens (`log.info(..., password)`) |
| 15 | `reflection` | `reflection_unsafe` | `Class.forName()`, `Method.invoke()`, `newInstance()` |

### 2.2 Early Rejection Heuristics (Task 3.2)
Candidates undergo early rejection prefiltering before downstream LLM analysis:
- **Parameterized Query Filter**: SQL queries using `PreparedStatement`, `JdbcTemplate`, or positional `?` / `:param` placeholders are flagged as `is_rejected = True` with priority `low`.
- **Sanitizer Filter**: Calls containing sanitizers (`htmlEscape`, `clean`, `encode`, `ESAPI`) are marked as rejected.
- **Constant Literal Filter**: Arguments that are string literals are marked as rejected.
- **Method Authorization Filter**: Endpoint methods annotated with `@PreAuthorize` or `@Secured` are marked as low priority.

### 2.3 Candidate Output JSONL (Task 3.3)
Each candidate record is written to `results/<experiment-id>/candidates.jsonl` adhering to schema:
```json
{
  "candidate_id": "CAND-WG-0001",
  "category": "database",
  "file": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
  "line": 42,
  "symbol": "searchUser",
  "matched_rule": "sqli_string_concat",
  "snippet": "String query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";",
  "context_refs": ["src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java:42"],
  "priority": "high",
  "is_rejected": false,
  "rejection_reason": null
}
```

---

## 3. Results on WebGoat (2025.3)

Running candidate discovery on WebGoat produced:

| Metric | Count |
| :--- | :--- |
| **Total Candidates Discovered** | **166** |
| **Active Candidates (High/Medium Priority)** | **149** |
| **Rejected Candidates (Early Filtered)** | **17** |
| **Categories Detected** | **11 categories** |

### Breakdown by Category:
- `session`: 91 candidates
- `http_client`: 18 candidates
- `authentication`: 12 candidates
- `database`: 10 candidates
- `cryptography`: 10 candidates
- `file_handling`: 9 candidates
- `html_template`: 6 candidates
- `logging_sensitive`: 4 candidates
- `command_execution`: 3 candidates
- `redirect`: 2 candidates
- `xml_parsing`: 1 candidate

---

## 4. Files Created / Modified

- **[harness/candidate_finder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/candidate_finder.py)** — Deterministic candidate discovery engine (~420 lines).
- **[scripts/validate_jsonl.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/validate_jsonl.py)** — JSONL validator script for candidate and finding schema (~170 lines).
- **[tests/test_candidate_finder.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_candidate_finder.py)** — Unit test suite for candidate discovery & JSONL validation.
- **[results/exp-d-optimized/candidates.jsonl](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/exp-d-optimized/candidates.jsonl)** — Generated candidates output.
- **[reports/phase-3/task-3.1-candidate-discovery.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-3/task-3.1-candidate-discovery.md)** — Phase 3 report (this file).

---

## 5. How to Verify / Test

To run candidate discovery on WebGoat:

```bash
python3 -m harness.candidate_finder \
  --source webgoat/WebGoat-2025.3 \
  --output results \
  --experiment-id exp-d-optimized \
  --index results/symbol_index.json \
  --exclusions configs/exclusions.json
```

To validate the generated JSONL output:

```bash
python3 scripts/validate_jsonl.py results/exp-d-optimized/candidates.jsonl
```

To run unit tests:

```bash
python3 -m unittest discover -s tests -v
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Phase 3 is fully implemented. The candidate discovery engine identified 166 candidates across 11 security categories on WebGoat, applied early rejection prefiltering (17 low priority/rejected candidates), and exported valid `candidates.jsonl` matching schema requirements.
