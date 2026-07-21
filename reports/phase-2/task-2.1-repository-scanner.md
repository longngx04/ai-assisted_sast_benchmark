# Task 2.1 — Repository Scanner

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 2.1 |
| **Title** | Repository scanner |
| **Status** | ✅ Complete |
| **Phase** | Phase 2: Repository Reconnaissance & Indexing |
| **Date** | 2026-07-21 |

---

## 1. Objective

The objective of Task 2.1 is to implement [harness/repository.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/repository.py) — a purely deterministic (no LLM calls) repository scanner that performs full structural reconnaissance of the WebGoat source tree. The scanner identifies Maven modules, lesson packages, Spring components, REST endpoints, and security-relevant code patterns, producing machine-readable (`reconnaissance.json`) and human-readable (`architecture_map.md`) outputs for downstream analysis prompts and agents.

---

## 2. Implementation Details

### 2.1 Data Models
Created [harness/repository.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/repository.py) (~530 lines) with the following structured dataclasses:

| Dataclass | Purpose |
| :--- | :--- |
| `EndpointInfo` | REST endpoint annotations, HTTP methods, URL paths, and line positions |
| `ComponentInfo` | Spring-annotated classes with kind, class name, file, line, and package |
| `SecurityPattern` | Matched security-sensitive code snippets categorized by security theme |
| `LessonModule` | WebGoat lesson module packages under `org.owasp.webgoat.lessons.*` |
| `ReconnaissanceResult` | Top-level aggregation of all scan outputs including metadata and summary counts |

### 2.2 RepositoryScanner Class Methods

| Method | Responsibility |
| :--- | :--- |
| `_collect_java_files()` | Recursively walks source tree, respects [ExclusionPolicy](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/exclusions.py#L23) rules |
| `_find_maven_modules()` | Parses `pom.xml`, strips `<parent>` block to extract project's own `artifactId` |
| `_find_lesson_modules()` | Identifies lesson packages under `org.owasp.webgoat.lessons.*` |
| `_find_components()` | Detects `@RestController`, `@Controller`, `@Service`, `@Repository`, `@Configuration`, `@Component` |
| `_find_endpoints()` | Extracts REST endpoints from mapping annotations with class-level base path resolution |
| `_find_security_patterns()` | Regex-based detection across 15 security categories |
| `_git_info()` | Captures Git revision/branch from `.git` directory or `git` CLI fallback |
| `save()` | Exports `reconnaissance.json` and `architecture_map.md` |
| `_render_architecture_map()` | Generates markdown tables for lessons, components, endpoints, and security patterns |

### 2.3 Security Pattern Categories (15)
Regex rules cover the full vulnerability surface specified in `CONTEXT.md`:

| # | Category | Example Patterns |
| :--- | :--- | :--- |
| 1 | `database` | JDBC/Statement, SQL string concat, JPA native query, JdbcTemplate |
| 2 | `deserialization` | ObjectInputStream, XMLDecoder, XStream, Serializable |
| 3 | `command_execution` | Runtime.exec, ProcessBuilder |
| 4 | `file_handling` | File I/O, MultipartFile, Path traversal risk, ZipEntry |
| 5 | `xml_parsing` | SAXParser, DocumentBuilder, XMLReader, TransformerFactory |
| 6 | `authentication` | UserDetailsService, PasswordEncoder, AuthenticationManager |
| 7 | `authorization` | @PreAuthorize, @Secured, hasRole, requestMatchers |
| 8 | `session` | HttpSession, Cookie, CSRF config |
| 9 | `cryptography` | MessageDigest, Cipher, SecureRandom, Hardcoded key/secret |
| 10 | `redirect` | sendRedirect, redirect:, forward:, RedirectView |
| 11 | `template_rendering` | Thymeleaf, ModelAndView |
| 12 | `http_client` | URLConnection, RestTemplate, WebClient |
| 13 | `jwt` | JWT parsing, Bearer/Authorization token |
| 14 | `logging_sensitive` | Log injection risk |
| 15 | `reflection` | Class.forName, Method.invoke, newInstance |

### 2.4 Scan Results (WebGoat 2025.3)

| Metric | Count |
| :--- | :--- |
| Java files scanned | **370** |
| Files excluded | **1** |
| Maven modules | **1** (`webgoat`) |
| Lesson modules | **30** |
| Spring components | **183** |
| REST endpoints | **189** |
| Security patterns | **500** |

**Lesson modules detected** (30): `authbypass`, `bypassrestrictions`, `challenges`, `chromedevtools`, `cia`, `clientsidefiltering`, `cryptography`, `csrf`, `deserialization`, `hijacksession`, `htmltampering`, `httpbasics`, `httpproxies`, `idor`, `insecurelogin`, `jwt`, `lessontemplate`, `logging`, `missingac`, `passwordreset`, `pathtraversal`, `securepasswords`, `spoofcookie`, `sqlinjection`, `ssrf`, `vulnerablecomponents`, `webgoatintroduction`, `webwolfintroduction`, `xss`, `xxe`

### 2.5 Key Design Decisions

1. **Regex-Based Analysis over AST Parsers**: Avoids heavy external native dependencies (e.g. `tree-sitter`), delivering fast, self-contained reconnaissance suitable for bootstrap phases.
2. **15 Security Pattern Categories**: Mapped explicitly to the target vulnerability classes specified in `CONTEXT.md`.
3. **ExclusionPolicy Integration**: Reuses existing exclusion rules from Task 0.4 ([configs/exclusions.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/configs/exclusions.json)).
4. **Git CLI Fallback**: Ensures reliable revision detection when WebGoat source is tracked within a larger parent repository.
5. **Deterministic Execution**: Pure Python logic without non-deterministic LLM calls ensures 100% reproducible baseline outputs.
6. **Architecture Map Markdown**: Compact format optimizes downstream context sizes and token efficiency for future LLM analysis steps.

---

## 3. Files Created / Modified

- **[harness/repository.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/repository.py)** — Main scanner implementation (~530 lines).
- **[tests/test_repository.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_repository.py)** — Integration test suite (17 tests across 2 classes).
- **[results/reconnaissance.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/reconnaissance.json)** — Machine-readable full scan results output.
- **[results/architecture_map.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/architecture_map.md)** — Human-readable architecture summary for downstream prompts.

---

## 4. Test Results

Unit and integration tests in [tests/test_repository.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_repository.py) were executed.

- **Total Tests**: 17 tests across 2 test classes
- **Pass Rate**: 100% (17/17 passed)

### Test Coverage Details:

| Test Class | Method Count | Features Tested |
| :--- | :--- | :--- |
| `TestRepositoryScanner` | 15 | File scanning, Maven modules, lesson modules (6 expected), controllers, services, configurations, endpoints, database/deserialization/file_handling/session/crypto patterns, exclusion enforcement, JSON serializability, git info, summary population |
| `TestSaveOutput` | 2 | Output file creation, JSON validity, markdown section verification |

---

## 5. How to Verify / Test

To run the scanner directly against the WebGoat codebase:

```bash
python3 -m harness.repository --source webgoat/WebGoat-2025.3 --output results --exclusions configs/exclusions.json
```

To run the unit and integration test suite:

```bash
python3 -m unittest tests.test_repository -v
```

Expected unit test output:
```
test_excludes_target_directory (tests.test_repository.TestRepositoryScanner.test_excludes_target_directory) ... ok
test_finds_configurations (tests.test_repository.TestRepositoryScanner.test_finds_configurations) ... ok
test_finds_controllers (tests.test_repository.TestRepositoryScanner.test_finds_controllers) ... ok
test_finds_cryptography_patterns (tests.test_repository.TestRepositoryScanner.test_finds_cryptography_patterns) ... ok
test_finds_database_patterns (tests.test_repository.TestRepositoryScanner.test_finds_database_patterns) ... ok
test_finds_deserialization_patterns (tests.test_repository.TestRepositoryScanner.test_finds_deserialization_patterns) ... ok
test_finds_endpoints (tests.test_repository.TestRepositoryScanner.test_finds_endpoints) ... ok
test_finds_file_handling_patterns (tests.test_repository.TestRepositoryScanner.test_finds_file_handling_patterns) ... ok
test_finds_lesson_modules (tests.test_repository.TestRepositoryScanner.test_finds_lesson_modules) ... ok
test_finds_maven_modules (tests.test_repository.TestRepositoryScanner.test_finds_maven_modules) ... ok
test_finds_services (tests.test_repository.TestRepositoryScanner.test_finds_services) ... ok
test_finds_session_patterns (tests.test_repository.TestRepositoryScanner.test_finds_session_patterns) ... ok
test_git_info_present (tests.test_repository.TestRepositoryScanner.test_git_info_present) ... ok
test_result_is_json_serializable (tests.test_repository.TestRepositoryScanner.test_result_is_json_serializable) ... ok
test_scans_java_files (tests.test_repository.TestRepositoryScanner.test_scans_java_files) ... ok
test_summary_populated (tests.test_repository.TestRepositoryScanner.test_summary_populated) ... ok
test_save_creates_files (tests.test_repository.TestSaveOutput.test_save_creates_files) ... ok

----------------------------------------------------------------------
Ran 17 tests in 1.075s

OK
```

To inspect generated outputs:

```bash
cat results/reconnaissance.json | python3 -m json.tool | head -50
cat results/architecture_map.md
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: The repository reconnaissance scanner is fully operational, producing both machine-readable and human-readable maps of WebGoat's architecture. It detected 370 Java files, 30 lesson modules, 183 Spring components, 189 REST endpoints, and 500 security-relevant patterns across 15 categories — all without any LLM calls or external dependencies. The scanner integrates cleanly with the exclusion policy (Task 0.4) and repository manifest (Task 0.3).
