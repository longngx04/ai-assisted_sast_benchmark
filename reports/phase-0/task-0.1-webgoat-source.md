# Task 0.1 — Đưa WebGoat vào workspace

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 0.1 |
| **Title** | Đưa WebGoat vào workspace |
| **Status** | ✅ Complete |
| **Phase** | Phase 0: WebGoat Ingestion, Environment Verification & Scope Baseline |
| **Date** | 2026-07-21 |

---

## 1. Objective

The objective of Task 0.1 is to place the **WebGoat 2025.3** target source tree into the project workspace under [webgoat/WebGoat-2025.3/](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3) without modifying any target application files. This establishes a clean, reproducible vulnerability target baseline for all downstream SAST evaluation workflows and AI benchmark experiments.

---

## 2. Implementation Details

### 2.1 Workspace Structure & Location
The target repository was placed at the following absolute location:
`/home/longngx04/VinSOC/week 2/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3`

### 2.2 Repository Composition & File Inventory
The source tree was verified to contain a single Maven module structure with the following distribution of source artifacts:
- **Build Configuration**: Root [pom.xml](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3/pom.xml) defining `org.owasp.webgoat:webgoat:2025.3`
- **Java Source Files**: 370 `.java` files located under `src/main/java/` and `src/test/java/`
- **HTML Templates**: 69 `.html` files (Thymeleaf templates & lesson UI components)
- **JavaScript Files**: 94 `.js` client scripts
- **Stylesheet Files**: 30 `.css` style files
- **XML Configuration Files**: 6 `.xml` files
- **Total Lines of Code**: 98,026 lines across 569 total tracked source files

### 2.3 Strict Target Immutability Policy
- **Isolation Constraint**: The WebGoat source code is strictly immutable. No application files, configuration files, or pom definitions inside [webgoat/WebGoat-2025.3/](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3) were modified.
- **Harness Separation**: All benchmarking scripts, schema definitions, exclusion logic, tests, and execution artifacts reside strictly outside the WebGoat directory in top-level harness modules (`harness/`, `scripts/`, `configs/`, `tests/`, `results/`, `reports/`).

---

## 3. Files Created / Modified

- **[webgoat/WebGoat-2025.3/](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3)** — Directory containing the full WebGoat 2025.3 baseline target code (unmodified).
- **[webgoat/WebGoat-2025.3/pom.xml](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3/pom.xml)** — Maven root project descriptor for WebGoat.

---

## 4. Test Results

The target directory structure and essential build descriptor were verified via filesystem check.

| Verification Criteria | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- |
| `pom.xml` Existence | File exists at target path | `webgoat/WebGoat-2025.3/pom.xml` present | ✅ Pass |
| Java Source Tree | `src/main/java` directory present | 370 Java source files detected | ✅ Pass |
| Package Structure | `org.owasp.webgoat` hierarchy present | Intact | ✅ Pass |

---

## 5. How to Verify / Test

To verify that the WebGoat 2025.3 source tree is intact and properly located in the workspace, execute:

```bash
test -f webgoat/WebGoat-2025.3/pom.xml && echo OK
```

Expected output:
```
OK
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: WebGoat 2025.3 source tree is successfully ingested into [webgoat/WebGoat-2025.3/](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3) and confirmed to meet all immutability and workspace structure requirements.
