# Task 0.3 — Ghi metadata repository

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 0.3 |
| **Title** | Ghi metadata repository |
| **Status** | ✅ Complete |
| **Phase** | Phase 0: WebGoat Ingestion, Environment Verification & Scope Baseline |
| **Date** | 2026-07-21 |

---

## 1. Objective

The objective of Task 0.3 is to inspect the WebGoat source tree and produce a structured, reproducible repository metadata manifest ([results/repository_manifest.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/repository_manifest.json)). This manifest records essential architectural baselines—such as Git revision, primary language file counts, line metrics, detected frameworks, Maven module configuration, and standard source paths—without network calls.

---

## 2. Implementation Details

### 2.1 Manifest Collector Script ([scripts/collect_repository_manifest.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/collect_repository_manifest.py))
Implemented a standalone, dependency-free collector script [scripts/collect_repository_manifest.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/collect_repository_manifest.py) that:
1. Integrates with [harness/exclusions.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/exclusions.py) to exclude non-product artifacts (`.git`, `target`, binaries).
2. Traverses product source files to count file extensions (`.java`, `.html`, `.js`, `.css`, `.xml`) and calculate line metrics.
3. Parses Maven `pom.xml` descriptors as clean XML trees to identify root artifact metadata, submodules, and framework usage hints (`Spring`, `Spring Boot`, `Spring Security`, `Thymeleaf`, `WebJars`).
4. Queries local Git commands (`rev-parse`, `branch`) to attach exact commit revision hashes.

### 2.2 Repository Metadata Summary ([results/repository_manifest.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/repository_manifest.json))

| Metadata Field | Value / Description |
| :--- | :--- |
| **Repository Name** | `WebGoat-2025.3` |
| **Repository Root** | `/home/longngx04/VinSOC/week 2/AI-assisted_SAST_Bechmark/repo/webgoat/WebGoat-2025.3` |
| **Git Revision** | `5eb52db7d0cd9390946f8dcd6f39b7f58008ebcf` |
| **Git Branch** | `main` |
| **Primary Language** | `Java` (370 `.java` files) |
| **Total Source Files** | 569 files (370 `.java`, 94 `.js`, 69 `.html`, 30 `.css`, 6 `.xml`) |
| **Lines of Code** | 98,026 lines |
| **Maven Module** | `webgoat` (single jar artifact) |
| **Detected Frameworks** | Spring, Spring Boot, Spring Security, Thymeleaf, WebJars |
| **Source Paths** | `["src/main"]` |
| **Test Paths** | `["src/test"]` |
| **Build Output Paths** | `["target"]` |

---

## 3. Files Created / Modified

- **[scripts/collect_repository_manifest.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/collect_repository_manifest.py)** — Metadata collection engine script.
- **[results/repository_manifest.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/results/repository_manifest.json)** — Standardized JSON repository manifest artifact.
- **[tests/test_collect_repository_manifest.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_collect_repository_manifest.py)** — Unit test suite for manifest collector.

---

## 4. Test Results

Unit test suite in [tests/test_collect_repository_manifest.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_collect_repository_manifest.py) was executed.

- **Total Tests**: 2 tests
- **Pass Rate**: 100% (2/2 passed)

### Test Coverage Details:
1. `test_collects_source_counts_paths_and_maven_project`: Validates POM parsing, path classification (`src/main`, `src/test`), file counting, and artifact identification.
2. `test_manifest_is_json_serializable`: Confirms clean JSON serialization and warning handling when running against non-Java or temporary fixtures.

---

## 5. How to Verify / Test

To generate or update the repository manifest:

```bash
python3 scripts/collect_repository_manifest.py
```

To execute the unit test suite:

```bash
python3 -m unittest tests.test_collect_repository_manifest -v
```

Expected unit test output:
```
test_collects_source_counts_paths_and_maven_project (tests.test_collect_repository_manifest.RepositoryManifestTest.test_collects_source_counts_paths_and_maven_project) ... ok
test_manifest_is_json_serializable (tests.test_collect_repository_manifest.RepositoryManifestTest.test_manifest_is_json_serializable) ... ok

----------------------------------------------------------------------
Ran 2 tests in 0.006s

OK
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Metadata collector is operational, and [results/repository_manifest.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/repository_manifest.json) accurately reflects the structural and architectural parameters of WebGoat 2025.3.
