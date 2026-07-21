# Task 0.2 — Kiểm tra runtime

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 0.2 |
| **Title** | Kiểm tra runtime |
| **Status** | ✅ Complete |
| **Phase** | Phase 0: WebGoat Ingestion, Environment Verification & Scope Baseline |
| **Date** | 2026-07-21 |

---

## 1. Objective

The objective of Task 0.2 is to inspect and document all mandatory local runtime toolchains (Python, OpenJDK, Apache Maven, and Git) and verify offline build capability for WebGoat (`mvn -o -DskipTests compile`). Diagnostic results are recorded into [results/environment.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/environment.json) to guarantee reproducible benchmark execution environment baselines.

---

## 2. Implementation Details

### 2.1 Diagnostic Collector Script ([scripts/check_environment.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/check_environment.py))
Implemented a dedicated Python CLI tool [scripts/check_environment.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/check_environment.py) that:
1. Queries the operating system platform details via `platform.platform()`.
2. Inspects installed tool binaries and captures clean version outputs, exit codes, and invocation durations.
3. Invokes an offline Maven build check (`mvn -o -DskipTests compile`) against the target WebGoat source root to confirm local dependency caching.
4. Generates structured JSON output conforming to `schema_version: "1.0"`.

### 2.2 Verified Toolchain Versions

| Tool | Version / Details | Status | Output Summary |
| :--- | :--- | :--- | :--- |
| **Python** | `3.12.3` | ✅ Available | `Python 3.12.3` |
| **Java** | `21.0.11` | ✅ Available | `openjdk version "21.0.11" 2026-04-21` (Ubuntu OpenJDK 64-Bit Server VM) |
| **Maven** | `3.8.7` | ✅ Available | `Apache Maven 3.8.7` (Maven home: `/usr/share/maven`) |
| **Git** | `2.43.0` | ✅ Available | `git version 2.43.0` |

### 2.3 Offline Build Verification
- **Command Executed**: `mvn -o -DskipTests compile`
- **Network Constraint Policy**: Offline (`-o` flag enabled, zero remote repository network calls).
- **Execution Result**: `BUILD SUCCESS`
- **Duration**: `1.353s` (total command runtime: `2.128s`)
- **Build Output Summary**: Log4j ban rules passed, resources copied (642 files to `target/classes`), container ports reserved, java compilation verified up-to-date.

---

## 3. Files Created / Modified

- **[scripts/check_environment.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/check_environment.py)** — CLI script for runtime toolchain inspection and offline build validation.
- **[results/environment.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/environment.json)** — Output artifact storing JSON runtime state metadata.
- **[tests/test_check_environment.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_check_environment.py)** — Unit test suite for environment diagnostic logic.

---

## 4. Test Results

Unit test suite in [tests/test_check_environment.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_check_environment.py) was executed.

- **Total Tests**: 1 test (`test_can_collect_versions_without_build`)
- **Pass Rate**: 100% (1/1 passed)

### Test Verification Details:
1. `test_can_collect_versions_without_build`: Validates tool detection, network policy formatting (`offline; Maven invoked with -o`), and JSON payload structure when build flag is disabled.

---

## 5. How to Verify / Test

To run the environment inspection script manually:

```bash
python3 scripts/check_environment.py
```

To run the automated unit test suite:

```bash
python3 -m unittest tests.test_check_environment -v
```

Expected unit test output:
```
test_can_collect_versions_without_build (tests.test_check_environment.EnvironmentCheckTest.test_can_collect_versions_without_build) ... ok

----------------------------------------------------------------------
Ran 1 test in 0.005s

OK
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Local environment toolchain and offline build capability for WebGoat 2025.3 are fully verified and recorded in [results/environment.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/results/environment.json).
