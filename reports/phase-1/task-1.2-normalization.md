# Task 1.2 — Quy định Normalization

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 1.2 |
| **Title** | Quy định normalization |
| **Status** | ✅ Complete |
| **Phase** | Phase 1: Core Foundation & Data Infrastructure |
| **Date** | 2026-07-21 |

---

## 1. Objective

The goal of Task 1.2 is to implement normalization rules for converting heterogeneous, messy raw outputs from LLM models and SAST tools into canonical, schema-compliant [Finding](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L30) objects. Raw model outputs frequently contain path inconsistencies, invalid line numbers, confidence out of bounds, varied CWE representations, and free-form severity terms. The normalizer provides a resilient transformation layer that sanitizes data while preserving raw evidence intact.

---

## 2. Implementation Details

The normalizer logic is implemented in [harness/normalizer.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py). It consists of specialized transformation helpers and a single main orchestrator entry point.

### 2.1 Individual Normalization Functions

1. **Path Normalization ([normalize_path](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L76))**:
   - Converts absolute paths into relative paths relative to `WEBGOAT_ROOT`.
   - Strips leading `./` and redundant `./` or `../` path segments.
   - Replaces Windows backslashes (`\`) with standard forward slashes (`/`) for cross-platform JSONL portability.
   - Strips root prefix if absolute or relative paths repeat the `WEBGOAT_ROOT` base path.

2. **CWE Format Standardization ([normalize_cwe](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L56))**:
   - Accepts raw inputs such as `'CWE-89'`, `'cwe89'`, `'89'`, or integer `89`.
   - Extracts numeric identifiers using regex `(?:CWE-?)?(\d+)`.
   - Returns standardized string format `'CWE-<number>'` (e.g. `'CWE-89'`).
   - Returns `None` for missing or non-matching string inputs.

3. **Line Number Normalization ([normalize_line](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L194))**:
   - Accepts string integers, floats, or integers.
   - Truncates floats to integer and verifies `value >= 1`.
   - Returns `None` for zero (`0`), negative values, non-numeric strings, or `None`.

4. **Confidence Score Clamping ([normalize_confidence](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L145))**:
   - Clamps numeric values strictly into `[0.0, 1.0]` using `max(0.0, min(1.0, value))`.
   - Converts numeric strings to floats.
   - Non-numeric inputs or `None` default safely to `0.0`.

5. **Severity Alias Mapping ([normalize_severity](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L161))**:
   - Maps raw free-form strings to canonical [Severity](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L10) enum members:
     - `crit`, `critical` → `Severity.CRITICAL`
     - `error`, `high` → `Severity.HIGH`
     - `warning`, `warn`, `medium` → `Severity.MEDIUM`
     - `note`, `low` → `Severity.LOW`
     - `info`, `none`, `informational` → `Severity.INFORMATIONAL`
   - Unrecognized severity strings default to `Severity.MEDIUM`.

6. **Validation Status Normalization ([normalize_validation_status](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L176))**:
   - Converts string values to [ValidationStatus](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L18).
   - Unrecognized strings default to `ValidationStatus.UNVALIDATED`.

7. **Deterministic Finding ID Generation ([generate_finding_id](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L115))**:
   - Constructs a deterministic, collision-resistant hash from key tuple:
     `(experiment_id, file, start_line, cwe, vulnerability_type)`.
   - Computes SHA-256 digest and formats as `WG-<8-hex-chars>` (e.g. `WG-f47ac10b`).
   - Ensures findings re-discovered in identical locations have stable IDs across benchmark re-runs.

### 2.2 Entry Point & Null Conventions ([normalize_raw_finding](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L213))

The entry point [normalize_raw_finding](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py#L213) orchestrates the normalization pipeline:
- **Nullable String Fields** (`cwe`, `function`, `source`, `sink`, `security_control`, `validator`, `duplicate_of`): missing values convert to `None`.
- **Required String Fields** (`vulnerability_type`, `description`, `evidence`, `attack_scenario`, `recommendation`, `notes`): missing values default to `""` (empty string).
- **Data Flow**: missing or invalid non-list data convert to `[]` (empty list); single string wraps into `[string]`.
- **Inverted Line Ranges**: automatically swaps `start_line` and `end_line` if `start_line > end_line`.
- **Raw Evidence**: raw code snippets and model outputs are preserved as-is without loss.

---

## 3. Files Created / Modified

- **[harness/normalizer.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py)** — Implementation of normalization rules, path cleanup, CWE extraction, ID generation, and main entry point.
- **[tests/test_normalizer.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_normalizer.py)** — Comprehensive test suite for all normalizer helpers and entry points.

---

## 4. Test Results

Unit tests in [tests/test_normalizer.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_normalizer.py) were executed.

- **Total Tests**: 52 test cases across 8 test classes
- **Pass Rate**: 100% (52/52 passed)

### Test Class Summary:

| Test Class | Method Count | Features Tested | Result |
| :--- | :--- | :--- | :--- |
| `TestNormalizeCWE` | 8 | Bare numbers, canonical format, empty string, non-numeric garbage, integer inputs, case-insensitivity | PASSED |
| `TestNormalizePath` | 5 | Absolute path conversion, relative passthrough, `./` stripping, forward slash enforcement | PASSED |
| `TestGenerateFindingID` | 5 | Determinism, component differentiation, prefix `WG-`, case-insensitivity, length (8 hex) | PASSED |
| `TestNormalizeConfidence` | 6 | Upper bound clamping (>1.0), lower bound clamping (<0.0), non-numeric fallback, string parsing | PASSED |
| `TestNormalizeSeverity` | 6 | Alias resolution (`warning`, `error`, `crit`), canonical passthrough, case-insensitivity, fallback | PASSED |
| `TestNormalizeValidationStatus` | 3 | Enum passthrough, string parsing, unknown fallback to `unvalidated` | PASSED |
| `TestNormalizeLine` | 7 | Positive integer parsing, zero/negative rejection to `None`, string integers, float truncation | PASSED |
| `TestNormalizeRawFinding` | 12 | End-to-end normalization, raw evidence preservation, inverted range auto-fix, null handling | PASSED |

---

## 5. How to Verify / Test

Execute the unit test suite for the normalizer module:

```bash
python3 -m unittest tests.test_normalizer -v
```

Expected unit test output (abbreviated):
```
test_case_insensitive_vuln_type (tests.test_normalizer.TestGenerateFindingID.test_case_insensitive_vuln_type) ... ok
test_deterministic (tests.test_normalizer.TestGenerateFindingID.test_deterministic) ... ok
...
test_produces_valid_finding (tests.test_normalizer.TestNormalizeRawFinding.test_produces_valid_finding) ... ok
test_round_trip_to_dict_is_valid_json (tests.test_normalizer.TestNormalizeRawFinding.test_round_trip_to_dict_is_valid_json) ... ok

----------------------------------------------------------------------
Ran 52 tests in 0.004s

OK
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: The normalization layer is fully operational and tested. All six normalization rules from the PLAN (path relativity, line positivity, confidence clamping, null convention, deterministic ID, evidence preservation) are enforced through [harness/normalizer.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/normalizer.py) with 52 passing tests.
