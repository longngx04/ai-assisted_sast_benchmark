# Task 8.1–8.3 — Converter & Validators

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 8.1, Task 8.2, Task 8.3 |
| **Title** | SARIF/JSON Converter, JSONL Validator & Findings Validator CLI |
| **Status** | ✅ Complete |
| **Phase** | Phase 8: Converter and Validators |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Phase 8 is to implement [scripts/convert_to_jsonl.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/convert_to_jsonl.py), [scripts/validate_jsonl.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/validate_jsonl.py), [scripts/validate_findings.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/validate_findings.py), and [scripts/deduplicate_findings.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/deduplicate_findings.py).

These scripts form the validation and conversion CLI toolkit for the benchmark harness:
1. **Task 8.1 (SARIF/JSON Converter)**: Converts third-party SARIF 2.1.0 and JSON SAST reports into canonical benchmark `Finding` JSONL lines.
2. **Task 8.2 (JSONL Format Validator)**: Validates JSON syntax, schema rules, line numbers, enum boundaries, relative file paths, and absence of JSON array outer wrapping.
3. **Task 8.3 (Deduplicate CLI)**: Standalone command-line interface for running finding deduplication.

---

## 2. Implementation Details

### 2.1 SARIF / JSON Converter (`convert_to_jsonl.py`)
CLI interface:
```bash
python3 scripts/convert_to_jsonl.py \
  --input results/raw/results.sarif \
  --format sarif \
  --output results/exp-c-indexed/findings.jsonl \
  --experiment-id exp-c-indexed
```

Converts SARIF 2.1.0 rules and results:
- Maps SARIF `level` (`error` -> High, `warning` -> Medium, `note` -> Low).
- Maps rule IDs and CWE tags from `properties.tags`.
- Extracts `physicalLocation.artifactLocation.uri` and `region.startLine`.
- Normalizes path, line numbers, severity, and CWE via `harness/normalizer.py`.

### 2.2 JSONL & Findings Schema Validators (`validate_jsonl.py` & `validate_findings.py`)
CLI interface:
```bash
python3 scripts/validate_jsonl.py results/exp-d-optimized/candidates.jsonl
python3 scripts/validate_findings.py results/exp-d-optimized/findings.jsonl
```

Verifies:
- Each line is a single JSON object (rejects outer `[` array wrapping).
- Required fields are present.
- Confidence is in range `[0, 1]`.
- Severities match enum: `critical`, `high`, `medium`, `low`, `informational`.
- Validation status matches enum: `validated`, `rejected`, `uncertain`, `unvalidated`.
- File paths are relative to repository root.
- Candidate and finding IDs are unique.

---

## 3. Files Created / Modified

- **[scripts/convert_to_jsonl.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/convert_to_jsonl.py)** — Converter script for SARIF 2.1.0 and JSON reports (~120 lines).
- **[scripts/validate_jsonl.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/validate_jsonl.py)** — General JSONL format and schema validator (~170 lines).
- **[scripts/validate_findings.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/validate_findings.py)** — Finding schema contract validator (~60 lines).
- **[scripts/deduplicate_findings.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/scripts/deduplicate_findings.py)** — Standalone dedup CLI (~50 lines).
- **[tests/test_converter_and_validators.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_converter_and_validators.py)** — Unit test suite.
- **[reports/phase-8/task-8.1-converter-and-validators.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-8/task-8.1-converter-and-validators.md)** — Phase 8 report (this file).

---

## 4. Test Results

- **Total Test Suite**: 161 tests across all modules
- **Pass Rate**: 100% (161/161 passed)
- **Phase 8 Tests**: `test_sarif_conversion` and `test_validate_findings_file` pass 100%.

---

## 5. How to Verify / Test

To test SARIF conversion:

```bash
python3 scripts/convert_to_jsonl.py --input sample.sarif --format sarif --output findings.jsonl
```

To validate JSONL outputs:

```bash
python3 scripts/validate_jsonl.py results/exp-d-optimized/findings.jsonl
python3 scripts/validate_findings.py results/exp-d-optimized/findings.jsonl
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Phase 8 is complete. The conversion and validation CLI scripts allow importing external SARIF/JSON findings and strictly enforcing JSONL schema contracts across all pipeline outputs.
