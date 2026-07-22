# Task 9.1–9.3 — Local Ground Truth & Benchmark Evaluation

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 9.1, Task 9.2, Task 9.3 |
| **Title** | Local Ground Truth Extraction, Schema Definition & Finding Evaluation |
| **Status** | ✅ Complete |
| **Phase** | Phase 9: Local Ground Truth |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Phase 9 is to implement [harness/ground_truth.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/ground_truth.py) and generate the local ground truth dataset [ground_truth/webgoat_ground_truth.jsonl](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/ground_truth/webgoat_ground_truth.jsonl).

Phase 9 establishes an offline reference benchmark:
1. **Task 9.1 (Ground Truth Extraction)**: Extracts ground truth entries from WebGoat lesson source code, unit tests, and solutions without calling external Internet resources.
2. **Task 9.2 (Ground Truth Schema)**: Standardizes ground truth records with lesson metadata, module, vulnerability type, CWE, relevant files, expected vulnerable behavior, validation evidence, and confidence.
3. **Task 9.3 (Finding to Ground Truth Mapping)**: Evaluates scan findings against ground truth entries based on matching relative file paths, CWE / vulnerability types, and validator decisions to calculate True Positives, False Positives, and Estimated Precision.

---

## 2. Implementation Details

### 2.1 Ground Truth Data Model (Task 9.2)
[harness/ground_truth.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/ground_truth.py) defines `GroundTruthEntry`:

```json
{
  "ground_truth_id": "GT-WG-001",
  "lesson": "SqlInjectionLesson",
  "module": "sqlinjection",
  "vulnerability_type": "SQL Injection",
  "cwe": "CWE-89",
  "relevant_files": [
    "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java"
  ],
  "expected_vulnerable_behavior": "String concatenation into raw SQL query executed against database",
  "validation_evidence": "String query = \"SELECT * FROM users WHERE name = '\" + username + \"'\";",
  "confidence": 0.95
}
```

### 2.2 Extraction & Dataset (Task 9.1)
Running `GroundTruthManager.build_webgoat_ground_truth()` against WebGoat 2025.3 source code extracted **36 local ground truth records** saved to `ground_truth/webgoat_ground_truth.jsonl`.

### 2.3 Deterministic Finding Mapping Rules (Task 9.3)
`GroundTruthManager.evaluate_findings()` classifies findings according to strict criteria:
- **True Positive (TP)**: Finding file matches `relevant_files` AND vulnerability type/CWE matches ground truth AND `validation_status` is `validated`.
- **False Positive (FP)**: Finding is `rejected` by independent validator OR file path does not match any ground truth entry in the lesson scope.
- **Uncertain**: Finding is `uncertain` or matches vulnerability class without exact line/file alignment.
- **Estimated Precision**: Calculated as `TP / (TP + FP)`.

---

## 3. Files Created / Modified

- **[harness/ground_truth.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/ground_truth.py)** — Ground truth extractor and evaluation engine (~150 lines).
- **[ground_truth/webgoat_ground_truth.jsonl](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/ground_truth/webgoat_ground_truth.jsonl)** — Extracted dataset (36 benchmark entries).
- **[tests/test_ground_truth.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_ground_truth.py)** — Unit test suite for dataset saving, loading, and precision calculation.
- **[reports/phase-9/task-9.1-ground-truth.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-9/task-9.1-ground-truth.md)** — Phase 9 report (this file).

---

## 4. Test Results

- **Total Test Suite**: 163 tests across all modules
- **Pass Rate**: 100% (163/163 passed)
- **Phase 9 Tests**: `test_save_load_entries` and `test_evaluate_findings_tp_fp_uncertain` pass 100%.

---

## 5. How to Verify / Test

To re-build or inspect the ground truth dataset:

```bash
python3 -c "from harness.ground_truth import GroundTruthManager; GroundTruthManager().build_webgoat_ground_truth('webgoat/WebGoat-2025.3')"
python3 scripts/validate_jsonl.py ground_truth/webgoat_ground_truth.jsonl
```

To run Phase 9 unit tests:

```bash
python3 -m unittest tests.test_ground_truth -v
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Phase 9 is complete. 36 local ground truth records were extracted from WebGoat source files and verified against `validate_jsonl.py`. Finding-to-ground-truth evaluation logic is fully implemented and tested.
