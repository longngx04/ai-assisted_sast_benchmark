# Task 6.1–6.3 — Investigation & Validation Workflow

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 6.1, Task 6.2, Task 6.3 |
| **Title** | Investigation Agent, Independent Validator & Validation Output Partitioning |
| **Status** | ✅ Complete |
| **Phase** | Phase 6: Investigation and Validation Workflow |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Phase 6 is to implement [harness/investigator.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/investigator.py) and [harness/validator.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/validator.py).

Phase 6 connects candidate discovery to LLM vulnerability analysis:
1. **Task 6.1 (Investigation Agent)**: Coordinates context retrieval, vulnerability-specific prompt selection, LLM analysis, and finding schema normalization (`normalize_raw_finding`).
2. **Task 6.2 (Independent Validator)**: Re-evaluates findings against caller/callee context, security assumptions, and attack scenarios using an independent validation prompt.
3. **Task 6.3 (Validation Output Partitioning)**: Partitions findings into three output JSONL files (`validated_findings.jsonl`, `rejected_findings.jsonl`, `uncertain_findings.jsonl`).

---

## 2. Implementation Details

### 2.1 Investigation Workflow (Task 6.1)
[harness/investigator.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/investigator.py) implements `InvestigationAgent`:

```text
candidate
 → context retrieval (ContextBuilder)
 → vulnerability-specific prompt selection (prompts/<cat>.md)
 → LLM invocation (ModelClient)
 → schema normalization (normalize_raw_finding)
 → unvalidated finding
```

Features:
- **Prefilter Respect**: Automatically skips candidates marked `is_rejected = True` by Phase 3.2.
- **Robust Error Handling**: If model output is malformed or unparseable, logs a warning and yields 0 findings rather than manufacturing dummy data.

### 2.2 Independent Validator Engine (Task 6.2)
[harness/validator.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/validator.py) implements `IndependentValidator`:
- Constructs `ValidationContext` containing finding metadata, code context, caller/callee details, and attack scenario.
- Invocates `ModelClient` with [prompts/validation.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/prompts/validation.md).
- Updates `Finding` fields: `validation_status`, `validator`, `validator_confidence`, and appending validator rationale to `notes`.

### 2.3 Partitioning Output (Task 6.3)
Findings are partitioned by `validation_status` and written to:
- `results/<experiment-id>/validated_findings.jsonl`
- `results/<experiment-id>/rejected_findings.jsonl`
- `results/<experiment-id>/uncertain_findings.jsonl`

---

## 3. Files Created / Modified

- **[harness/investigator.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/investigator.py)** — Investigation agent implementation (~175 lines).
- **[harness/validator.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/validator.py)** — Independent validator and JSONL partitioning engine (~200 lines).
- **[tests/test_investigation_and_validation.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_investigation_and_validation.py)** — Unit test suite covering investigation pipeline, independent validation, and output partitioning.
- **[reports/phase-6/task-6.1-investigation-and-validation.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-6/task-6.1-investigation-and-validation.md)** — Phase 6 report (this file).

---

## 4. Test Results

- **Total Test Suite**: 157 tests across all modules
- **Pass Rate**: 100% (157/157 passed)
- **Phase 6 Tests**: `test_investigation_agent_mock` and `test_validator_and_partitioning` pass 100%.

---

## 5. How to Verify / Test

To run Phase 6 unit tests:

```bash
python3 -m unittest tests.test_investigation_and_validation -v
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Phase 6 is complete. `InvestigationAgent` and `IndependentValidator` provide end-to-end orchestration from candidate discovery to schema normalization, independent validation, and status-partitioned output persistence.
