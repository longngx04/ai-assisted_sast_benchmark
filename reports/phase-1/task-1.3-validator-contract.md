# Task 1.3 — Định nghĩa Validator Contract

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 1.3 |
| **Title** | Định nghĩa validator contract |
| **Status** | ✅ Complete |
| **Phase** | Phase 1: Core Foundation & Data Infrastructure |
| **Date** | 2026-07-21 |

---

## 1. Objective

The goal of Task 1.3 is to establish the formal data contract and input/output payload specification for validator components. The independent validator phase evaluates candidate findings generated during initial scan passes, determining whether a finding is verified (`validated`), rejected as a false positive (`rejected`), or ambiguous (`uncertain`). 

This contract ensures that validator responses follow a strict JSON schema, and that validator engines receive rich contextual information (code context, call graph info, security assumptions, attack scenarios) rather than evaluating finding descriptions in isolation.

---

## 2. Implementation Details

### 2.1 Validator Output Schema & Dataclass ([harness/schemas.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L169))

Implemented the `ValidationResult` dataclass and `ValidationDecision` Enum in [harness/schemas.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L117):

1. **`ValidationDecision` Enum**: String-backed enum defining valid validation decisions:
   - `validated` (true positive vulnerability confirmed)
   - `rejected` (false positive or non-vulnerable path confirmed)
   - `uncertain` (insufficient evidence to reach a conclusive decision)

2. **`ValidationResult` Dataclass**: Frozen slotted dataclass with strict validation checks:
   - `status`: `ValidationDecision` enum member
   - `confidence`: `float` in `[0.0, 1.0]`
   - `reason`: `str` explanation of the decision
   - `missing_evidence`: `list[str]` listing unverified symbols or missing context steps
   - `recommended_manual_check`: `str` guidance for human analyst review

3. **Validation Integration (`apply_to_finding`)**:
   - `apply_to_finding(finding: Finding, validator_name: str) -> Finding`: Transforms a candidate `Finding` into an updated `Finding` instance with updated `validation_status`, `validator`, `validator_confidence`, and annotated notes.

### 2.2 Validator Input Context Payload ([harness/schemas.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L123))

Implemented `ValidationContext` dataclass in [harness/schemas.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L123) to enforce that validator engines receive complete contextual evidence:

- `finding`: Full [Finding](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py#L30) instance
- `code_context`: Relevant source code lines around source and sink
- `caller_callee_info`: List of caller/callee signatures and call graph traces
- `security_assumptions`: List of security controls and configuration invariants
- `attack_scenario`: Detailed exploit scenario description

### 2.3 JSON Schema Definitions

1. **[schemas/validation_result.schema.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/schemas/validation_result.schema.json)**: Draft 2020-12 schema enforcing `additionalProperties: false`, required fields (`status`, `confidence`, `reason`, `missing_evidence`, `recommended_manual_check`), and probability boundaries.
2. **[schemas/validation_context.schema.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/schemas/validation_context.schema.json)**: Draft 2020-12 schema defining the input payload layout and referencing `finding.schema.json`.

---

## 3. Files Created / Modified

- **[harness/schemas.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py)** — Extended with `ValidationDecision`, `ValidationContext`, `ValidationResult`, and `apply_to_finding()` logic.
- **[schemas/validation_result.schema.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/schemas/validation_result.schema.json)** — Draft 2020-12 JSON Schema for validator results.
- **[schemas/validation_context.schema.json](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/schemas/validation_context.schema.json)** — Draft 2020-12 JSON Schema for validator input context.
- **[tests/test_validator_contract.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_validator_contract.py)** — Unit test suite verifying contract validation, serialization, and JSON schema alignment.
- **[reports/phase-1/task-1.3-validator-contract.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-1/task-1.3-validator-contract.md)** — Updated technical task report.

---

## 4. Test Results

Unit tests in [tests/test_validator_contract.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_validator_contract.py) were executed.

- **Total Tests**: 7 test methods
- **Pass Rate**: 100% (7/7 passed)

### Test Coverage Details:

| Test Method | Description | Result |
| :--- | :--- | :--- |
| `test_result_round_trip_preserves_contract` | Verifies full `from_dict()` / `to_dict()` round-trip serialization for `ValidationResult` | PASSED |
| `test_result_rejects_invalid_status` | Confirms rejection of invalid decisions (e.g. `unvalidated` is not a valid output status) | PASSED |
| `test_result_rejects_invalid_confidence` | Validates rejection of confidence values out of bounds (`>1.0` or `<0.0`) | PASSED |
| `test_result_apply_to_finding` | Tests updating a candidate `Finding` object with validator decisions and notes | PASSED |
| `test_context_round_trip_preserves_contract` | Verifies full `from_dict()` / `to_dict()` round-trip serialization for `ValidationContext` | PASSED |
| `test_context_rejects_invalid_types` | Verifies type enforcement for context payload attributes | PASSED |
| `test_json_schemas_aligned_with_python_enums` | Validates exact alignment between Python `ValidationDecision` enums and JSON Schema arrays | PASSED |

---

## 5. How to Verify / Test

Run the Python unit test suite for the validator contract:

```bash
python3 -m unittest tests.test_validator_contract -v
```

Expected unit test output:
```
test_context_rejects_invalid_types (tests.test_validator_contract.ValidatorContractTest.test_context_rejects_invalid_types) ... ok
test_context_round_trip_preserves_contract (tests.test_validator_contract.ValidatorContractTest.test_context_round_trip_preserves_contract) ... ok
test_json_schemas_aligned_with_python_enums (tests.test_validator_contract.ValidatorContractTest.test_json_schemas_aligned_with_python_enums) ... ok
test_result_apply_to_finding (tests.test_validator_contract.ValidatorContractTest.test_result_apply_to_finding) ... ok
test_result_rejects_invalid_confidence (tests.test_validator_contract.ValidatorContractTest.test_result_rejects_invalid_confidence) ... ok
test_result_rejects_invalid_status (tests.test_validator_contract.ValidatorContractTest.test_result_rejects_invalid_status) ... ok
test_result_round_trip_preserves_contract (tests.test_validator_contract.ValidatorContractTest.test_result_round_trip_preserves_contract) ... ok

----------------------------------------------------------------------
Ran 7 tests in 0.002s

OK
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: The validator contract for Task 1.3 is fully defined, implemented, and tested. The `ValidationResult` and `ValidationContext` dataclasses in [harness/schemas.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/schemas.py) together with JSON schemas in [schemas/](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/schemas) establish a clear contract for independent validation workflows.
