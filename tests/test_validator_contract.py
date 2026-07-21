"""Tests for validator contract schemas (Micro-task 1.3)."""

import json
import unittest
from pathlib import Path

from harness.schemas import (
    Finding,
    FindingSchemaError,
    Severity,
    ValidationContext,
    ValidationDecision,
    ValidationResult,
    ValidationStatus,
)

SCHEMA_DIR = Path(__file__).parents[1] / "schemas"
RESULT_SCHEMA_PATH = SCHEMA_DIR / "validation_result.schema.json"
CONTEXT_SCHEMA_PATH = SCHEMA_DIR / "validation_context.schema.json"


def valid_finding_payload() -> dict:
    return {
        "finding_id": "WG-0001",
        "experiment_id": "exp-c-indexed",
        "tool": "custom-harness",
        "harness_version": "v1",
        "model": "gemini-2.5-flash",
        "prompt_version": "validation-v1",
        "vulnerability_type": "SQL Injection",
        "cwe": "CWE-89",
        "severity": "high",
        "confidence": 0.9,
        "file": "src/main/java/org/owasp/webgoat/lessons/sqlinjection/SqlInjectionLesson.java",
        "start_line": 42,
        "end_line": 48,
        "function": "executeSearch",
        "source": "username parameter",
        "sink": "Statement.executeQuery",
        "data_flow": ["HTTP param", "String concat", "SQL execution"],
        "description": "User input concatenated into raw query string.",
        "evidence": "String query = \"SELECT * FROM users WHERE name='\" + username + \"'\";",
        "attack_scenario": "Attacker passes admin' OR '1'='1",
        "security_control": None,
        "recommendation": "Use PreparedStatement parameter binding.",
        "validation_status": "unvalidated",
        "validator": None,
        "validator_confidence": None,
        "duplicate_of": None,
        "notes": "",
    }


def valid_result_payload() -> dict:
    return {
        "status": "validated",
        "confidence": 0.95,
        "reason": "Data flow from request param to raw SQL query execution confirmed with no sanitization.",
        "missing_evidence": [],
        "recommended_manual_check": "Verify database permissions.",
    }


def valid_context_payload() -> dict:
    return {
        "finding": valid_finding_payload(),
        "code_context": "public void executeSearch(HttpServletRequest req) { String username = req.getParameter(\"username\"); ... }",
        "caller_callee_info": ["SqlInjectionController.handleRequest -> SqlInjectionLesson.executeSearch"],
        "security_assumptions": ["No global SQL sanitization filter is active in WebSecurityConfig"],
        "attack_scenario": "Attacker submits admin' -- via username form input.",
    }


class ValidatorContractTest(unittest.TestCase):
    def test_result_round_trip_preserves_contract(self):
        payload = valid_result_payload()
        result = ValidationResult.from_dict(payload)
        self.assertEqual(result.status, ValidationDecision.VALIDATED)
        self.assertEqual(result.confidence, 0.95)
        self.assertEqual(result.to_dict(), payload)
        json.dumps(result.to_dict())

    def test_result_rejects_invalid_status(self):
        payload = valid_result_payload()
        payload["status"] = "unvalidated"  # unvalidated is not a valid output decision
        with self.assertRaises(FindingSchemaError):
            ValidationResult.from_dict(payload)

    def test_result_rejects_invalid_confidence(self):
        payload = valid_result_payload()
        payload["confidence"] = 1.5
        with self.assertRaisesRegex(FindingSchemaError, "confidence"):
            ValidationResult.from_dict(payload)

    def test_result_apply_to_finding(self):
        finding = Finding.from_dict(valid_finding_payload())
        result = ValidationResult.from_dict(valid_result_payload())
        updated = result.apply_to_finding(finding, validator_name="independent-judge")

        self.assertEqual(updated.validation_status, ValidationStatus.VALIDATED)
        self.assertEqual(updated.validator, "independent-judge")
        self.assertEqual(updated.validator_confidence, 0.95)
        self.assertIn("[Validator (independent-judge)]", updated.notes)

    def test_context_round_trip_preserves_contract(self):
        payload = valid_context_payload()
        context = ValidationContext.from_dict(payload)
        self.assertEqual(context.finding.finding_id, "WG-0001")
        self.assertEqual(context.to_dict(), payload)
        json.dumps(context.to_dict())

    def test_context_rejects_invalid_types(self):
        payload = valid_context_payload()
        payload["caller_callee_info"] = "not a list"
        with self.assertRaisesRegex(FindingSchemaError, "caller_callee_info"):
            ValidationContext.from_dict(payload)

    def test_json_schemas_aligned_with_python_enums(self):
        result_schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            result_schema["properties"]["status"]["enum"],
            [item.value for item in ValidationDecision],
        )
        self.assertEqual(set(result_schema["required"]), set(result_schema["properties"]))

        context_schema = json.loads(CONTEXT_SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(set(context_schema["required"]), set(context_schema["properties"]))


if __name__ == "__main__":
    unittest.main()
