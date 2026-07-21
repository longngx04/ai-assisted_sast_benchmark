import json
import unittest
from pathlib import Path

from harness.schemas import Finding, FindingSchemaError, Severity, ValidationStatus


SCHEMA_PATH = Path(__file__).parents[1] / "schemas/finding.schema.json"


def valid_payload() -> dict:
    return {
        "finding_id": "WG-0001",
        "experiment_id": "exp-a-baseline",
        "tool": "custom-harness",
        "harness_version": "v1",
        "model": "gemini-2.5-flash",
        "prompt_version": "baseline-v1",
        "vulnerability_type": "SQL Injection",
        "cwe": "CWE-89",
        "severity": "high",
        "confidence": 0.92,
        "file": "src/main/java/example/File.java",
        "start_line": 42,
        "end_line": 48,
        "function": "searchUser",
        "source": "request parameter username",
        "sink": "SQL query execution",
        "data_flow": ["HTTP request", "SQL concatenation", "query execution"],
        "description": "Untrusted input reaches a SQL query.",
        "evidence": "The username value is concatenated into the query string.",
        "attack_scenario": "An attacker submits SQL syntax as the username.",
        "security_control": "No parameterized query is used.",
        "recommendation": "Use a prepared statement.",
        "validation_status": "unvalidated",
        "validator": None,
        "validator_confidence": None,
        "duplicate_of": None,
        "notes": "",
    }


class FindingSchemaTest(unittest.TestCase):
    def test_round_trip_preserves_json_contract(self):
        payload = valid_payload()
        finding = Finding.from_dict(payload)
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.validation_status, ValidationStatus.UNVALIDATED)
        self.assertEqual(finding.to_dict(), payload)
        json.dumps(finding.to_dict())

    def test_rejects_unknown_enum(self):
        payload = valid_payload()
        payload["severity"] = "urgent"
        with self.assertRaises(FindingSchemaError):
            Finding.from_dict(payload)

    def test_direct_constructor_enforces_enum_contract(self):
        payload = valid_payload()
        payload["validation_status"] = ValidationStatus.UNVALIDATED
        with self.assertRaisesRegex(FindingSchemaError, "severity"):
            Finding(**payload)

    def test_rejects_invalid_probability_and_line_range(self):
        payload = valid_payload()
        payload["confidence"] = 1.1
        with self.assertRaisesRegex(FindingSchemaError, "confidence"):
            Finding.from_dict(payload)

        payload = valid_payload()
        payload["end_line"] = 41
        with self.assertRaisesRegex(FindingSchemaError, "end_line"):
            Finding.from_dict(payload)

    def test_json_schema_and_python_enums_are_aligned(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["severity"]["enum"], [item.value for item in Severity])
        self.assertEqual(
            schema["properties"]["validation_status"]["enum"],
            [item.value for item in ValidationStatus],
        )
        self.assertEqual(set(schema["required"]), set(schema["properties"]))


if __name__ == "__main__":
    unittest.main()
