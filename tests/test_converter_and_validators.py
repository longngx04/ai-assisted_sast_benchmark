"""Unit tests for Phase 8 converters and validators."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.convert_to_jsonl import convert_generic_json_to_findings, convert_sarif_to_findings
from scripts.validate_findings import validate_findings_file
from scripts.validate_jsonl import validate_jsonl


class TestPhase8ConvertersAndValidators(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_sarif_conversion(self) -> None:
        sarif_payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemas/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Datadog SAIST",
                            "rules": [
                                {
                                    "id": "java-sqli",
                                    "name": "SQL Injection",
                                    "shortDescription": {"text": "Untrusted input in SQL query"},
                                    "properties": {"tags": ["CWE-89"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "java-sqli",
                            "level": "error",
                            "message": {"text": "SQL concatenation detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java"
                                        },
                                        "region": {"startLine": 15, "endLine": 20},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = convert_sarif_to_findings(sarif_payload, experiment_id="exp-sarif-test")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].vulnerability_type, "SQL Injection")
        self.assertEqual(findings[0].cwe, "CWE-89")
        self.assertEqual(findings[0].start_line, 15)

    def test_validate_findings_file(self) -> None:
        p = self.root / "findings.jsonl"
        sarif_payload = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "test", "rules": [{"id": "r1", "name": "XSS"}]}},
                "results": [{
                    "ruleId": "r1", "level": "warning", "message": {"text": "xss"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/File.java"}, "region": {"startLine": 10}}}],
                }],
            }],
        }
        findings = convert_sarif_to_findings(sarif_payload)
        lines = [json.dumps(f.to_dict()) for f in findings]
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, errors = validate_findings_file(p)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

        cli_result = subprocess.run(
            ["python3", "scripts/validate_findings.py", str(p)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(cli_result.returncode, 0, cli_result.stderr + cli_result.stdout)


if __name__ == "__main__":
    unittest.main()
