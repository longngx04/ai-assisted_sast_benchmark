"""Unit tests for harness.deduplicator and scripts.deduplicate_findings (Phase 7)."""

import json
import tempfile
import unittest
from pathlib import Path

from harness.deduplicator import Deduplicator
from harness.schemas import Finding, Severity, ValidationStatus


class TestDeduplicatorUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

        self.f1 = Finding(
            finding_id="WG-0001",
            experiment_id="exp-test-7",
            tool="custom",
            harness_version="v1",
            model="mock",
            prompt_version="v1",
            vulnerability_type="SQL Injection",
            cwe="CWE-89",
            severity=Severity.HIGH,
            confidence=0.9,
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            start_line=15,
            end_line=20,
            function="searchUser",
            source="username",
            sink="executeQuery",
            data_flow=["input -> sql"],
            description="SQLi in searchUser",
            evidence="stmt.executeQuery(query)",
            attack_scenario="attack",
            security_control=None,
            recommendation="PreparedStatement",
            validation_status=ValidationStatus.UNVALIDATED,
            validator=None,
            validator_confidence=None,
            duplicate_of=None,
            notes="",
        )

        # Duplicate of f1 with better validation
        self.f2 = Finding(
            finding_id="WG-0002",
            experiment_id="exp-test-7",
            tool="custom",
            harness_version="v1",
            model="mock",
            prompt_version="v1",
            vulnerability_type="SQL Injection",
            cwe="CWE-89",
            severity=Severity.HIGH,
            confidence=0.95,
            file="src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            start_line=16,
            end_line=21,
            function="searchUser",
            source="username",
            sink="executeQuery",
            data_flow=["input -> sql"],
            description="SQL Injection finding",
            evidence="stmt.executeQuery(query)",
            attack_scenario="attack",
            security_control=None,
            recommendation="PreparedStatement",
            validation_status=ValidationStatus.VALIDATED,
            validator="judge",
            validator_confidence=0.95,
            duplicate_of=None,
            notes="",
        )

        # Distinct finding (different file)
        self.f3 = Finding(
            finding_id="WG-0003",
            experiment_id="exp-test-7",
            tool="custom",
            harness_version="v1",
            model="mock",
            prompt_version="v1",
            vulnerability_type="Cross-Site Scripting",
            cwe="CWE-79",
            severity=Severity.MEDIUM,
            confidence=0.85,
            file="src/main/java/org/owasp/webgoat/xss/XssLesson.java",
            start_line=40,
            end_line=45,
            function="renderHtml",
            source="input",
            sink="writer.write",
            data_flow=["input -> output"],
            description="XSS finding",
            evidence="writer.write(input)",
            attack_scenario="attack",
            security_control=None,
            recommendation="Escape output",
            validation_status=ValidationStatus.VALIDATED,
            validator="judge",
            validator_confidence=0.9,
            duplicate_of=None,
            notes="",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_deduplicate_clusters(self) -> None:
        dedup = Deduplicator()
        canonical, duplicates = dedup.deduplicate([self.f1, self.f2, self.f3])

        self.assertEqual(len(canonical), 2)
        self.assertEqual(len(duplicates), 1)

        # f2 should be selected over f1 because it is VALIDATED and has higher confidence
        canonical_ids = [c.finding_id for c in canonical]
        self.assertIn("WG-0002", canonical_ids)
        self.assertIn("WG-0003", canonical_ids)

        # Duplicate should link to WG-0002
        self.assertEqual(duplicates[0].duplicate_of, "WG-0002")

    def test_process_and_save(self) -> None:
        dedup = Deduplicator()
        out_file = dedup.process_and_save(
            findings=[self.f1, self.f2, self.f3],
            output_dir=self.root / "results",
            experiment_id="exp-test-7",
        )

        self.assertTrue(out_file.exists())
        lines = [json.loads(line) for line in out_file.read_text().splitlines()]
        self.assertEqual(len(lines), 2)


if __name__ == "__main__":
    unittest.main()
