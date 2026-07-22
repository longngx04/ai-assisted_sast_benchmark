"""Unit tests for harness.ground_truth (Phase 9)."""

import json
import tempfile
import unittest
from pathlib import Path

from harness.ground_truth import GroundTruthEntry, GroundTruthManager
from harness.schemas import Finding, Severity, ValidationStatus


class TestGroundTruthUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.gt_path = self.root / "webgoat_ground_truth.jsonl"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_save_load_entries(self) -> None:
        gtm = GroundTruthManager(ground_truth_file=self.gt_path, coverage_complete=True)
        entry = GroundTruthEntry(
            ground_truth_id="GT-001",
            lesson="SqlInjection",
            module="sqlinjection",
            vulnerability_type="SQL Injection",
            cwe="CWE-89",
            relevant_files=["src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java"],
            expected_vulnerable_behavior="Raw SQL string concatenation",
            validation_evidence="stmt.executeQuery(query)",
            confidence=0.95,
            review_status="reviewed",
        )

        gtm.entries = [entry]
        gtm.save_entries()
        self.assertTrue(self.gt_path.exists())

        loaded = gtm.load_entries()
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].ground_truth_id, "GT-001")
        self.assertEqual(loaded[0].cwe, "CWE-89")

    def test_evaluate_findings_tp_fp_uncertain(self) -> None:
        gtm = GroundTruthManager(ground_truth_file=self.gt_path, coverage_complete=True)
        gtm.entries = [
            GroundTruthEntry(
                ground_truth_id="GT-001",
                lesson="SqlInjection",
                module="sqlinjection",
                vulnerability_type="SQL Injection",
                cwe="CWE-89",
                relevant_files=["src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java"],
                expected_vulnerable_behavior="SQLi",
                validation_evidence="stmt.executeQuery",
                confidence=0.95,
                review_status="reviewed",
            )
        ]

        # Validated True Positive finding
        f_tp = Finding(
            finding_id="F-TP",
            experiment_id="exp-test",
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
            function="search",
            source="input",
            sink="executeQuery",
            data_flow=[],
            description="SQLi",
            evidence="query",
            attack_scenario="attack",
            security_control=None,
            recommendation="",
            validation_status=ValidationStatus.VALIDATED,
            validator="judge",
            validator_confidence=0.9,
            duplicate_of=None,
            notes="",
        )

        # Rejected False Positive finding
        f_fp = Finding(
            finding_id="F-FP",
            experiment_id="exp-test",
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
            function="search",
            source="input",
            sink="executeQuery",
            data_flow=[],
            description="SQLi",
            evidence="query",
            attack_scenario="attack",
            security_control=None,
            recommendation="",
            validation_status=ValidationStatus.REJECTED,
            validator="judge",
            validator_confidence=0.9,
            duplicate_of=None,
            notes="",
        )

        res = gtm.evaluate_findings([f_tp, f_fp])
        self.assertEqual(res["true_positives"], 1)
        self.assertEqual(res["false_positives"], 1)
        self.assertEqual(res["estimated_precision"], 0.5)

    def test_incomplete_heuristic_ground_truth_does_not_claim_precision(self) -> None:
        gtm = GroundTruthManager(ground_truth_file=self.gt_path, coverage_complete=False)
        self.assertFalse(gtm.coverage_complete)
        result = gtm.evaluate_findings([])
        self.assertIsNone(result["estimated_precision"])
        self.assertEqual(result["precision_type"], "unavailable")


if __name__ == "__main__":
    unittest.main()
