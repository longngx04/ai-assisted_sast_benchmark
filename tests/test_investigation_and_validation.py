"""Unit tests for harness.investigator and harness.validator (Phase 6)."""

import json
import tempfile
import unittest
from pathlib import Path

from harness.indexer import JavaSymbolIndex
from harness.investigator import InvestigationAgent
from harness.model_client import ModelClient
from harness.schemas import Finding, ValidationStatus
from harness.validator import IndependentValidator


class TestInvestigationAndValidationUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.webgoat_root = Path("webgoat/WebGoat-2025.3").resolve()

        # Dummy index
        self.index = JavaSymbolIndex(
            generated_at="",
            webgoat_root=str(self.webgoat_root),
            total_java_files=0,
            indexed_files=0,
            excluded_files=0,
            classes=[],
            caller_callee_edges=[],
            summary={},
        )
        self.client = ModelClient(
            default_model="mock",
            results_dir=self.root / "results",
            cache_dir=self.root / "cache",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_investigation_agent_mock(self) -> None:
        agent = InvestigationAgent(
            webgoat_root=self.webgoat_root,
            index=self.index,
            client=self.client,
            prompts_dir="prompts",
        )

        cand = {
            "candidate_id": "CAND-001",
            "category": "database",
            "file": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            "line": 15,
            "symbol": "searchUser",
            "snippet": "SELECT *",
            "is_rejected": False,
        }

        findings = agent.investigate_candidate(
            candidate=cand,
            experiment_id="exp-test-6",
            model="mock",
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.vulnerability_type, "SQL Injection")
        self.assertEqual(finding.cwe, "CWE-89")

    def test_validator_and_partitioning(self) -> None:
        agent = InvestigationAgent(
            webgoat_root=self.webgoat_root,
            index=self.index,
            client=self.client,
            prompts_dir="prompts",
        )

        cand = {
            "candidate_id": "CAND-002",
            "category": "database",
            "file": "src/main/java/org/owasp/webgoat/sqli/SqlInjectionLesson.java",
            "line": 15,
            "symbol": "searchUser",
            "snippet": "SELECT *",
            "is_rejected": False,
        }
        findings = agent.investigate_candidate(cand, experiment_id="exp-test-6", model="mock")
        self.assertEqual(len(findings), 1)

        validator = IndependentValidator(
            webgoat_root=self.webgoat_root,
            index=self.index,
            client=self.client,
            prompts_dir="prompts",
        )

        validated_findings = validator.validate_batch(
            findings=findings,
            experiment_id="exp-test-6",
            model="mock",
        )

        self.assertEqual(len(validated_findings), 1)
        self.assertEqual(validated_findings[0].validation_status, ValidationStatus.VALIDATED)

        paths = validator.partition_and_save_findings(
            findings=validated_findings,
            output_dir=self.root / "results",
            experiment_id="exp-test-6",
        )

        self.assertTrue(paths["validated"].exists())
        self.assertTrue(paths["rejected"].exists())
        self.assertTrue(paths["uncertain"].exists())

        lines = [json.loads(line) for line in paths["validated"].read_text().splitlines()]
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["validation_status"], "validated")


if __name__ == "__main__":
    unittest.main()
