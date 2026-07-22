"""Unit tests for harness.investigator and harness.validator (Phase 6)."""

import json
import tempfile
import unittest
from pathlib import Path

from harness.indexer import JavaIndexer, JavaSymbolIndex
from harness.investigator import InvestigationAgent
from harness.model_client import ModelClient
from harness.schemas import Finding, ValidationStatus
from harness.validator import IndependentValidator


class TestInvestigationAndValidationUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.webgoat_root = (Path(__file__).parent / "fixtures" / "webgoat-mini").resolve()

        # Dummy index
        self.index = JavaIndexer(self.webgoat_root).build()
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
            "file": "src/main/java/org/owasp/webgoat/mini/VulnerableLesson.java",
            "line": 10,
            "symbol": "executeQuery",
            "snippet": 'String sql = "SELECT * FROM users WHERE name = \'" + username + "\'";',
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
            "file": "src/main/java/org/owasp/webgoat/mini/VulnerableLesson.java",
            "line": 10,
            "symbol": "executeQuery",
            "snippet": 'String sql = "SELECT * FROM users WHERE name = \'" + username + "\'";',
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

    def test_discards_finding_when_evidence_is_not_in_source(self) -> None:
        agent = InvestigationAgent(
            webgoat_root=self.webgoat_root,
            index=self.index,
            client=self.client,
            prompts_dir="prompts",
        )
        raw = {
            "vulnerability_type": "SQL Injection",
            "cwe": "CWE-89",
            "source": "username",
            "sink": "executeQuery",
            "data_flow": ["username reaches query"],
            "description": "SQL injection",
            "evidence": "this code does not exist",
            "attack_scenario": "Inject a quote",
            "recommendation": "Use parameters",
            "file": "src/main/java/org/owasp/webgoat/mini/VulnerableLesson.java",
        }
        self.assertIsNone(agent._verify_evidence(raw))

    def test_category_mapping_loads_prompt_and_skill(self) -> None:
        agent = InvestigationAgent(
            webgoat_root=self.webgoat_root,
            index=self.index,
            client=self.client,
            prompts_dir="prompts",
            skills_dir="skills",
        )
        text, version = agent._load_analysis_resources("file_handling", True)
        self.assertIn("Path Traversal Investigation Prompt", text)
        self.assertIn("SECURITY SKILL: path-traversal", text)
        self.assertEqual(version, "path-traversal-v1.0")


if __name__ == "__main__":
    unittest.main()
