"""End-to-end integration test running benchmark on webgoat-mini fixture (Micro-task 12.2)."""

import tempfile
import unittest
from pathlib import Path

from harness.runner import BenchmarkRunner
from scripts.validate_findings import validate_findings_file
from scripts.validate_jsonl import validate_jsonl


class TestEndToEndFixture(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.fixture_dir = Path(__file__).parent / "fixtures" / "webgoat-mini"
        self.exclusions = Path(__file__).parent.parent / "configs" / "exclusions.json"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_run_end_to_end_mini_fixture(self) -> None:
        runner = BenchmarkRunner(
            source_root=self.fixture_dir,
            results_dir=self.root / "results",
            experiment_id="exp-fixture-mini",
            model="mock",
            exclusions_config=self.exclusions,
        )

        metrics = runner.run()

        self.assertGreater(metrics["llm_calls"], 0)
        self.assertGreater(metrics["raw_findings"], 0)
        self.assertIn("runtime_seconds", metrics)

        findings_file = self.root / "results" / "exp-fixture-mini" / "findings.jsonl"
        self.assertTrue(findings_file.exists())

        is_valid_jsonl, jsonl_errs = validate_jsonl(findings_file, expected_type="finding")
        self.assertTrue(is_valid_jsonl, f"JSONL validation errors: {jsonl_errs}")

        is_valid_schema, schema_errs = validate_findings_file(findings_file)
        self.assertTrue(is_valid_schema, f"Findings schema errors: {schema_errs}")


if __name__ == "__main__":
    unittest.main()
