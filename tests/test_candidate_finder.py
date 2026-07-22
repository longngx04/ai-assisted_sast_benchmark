"""Unit tests for harness.candidate_finder and scripts.validate_jsonl (Phase 3)."""

import json
import tempfile
import unittest
from pathlib import Path

from harness.candidate_finder import Candidate, CandidateFinder, run_candidate_discovery
from scripts.validate_jsonl import validate_jsonl


class TestCandidateFinderUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

        # Create synthetic Java file
        self.java_dir = self.root / "src" / "main" / "java" / "org" / "example"
        self.java_dir.mkdir(parents=True)
        self.sample_file = self.java_dir / "VulnerableService.java"
        self.sample_file.write_text(
            """package org.example;
import java.sql.*;

public class VulnerableService {
    public void searchUser(String input) throws Exception {
        // Vulnerable SQLi
        String query = "SELECT * FROM users WHERE username = '" + input + "'";
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:test");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        # Vulnerable Command Injection
        Runtime.getRuntime().exec("ping " + input);

        # Safe Parameterized SQLi
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setInt(1, 1);
    }
}
""",
            encoding="utf-8",
        )
        self.web_dir = self.root / "src" / "main" / "resources"
        self.web_dir.mkdir(parents=True)
        (self.web_dir / "lesson.js").write_text(
            "const value = request.query.name; element.innerHTML = value;\n",
            encoding="utf-8",
        )
        (self.web_dir / "lesson.html").write_text(
            '<div th:utext="${name}"></div>\n', encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_candidate_discovery(self) -> None:
        finder = CandidateFinder(webgoat_root=self.root)
        cands = finder.scan()

        self.assertGreater(len(cands), 0)
        categories = [c.category for c in cands]
        self.assertIn("database", categories)
        self.assertIn("command_execution", categories)
        self.assertIn("html_template", categories)

    def test_early_rejection_parameterized(self) -> None:
        finder = CandidateFinder(webgoat_root=self.root)
        cands = finder.scan()

        # Find the candidate matching PreparedStatement line
        ps_cand = [c for c in cands if "PreparedStatement" in c.snippet or "prepareStatement" in c.snippet]
        if ps_cand:
            self.assertTrue(ps_cand[0].is_rejected)
            self.assertEqual(ps_cand[0].priority, "low")

    def test_run_candidate_discovery_and_validate(self) -> None:
        out_file = run_candidate_discovery(
            webgoat_root=self.root,
            output_dir=self.root / "results",
            experiment_id="exp-test",
        )
        self.assertTrue(out_file.exists())

        is_valid, errors = validate_jsonl(out_file, expected_type="candidate")
        self.assertTrue(is_valid, f"Validation errors: {errors}")


class TestValidateJsonl(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_validate_valid_candidate_jsonl(self) -> None:
        p = self.root / "candidates.jsonl"
        cand = {
            "candidate_id": "CAND-001",
            "category": "database",
            "file": "src/main/File.java",
            "line": 10,
            "symbol": "search",
            "matched_rule": "sqli_concat",
            "snippet": "SELECT *",
            "context_refs": [],
            "priority": "high",
            "is_rejected": False,
            "rejection_reason": None,
        }
        p.write_text(json.dumps(cand) + "\n", encoding="utf-8")
        is_valid, errors = validate_jsonl(p)
        self.assertTrue(is_valid)
        self.assertEqual(len(errors), 0)

    def test_rejects_json_array(self) -> None:
        p = self.root / "array.jsonl"
        p.write_text("[{'candidate_id': '1'}]\n", encoding="utf-8")
        is_valid, errors = validate_jsonl(p)
        self.assertFalse(is_valid)
        self.assertIn("JSON array", errors[0])

    def test_rejects_absolute_path(self) -> None:
        p = self.root / "abs.jsonl"
        cand = {
            "candidate_id": "CAND-002",
            "category": "database",
            "file": "/absolute/path/File.java",
            "line": 10,
            "matched_rule": "rule",
            "snippet": "code",
        }
        p.write_text(json.dumps(cand) + "\n", encoding="utf-8")
        is_valid, errors = validate_jsonl(p)
        self.assertFalse(is_valid)
        self.assertTrue(any("relative" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
