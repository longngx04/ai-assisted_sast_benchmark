"""Tests for harness.repository — Micro-task 2.1 repository reconnaissance."""

import json
import os
import unittest
from pathlib import Path

from harness.exclusions import ExclusionPolicy
from harness.repository import (
    RepositoryScanner,
    ReconnaissanceResult,
    run_reconnaissance,
)

# Resolve the real WebGoat root from the repo
REPO_ROOT = Path(__file__).parents[1]
WEBGOAT_ROOT = REPO_ROOT / "webgoat" / "WebGoat-2025.3"
EXCLUSIONS_PATH = REPO_ROOT / "configs" / "exclusions.json"


@unittest.skipUnless(WEBGOAT_ROOT.is_dir(), "WebGoat source not available")
class TestRepositoryScanner(unittest.TestCase):
    """Integration tests that run against the real WebGoat source."""

    @classmethod
    def setUpClass(cls):
        policy = ExclusionPolicy.from_file(EXCLUSIONS_PATH)
        cls.scanner = RepositoryScanner(WEBGOAT_ROOT, exclusion_policy=policy)
        cls.result = cls.scanner.scan()

    def test_scans_java_files(self):
        self.assertGreater(self.result.scanned_java_files, 0)
        self.assertGreater(self.result.total_java_files, 0)

    def test_finds_maven_modules(self):
        self.assertGreater(len(self.result.maven_modules), 0)
        artifact_ids = [m["artifact_id"] for m in self.result.maven_modules]
        self.assertIn("webgoat", artifact_ids)

    def test_finds_lesson_modules(self):
        self.assertGreater(len(self.result.lesson_modules), 0)
        names = [lm.name for lm in self.result.lesson_modules]
        # WebGoat must have these lesson modules
        for expected in ("sqlinjection", "xss", "xxe", "csrf", "jwt", "pathtraversal"):
            self.assertIn(expected, names, f"Missing lesson module: {expected}")

    def test_finds_controllers(self):
        controllers = [c for c in self.result.components if c.kind == "controller"]
        self.assertGreater(len(controllers), 0)

    def test_finds_services(self):
        services = [c for c in self.result.components if c.kind == "service"]
        self.assertGreater(len(services), 0)

    def test_finds_configurations(self):
        configs = [c for c in self.result.components if c.kind == "configuration"]
        self.assertGreater(len(configs), 0)

    def test_finds_endpoints(self):
        self.assertGreater(len(self.result.endpoints), 0)

    def test_finds_database_patterns(self):
        db = self.result.security_patterns.get("database", [])
        self.assertGreater(len(db), 0, "Should find database patterns in WebGoat")

    def test_finds_deserialization_patterns(self):
        deser = self.result.security_patterns.get("deserialization", [])
        self.assertGreater(len(deser), 0, "Should find deserialization patterns")

    def test_finds_file_handling_patterns(self):
        fh = self.result.security_patterns.get("file_handling", [])
        self.assertGreater(len(fh), 0, "Should find file handling patterns")

    def test_finds_session_patterns(self):
        session = self.result.security_patterns.get("session", [])
        self.assertGreater(len(session), 0, "Should find session patterns")

    def test_finds_cryptography_patterns(self):
        crypto = self.result.security_patterns.get("cryptography", [])
        self.assertGreater(len(crypto), 0, "Should find cryptography patterns")

    def test_excludes_target_directory(self):
        # No file paths should contain /target/
        all_files = (
            [sp.file for items in self.result.security_patterns.values() for sp in items]
            + [c.file for c in self.result.components]
            + [e.file for e in self.result.endpoints]
        )
        for f in all_files:
            self.assertNotIn("/target/", f, f"Excluded path leaked: {f}")

    def test_summary_populated(self):
        s = self.result.summary
        self.assertGreater(s["lesson_count"], 0)
        self.assertGreater(s["endpoint_count"], 0)
        self.assertGreater(s["total_security_patterns"], 0)

    def test_result_is_json_serializable(self):
        """The full result must serialize cleanly to JSON."""
        from harness.repository import _to_serializable
        payload = _to_serializable(self.result)
        text = json.dumps(payload, indent=2)
        parsed = json.loads(text)
        self.assertIn("lesson_modules", parsed)

    def test_git_info_present(self):
        # WebGoat is a git checkout, should detect revision
        self.assertIsNotNone(self.result.revision)
        self.assertIsNotNone(self.result.branch)


@unittest.skipUnless(WEBGOAT_ROOT.is_dir(), "WebGoat source not available")
class TestSaveOutput(unittest.TestCase):
    """Test that save() produces valid output files."""

    def test_save_creates_files(self):
        import tempfile

        policy = ExclusionPolicy.from_file(EXCLUSIONS_PATH)
        scanner = RepositoryScanner(WEBGOAT_ROOT, exclusion_policy=policy)
        result = scanner.scan()

        with tempfile.TemporaryDirectory() as tmpdir:
            recon_path, arch_path = scanner.save(result, tmpdir)

            self.assertTrue(recon_path.exists())
            self.assertTrue(arch_path.exists())

            # reconnaissance.json must be valid JSON
            data = json.loads(recon_path.read_text(encoding="utf-8"))
            self.assertIn("lesson_modules", data)
            self.assertIn("endpoints", data)
            self.assertIn("security_patterns", data)

            # architecture_map.md must contain key sections
            md = arch_path.read_text(encoding="utf-8")
            self.assertIn("# WebGoat Architecture Map", md)
            self.assertIn("## Lesson Modules", md)
            self.assertIn("## REST Endpoints", md)
            self.assertIn("## Security-Relevant Patterns", md)


if __name__ == "__main__":
    unittest.main()
