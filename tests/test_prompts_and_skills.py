"""Unit tests for Phase 4 prompts and security skill files integrity."""

import unittest
from pathlib import Path


class TestPromptsAndSkillsIntegrity(unittest.TestCase):

    def setUp(self) -> None:
        self.root = Path(__file__).parent.parent
        self.prompts_dir = self.root / "prompts"
        self.skills_dir = self.root / "skills"

    def test_required_prompts_exist_and_have_version(self) -> None:
        expected_prompts = [
            "baseline.md",
            "reconnaissance.md",
            "architecture-map.md",
            "sqli.md",
            "xss.md",
            "command-injection.md",
            "path-traversal.md",
            "ssrf.md",
            "access-control.md",
            "deserialization.md",
            "validation.md",
            "deduplication.md",
        ]
        for p_name in expected_prompts:
            p_path = self.prompts_dir / p_name
            self.assertTrue(p_path.exists(), f"Missing prompt file: {p_name}")
            content = p_path.read_text(encoding="utf-8")
            self.assertIn("prompt_version:", content, f"Prompt {p_name} missing prompt_version comment")

    def test_required_skills_exist_and_have_version(self) -> None:
        expected_skills = [
            "sqli",
            "xss",
            "command-injection",
            "path-traversal",
            "ssrf",
            "access-control",
            "authentication",
            "deserialization",
            "business-logic",
        ]
        for s_name in expected_skills:
            s_path = self.skills_dir / s_name / "SKILL.md"
            self.assertTrue(s_path.exists(), f"Missing skill file for: {s_name}")
            content = s_path.read_text(encoding="utf-8")
            self.assertIn("skill_version:", content, f"Skill {s_name} missing skill_version comment")
            self.assertIn("## 1. Goal", content)
            self.assertIn("## 8. CWE & Severity Guidance", content)


if __name__ == "__main__":
    unittest.main()
