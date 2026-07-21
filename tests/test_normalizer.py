"""Tests for harness.normalizer — Micro-task 1.2 normalization rules."""

import os
import unittest

from harness.normalizer import (
    generate_finding_id,
    normalize_confidence,
    normalize_cwe,
    normalize_line,
    normalize_path,
    normalize_raw_finding,
    normalize_severity,
    normalize_validation_status,
)
from harness.schemas import Finding, Severity, ValidationStatus


class TestNormalizeCWE(unittest.TestCase):
    """CWE strings must be normalized to ``CWE-<number>`` or ``None``."""

    def test_canonical_format(self):
        self.assertEqual(normalize_cwe("CWE-89"), "CWE-89")

    def test_lowercase(self):
        self.assertEqual(normalize_cwe("cwe-89"), "CWE-89")

    def test_no_dash(self):
        self.assertEqual(normalize_cwe("CWE89"), "CWE-89")

    def test_bare_number(self):
        self.assertEqual(normalize_cwe("89"), "CWE-89")

    def test_integer_input(self):
        self.assertEqual(normalize_cwe(89), "CWE-89")

    def test_none(self):
        self.assertIsNone(normalize_cwe(None))

    def test_empty_string(self):
        self.assertIsNone(normalize_cwe(""))

    def test_garbage(self):
        self.assertIsNone(normalize_cwe("not-a-cwe"))


class TestNormalizePath(unittest.TestCase):
    """File paths must be relative to WEBGOAT_ROOT with forward slashes."""

    def setUp(self):
        self.root = "/opt/webgoat/WebGoat-2025.3"

    def test_absolute_path_becomes_relative(self):
        result = normalize_path(
            "/opt/webgoat/WebGoat-2025.3/src/main/java/Foo.java",
            self.root,
        )
        self.assertEqual(result, "src/main/java/Foo.java")

    def test_already_relative_stays_relative(self):
        result = normalize_path("src/main/java/Foo.java", self.root)
        self.assertEqual(result, "src/main/java/Foo.java")

    def test_strips_dot_slash(self):
        result = normalize_path("./src/main/java/Foo.java", self.root)
        self.assertEqual(result, "src/main/java/Foo.java")

    def test_empty_string_passthrough(self):
        self.assertEqual(normalize_path("", self.root), "")

    def test_forward_slashes(self):
        result = normalize_path(
            "/opt/webgoat/WebGoat-2025.3/a/b/c.java",
            self.root,
        )
        self.assertNotIn("\\", result)


class TestNormalizeLine(unittest.TestCase):
    """Line numbers must be positive integers or None."""

    def test_positive_int(self):
        self.assertEqual(normalize_line(42), 42)

    def test_string_int(self):
        self.assertEqual(normalize_line("42"), 42)

    def test_zero_becomes_none(self):
        self.assertIsNone(normalize_line(0))

    def test_negative_becomes_none(self):
        self.assertIsNone(normalize_line(-1))

    def test_none_stays_none(self):
        self.assertIsNone(normalize_line(None))

    def test_garbage_becomes_none(self):
        self.assertIsNone(normalize_line("abc"))

    def test_float_truncated(self):
        self.assertEqual(normalize_line(3.9), 3)


class TestNormalizeConfidence(unittest.TestCase):
    """Confidence must be clamped to [0.0, 1.0]."""

    def test_within_range(self):
        self.assertAlmostEqual(normalize_confidence(0.75), 0.75)

    def test_above_one_clamped(self):
        self.assertAlmostEqual(normalize_confidence(1.5), 1.0)

    def test_below_zero_clamped(self):
        self.assertAlmostEqual(normalize_confidence(-0.3), 0.0)

    def test_string_number(self):
        self.assertAlmostEqual(normalize_confidence("0.9"), 0.9)

    def test_non_numeric_becomes_zero(self):
        self.assertAlmostEqual(normalize_confidence("high"), 0.0)

    def test_none_becomes_zero(self):
        self.assertAlmostEqual(normalize_confidence(None), 0.0)


class TestNormalizeSeverity(unittest.TestCase):
    """Severity strings must map to canonical enum values."""

    def test_canonical(self):
        self.assertEqual(normalize_severity("high"), Severity.HIGH)

    def test_case_insensitive(self):
        self.assertEqual(normalize_severity("HIGH"), Severity.HIGH)

    def test_alias_warning(self):
        self.assertEqual(normalize_severity("warning"), Severity.MEDIUM)

    def test_alias_error(self):
        self.assertEqual(normalize_severity("error"), Severity.HIGH)

    def test_unknown_defaults_to_medium(self):
        self.assertEqual(normalize_severity("foo"), Severity.MEDIUM)

    def test_enum_passthrough(self):
        self.assertEqual(normalize_severity(Severity.LOW), Severity.LOW)


class TestNormalizeValidationStatus(unittest.TestCase):
    """Validation status strings must map to canonical enum values."""

    def test_canonical(self):
        self.assertEqual(
            normalize_validation_status("validated"),
            ValidationStatus.VALIDATED,
        )

    def test_unknown_defaults_to_unvalidated(self):
        self.assertEqual(
            normalize_validation_status("bogus"),
            ValidationStatus.UNVALIDATED,
        )

    def test_enum_passthrough(self):
        self.assertEqual(
            normalize_validation_status(ValidationStatus.REJECTED),
            ValidationStatus.REJECTED,
        )


class TestGenerateFindingID(unittest.TestCase):
    """Finding IDs must be deterministic and prefixed with ``WG-``."""

    def test_deterministic(self):
        a = generate_finding_id("exp-a", "Foo.java", 10, "CWE-89", "SQL Injection")
        b = generate_finding_id("exp-a", "Foo.java", 10, "CWE-89", "SQL Injection")
        self.assertEqual(a, b)

    def test_prefix(self):
        fid = generate_finding_id("exp-a", "Foo.java", 10, "CWE-89", "SQLi")
        self.assertTrue(fid.startswith("WG-"))

    def test_length(self):
        fid = generate_finding_id("exp-a", "Foo.java", None, None, "XSS")
        # WG- + 8 hex chars = 11 characters
        self.assertEqual(len(fid), 11)

    def test_different_inputs_differ(self):
        a = generate_finding_id("exp-a", "Foo.java", 10, "CWE-89", "SQLi")
        b = generate_finding_id("exp-b", "Foo.java", 10, "CWE-89", "SQLi")
        self.assertNotEqual(a, b)

    def test_case_insensitive_vuln_type(self):
        a = generate_finding_id("exp-a", "F.java", 1, None, "SQL Injection")
        b = generate_finding_id("exp-a", "F.java", 1, None, "sql injection")
        self.assertEqual(a, b)


class TestNormalizeRawFinding(unittest.TestCase):
    """Integration test: normalize_raw_finding produces valid Findings."""

    def _minimal_raw(self) -> dict:
        """Return the smallest raw dict that the normalizer can handle."""
        return {
            "vulnerability_type": "SQL Injection",
            "cwe": "89",
            "severity": "HIGH",
            "confidence": 0.9,
            "file": "/opt/webgoat/WebGoat-2025.3/src/main/java/Foo.java",
            "start_line": 42,
            "end_line": 48,
            "description": "SQL injection via string concat.",
            "evidence": "query = \"SELECT * FROM users WHERE name='\" + name + \"'\";",
            "attack_scenario": "Attacker sends crafted name parameter.",
            "recommendation": "Use prepared statements.",
        }

    def test_produces_valid_finding(self):
        finding = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertIsInstance(finding, Finding)

    def test_path_is_relative(self):
        finding = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.file, "src/main/java/Foo.java")

    def test_cwe_normalized(self):
        finding = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.cwe, "CWE-89")

    def test_severity_normalized(self):
        finding = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_deterministic_id_generated(self):
        f1 = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        f2 = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(f1.finding_id, f2.finding_id)
        self.assertTrue(f1.finding_id.startswith("WG-"))

    def test_missing_optional_fields_become_none_or_empty(self):
        raw = self._minimal_raw()
        # Deliberately omit optional fields
        finding = normalize_raw_finding(
            raw,
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        # Nullable strings → None
        self.assertIsNone(finding.function)
        self.assertIsNone(finding.source)
        self.assertIsNone(finding.sink)
        self.assertIsNone(finding.security_control)
        self.assertIsNone(finding.validator)
        self.assertIsNone(finding.duplicate_of)
        # Required strings with no value → ""
        self.assertEqual(finding.notes, "")
        # Missing list → []
        self.assertEqual(finding.data_flow, [])

    def test_inverted_line_range_is_fixed(self):
        raw = self._minimal_raw()
        raw["start_line"] = 50
        raw["end_line"] = 40
        finding = normalize_raw_finding(
            raw,
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.start_line, 40)
        self.assertEqual(finding.end_line, 50)

    def test_confidence_clamped(self):
        raw = self._minimal_raw()
        raw["confidence"] = 1.5
        finding = normalize_raw_finding(
            raw,
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertAlmostEqual(finding.confidence, 1.0)

    def test_data_flow_string_becomes_list(self):
        raw = self._minimal_raw()
        raw["data_flow"] = "single step"
        finding = normalize_raw_finding(
            raw,
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.data_flow, ["single step"])

    def test_round_trip_to_dict_is_valid_json(self):
        import json

        finding = normalize_raw_finding(
            self._minimal_raw(),
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        payload = finding.to_dict()
        line = json.dumps(payload)
        parsed = json.loads(line)
        # Re-create from parsed JSON to ensure full round-trip
        Finding.from_dict(parsed)

    def test_preserves_raw_evidence(self):
        raw = self._minimal_raw()
        raw["evidence"] = 'String query = "SELECT * FROM " + table;'
        finding = normalize_raw_finding(
            raw,
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.evidence, raw["evidence"])

    def test_raw_finding_id_preserved_when_present(self):
        raw = self._minimal_raw()
        raw["finding_id"] = "CUSTOM-001"
        finding = normalize_raw_finding(
            raw,
            experiment_id="exp-a-baseline",
            webgoat_root="/opt/webgoat/WebGoat-2025.3",
        )
        self.assertEqual(finding.finding_id, "CUSTOM-001")


if __name__ == "__main__":
    unittest.main()
