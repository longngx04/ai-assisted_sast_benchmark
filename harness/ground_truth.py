"""Local ground truth extractor and finding matcher engine (Phase 9).

Micro-tasks 9.1, 9.2, 9.3:
  * 9.1: Extract local ground truth benchmark records from WebGoat source, tests, and solutions.
  * 9.2: Schema definition for ground truth records.
  * 9.3: Deterministic matching between scan Findings and Ground Truth entries (TP / FP / Uncertain).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from harness.schemas import Finding, ValidationStatus

logger = logging.getLogger(__name__)


@dataclass
class GroundTruthEntry:
    """A ground truth vulnerability benchmark entry."""
    ground_truth_id: str
    lesson: str
    module: str
    vulnerability_type: str
    cwe: str
    relevant_files: list[str]
    expected_vulnerable_behavior: str
    validation_evidence: str
    confidence: float = 0.95

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GroundTruthManager:
    """Manages ground truth loading, extraction, and finding evaluation."""

    def __init__(self, ground_truth_file: str | Path = "ground_truth/webgoat_ground_truth.jsonl") -> None:
        self.gt_file = Path(ground_truth_file).resolve()
        self.entries: list[GroundTruthEntry] = []
        if self.gt_file.exists():
            self.load_entries()

    def load_entries(self) -> list[GroundTruthEntry]:
        """Load ground truth records from JSONL."""
        self.entries = []
        lines = self.gt_file.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                self.entries.append(GroundTruthEntry(**raw))
            except Exception as exc:
                logger.warning(f"Error loading ground truth line: {exc}")
        return self.entries

    def build_webgoat_ground_truth(self, webgoat_root: str | Path) -> list[GroundTruthEntry]:
        """Extract ground truth entries deterministically from WebGoat lessons and tests."""
        root = Path(webgoat_root).resolve()
        entries: list[GroundTruthEntry] = []
        gt_counter = 1

        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                if not fname.endswith(".java"):
                    continue
                abs_p = Path(dirpath) / fname
                rel_p = str(abs_p.relative_to(root)).replace(os.sep, "/")

                # Look for vulnerable lesson implementation classes or tests
                if "lesson" in rel_p.lower() or "assignment" in rel_p.lower() or "challenge" in rel_p.lower():
                    content = abs_p.read_text(encoding="utf-8", errors="replace")

                    # SQL Injection detection in lesson
                    if "SELECT" in content and "+" in content and ("executeQuery" in content or "createNativeQuery" in content):
                        entries.append(GroundTruthEntry(
                            ground_truth_id=f"GT-WG-{gt_counter:03d}",
                            lesson=fname.replace(".java", ""),
                            module=self._extract_module(rel_p),
                            vulnerability_type="SQL Injection",
                            cwe="CWE-89",
                            relevant_files=[rel_p],
                            expected_vulnerable_behavior="String concatenation into raw SQL query executed against database",
                            validation_evidence=self._extract_snippet(content, ["SELECT", "executeQuery", "createNativeQuery"]),
                            confidence=0.95,
                        ))
                        gt_counter += 1

                    # Path Traversal detection
                    elif "File" in content and ".." in content or ("getCanonicalPath" not in content and "FileInputStream" in content and "+" in content):
                        entries.append(GroundTruthEntry(
                            ground_truth_id=f"GT-WG-{gt_counter:03d}",
                            lesson=fname.replace(".java", ""),
                            module=self._extract_module(rel_p),
                            vulnerability_type="Path Traversal",
                            cwe="CWE-22",
                            relevant_files=[rel_p],
                            expected_vulnerable_behavior="File path constructed from untrusted user input without canonical bounds check",
                            validation_evidence=self._extract_snippet(content, ["File", "FileInputStream"]),
                            confidence=0.90,
                        ))
                        gt_counter += 1

                    # Deserialization detection
                    elif "ObjectInputStream" in content and "readObject" in content:
                        entries.append(GroundTruthEntry(
                            ground_truth_id=f"GT-WG-{gt_counter:03d}",
                            lesson=fname.replace(".java", ""),
                            module=self._extract_module(rel_p),
                            vulnerability_type="Insecure Deserialization",
                            cwe="CWE-502",
                            relevant_files=[rel_p],
                            expected_vulnerable_behavior="Untrusted byte stream deserialized without class allowlisting",
                            validation_evidence=self._extract_snippet(content, ["ObjectInputStream", "readObject"]),
                            confidence=0.95,
                        ))
                        gt_counter += 1

        self.entries = entries
        self.save_entries()
        return self.entries

    def save_entries(self) -> None:
        """Save ground truth entries to JSONL."""
        self.gt_file.parent.mkdir(parents=True, exist_ok=True)
        lines = [json.dumps(e.to_dict(), ensure_ascii=False) for e in self.entries]
        self.gt_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def evaluate_findings(
        self,
        findings: list[Finding],
    ) -> dict[str, Any]:
        """Map findings against ground truth records to compute True Positives, False Positives, and Uncertain.

        Task 9.3 Rules:
          * True Positive: Finding file matches ground truth relevant_files AND vulnerability_type/CWE matches AND status is not rejected.
          * False Positive: Finding rejected by validator OR no ground truth match in file.
          * Uncertain: Finding unvalidated or matching vulnerability class but not line/file path exactly.
        """
        tp: list[Finding] = []
        fp: list[Finding] = []
        uncertain: list[Finding] = []

        gt_file_map: dict[str, list[GroundTruthEntry]] = {}
        for entry in self.entries:
            for rf in entry.relevant_files:
                gt_file_map.setdefault(rf, []).append(entry)

        for finding in findings:
            if finding.validation_status == ValidationStatus.REJECTED:
                fp.append(finding)
                continue

            matches = gt_file_map.get(finding.file, [])
            type_match = False
            for gt in matches:
                if (finding.cwe and finding.cwe == gt.cwe) or (finding.vulnerability_type.lower() in gt.vulnerability_type.lower()):
                    type_match = True
                    break

            if type_match and finding.validation_status == ValidationStatus.VALIDATED:
                tp.append(finding)
            elif finding.validation_status == ValidationStatus.UNCERTAIN or type_match:
                uncertain.append(finding)
            else:
                fp.append(finding)

        precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0.0

        return {
            "true_positives": len(tp),
            "false_positives": len(fp),
            "uncertain": len(uncertain),
            "estimated_precision": round(precision, 4),
            "tp_findings": [f.finding_id for f in tp],
            "fp_findings": [f.finding_id for f in fp],
            "uncertain_findings": [f.finding_id for f in uncertain],
        }

    def _extract_module(self, rel_path: str) -> str:
        parts = Path(rel_path).parts
        for i, p in enumerate(parts):
            if p == "lessons" and i + 1 < len(parts):
                return parts[i + 1]
        return "core"

    def _extract_snippet(self, content: str, keywords: list[str]) -> str:
        for line in content.splitlines():
            if any(kw in line for kw in keywords):
                return line.strip()
        return content[:100].strip()
