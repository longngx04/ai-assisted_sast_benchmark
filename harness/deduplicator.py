"""Deduplication and canonical finding selection engine (Phase 7).

Micro-tasks 7.1, 7.2, 7.3:
  * 7.1: Multi-signal deduplication keying (vulnerability_type, CWE, file, function, line proximity, source/sink).
  * 7.2: Canonical finding selection prioritizing validation completeness, evidence detail, and confidence.
  * 7.3: Production of final findings.jsonl artifact.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Any

from harness.schemas import Finding, ValidationStatus

logger = logging.getLogger(__name__)


class Deduplicator:
    """Deduplicates findings and selects canonical representative records."""

    @staticmethod
    def generate_dedup_key(finding: Finding) -> str:
        """Construct a multi-signal deduplication key for grouping duplicates.

        Line numbers are bucketed into ranges of 10 lines to group findings
        discovered at slightly offset positions in the same function.
        """
        line_bucket = (finding.start_line // 10) * 10 if finding.start_line is not None else 0
        norm_type = (finding.vulnerability_type or "").strip().lower()
        norm_cwe = (finding.cwe or "").strip().upper()
        norm_file = (finding.file or "").strip().lower()
        norm_fn = (finding.function or "").strip().lower()
        norm_sink = (finding.sink or "").strip().lower()

        # Hash of core evidence snippet to catch identical code blocks
        snip_hash = hashlib.md5(finding.evidence.strip().encode("utf-8")).hexdigest()[:8] if finding.evidence else ""

        raw_key = f"{norm_type}:{norm_cwe}:{norm_file}:{norm_fn}:{line_bucket}:{norm_sink}:{snip_hash}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def score_finding(finding: Finding) -> tuple[int, float, int, int]:
        """Score a finding to pick the best canonical representative.

        Higher score is preferred.
        Rank criteria:
          1. Validation status rank (validated=3, unvalidated=2, uncertain=1, rejected=0)
          2. Confidence score
          3. Evidence length (more detailed evidence preferred)
          4. Data flow steps count
        """
        status_rank = {
            ValidationStatus.VALIDATED: 3,
            ValidationStatus.UNVALIDATED: 2,
            ValidationStatus.UNCERTAIN: 1,
            ValidationStatus.REJECTED: 0,
        }.get(finding.validation_status, 1)

        conf = finding.confidence
        evidence_len = len(finding.evidence or "")
        data_flow_len = len(finding.data_flow or [])

        return (status_rank, conf, evidence_len, data_flow_len)

    def deduplicate(
        self,
        findings: list[Finding],
    ) -> tuple[list[Finding], list[Finding]]:
        """Deduplicate findings list.

        Returns
        -------
        tuple[list[Finding], list[Finding]]
            (unique_canonical_findings, duplicate_findings_with_duplicate_of_set)
        """
        if not findings:
            return [], []

        clusters: dict[str, list[Finding]] = {}
        for f in findings:
            key = self.generate_dedup_key(f)
            clusters.setdefault(key, []).append(f)

        canonical_list: list[Finding] = []
        duplicate_list: list[Finding] = []

        for key, cluster in clusters.items():
            # Sort cluster by score descending
            sorted_cluster = sorted(cluster, key=self.score_finding, reverse=True)
            canonical = sorted_cluster[0]
            canonical_list.append(canonical)

            # Mark duplicates
            for dup in sorted_cluster[1:]:
                # Update duplicate_of reference
                d_dict = dup.to_dict()
                d_dict["duplicate_of"] = canonical.finding_id
                duplicate_finding = Finding.from_dict(d_dict)
                duplicate_list.append(duplicate_finding)

        return canonical_list, duplicate_list

    def process_and_save(
        self,
        findings: list[Finding],
        output_dir: str | Path,
        experiment_id: str = "exp-d-optimized",
    ) -> Path:
        """Deduplicate and write findings.jsonl (Micro-task 7.3)."""
        exp_dir = Path(output_dir) / experiment_id
        exp_dir.mkdir(parents=True, exist_ok=True)
        out_file = exp_dir / "findings.jsonl"

        canonical, duplicates = self.deduplicate(findings)

        lines = [json.dumps(f.to_dict(), ensure_ascii=False) for f in canonical]
        out_file.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

        logger.info(
            f"Deduplication complete: {len(findings)} total -> "
            f"{len(canonical)} canonical, {len(duplicates)} duplicates"
        )
        return out_file
