#!/usr/bin/env python3
"""JSONL format and schema validator for SAST benchmark artifacts (Micro-task 8.2 & 3.3).

Validates:
  * Each line is a valid JSON object
  * Required fields are present
  * Line numbers are positive integers or null
  * Confidence values are float [0, 1] or null
  * Severities and ValidationStatus enums (if present) match schema
  * Unique candidate/finding IDs
  * File paths are relative (no leading '/' or drive letter)
  * File is not wrapped in a JSON array
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def validate_jsonl(filepath: str | Path, expected_type: str = "auto") -> tuple[bool, list[str]]:
    """Validate a JSONL file.

    Parameters
    ----------
    filepath : str | Path
        Path to the .jsonl file to validate.
    expected_type : str
        "candidate", "finding", or "auto" (detected from fields).

    Returns
    -------
    tuple[bool, list[str]]
        (is_valid, list_of_error_messages)
    """
    path = Path(filepath)
    if not path.exists():
        return False, [f"File not found: {path}"]

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return True, []  # Empty file is valid JSONL with 0 records

    # Check for outer JSON array error
    if content.startswith("["):
        return False, ["File starts with '[': JSONL file must NOT be wrapped in a JSON array"]

    lines = content.splitlines()
    errors: list[str] = []
    seen_ids: set[str] = set()

    for idx, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str:
            continue  # Skip empty lines

        try:
            record = json.loads(line_str)
        except json.JSONDecodeError as exc:
            errors.append(f"Line {idx}: invalid JSON syntax: {exc}")
            continue

        if not isinstance(record, dict):
            errors.append(f"Line {idx}: record is not a JSON object (got {type(record).__name__})")
            continue

        # Determine type if auto
        rec_type = expected_type
        if rec_type == "auto":
            if "candidate_id" in record:
                rec_type = "candidate"
            elif "finding_id" in record:
                rec_type = "finding"
            else:
                rec_type = "generic"

        if rec_type == "candidate":
            rec_errors = _validate_candidate_record(record, idx, seen_ids)
            errors.extend(rec_errors)
        elif rec_type == "finding":
            rec_errors = _validate_finding_record(record, idx, seen_ids)
            errors.extend(rec_errors)
        else:
            # Generic record check
            if "id" in record and isinstance(record["id"], str):
                if record["id"] in seen_ids:
                    errors.append(f"Line {idx}: duplicate ID '{record['id']}'")
                seen_ids.add(record["id"])

    return len(errors) == 0, errors


def _validate_candidate_record(record: dict[str, Any], idx: int, seen_ids: set[str]) -> list[str]:
    errs: list[str] = []
    req_fields = ("candidate_id", "category", "file", "line", "matched_rule", "snippet")
    for f in req_fields:
        if f not in record:
            errs.append(f"Line {idx}: missing required candidate field '{f}'")

    cid = record.get("candidate_id")
    if isinstance(cid, str):
        if cid in seen_ids:
            errs.append(f"Line {idx}: duplicate candidate_id '{cid}'")
        seen_ids.add(cid)

    filePath = record.get("file")
    if isinstance(filePath, str):
        if filePath.startswith("/") or filePath.startswith("\\") or (len(filePath) > 1 and filePath[1] == ":"):
            errs.append(f"Line {idx}: file path '{filePath}' must be relative, not absolute")

    line_num = record.get("line")
    if line_num is not None:
        if isinstance(line_num, bool) or not isinstance(line_num, int) or line_num < 1:
            errs.append(f"Line {idx}: line must be positive integer or null (got {line_num})")

    return errs


def _validate_finding_record(record: dict[str, Any], idx: int, seen_ids: set[str]) -> list[str]:
    errs: list[str] = []
    req_fields = (
        "finding_id", "experiment_id", "tool", "harness_version", "model",
        "prompt_version", "vulnerability_type", "severity", "confidence",
        "file", "description", "evidence", "attack_scenario",
        "recommendation", "validation_status", "notes",
    )
    for f in req_fields:
        if f not in record:
            errs.append(f"Line {idx}: missing required finding field '{f}'")

    fid = record.get("finding_id")
    if isinstance(fid, str):
        if fid in seen_ids:
            errs.append(f"Line {idx}: duplicate finding_id '{fid}'")
        seen_ids.add(fid)

    filePath = record.get("file")
    if isinstance(filePath, str):
        if filePath.startswith("/") or filePath.startswith("\\") or (len(filePath) > 1 and filePath[1] == ":"):
            errs.append(f"Line {idx}: file path '{filePath}' must be relative, not absolute")

    sev = record.get("severity")
    valid_severities = ("critical", "high", "medium", "low", "informational")
    if sev not in valid_severities:
        errs.append(f"Line {idx}: invalid severity '{sev}', must be one of {valid_severities}")

    status = record.get("validation_status")
    valid_statuses = ("unvalidated", "validated", "rejected", "uncertain")
    if status not in valid_statuses:
        errs.append(f"Line {idx}: invalid validation_status '{status}', must be one of {valid_statuses}")

    conf = record.get("confidence")
    if isinstance(conf, bool) or not isinstance(conf, (int, float)) or not 0 <= conf <= 1:
        errs.append(f"Line {idx}: confidence must be a number between 0 and 1 (got {conf})")

    for line_key in ("start_line", "end_line"):
        ln = record.get(line_key)
        if ln is not None:
            if isinstance(ln, bool) or not isinstance(ln, int) or ln < 1:
                errs.append(f"Line {idx}: {line_key} must be positive integer or null (got {ln})")

    return errs


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scripts/validate_jsonl.py <path-to-file.jsonl>")
        sys.exit(1)

    target_file = sys.argv[1]
    is_valid, errors = validate_jsonl(target_file)
    if is_valid:
        print(f"✅ {target_file} is valid JSONL")
        sys.exit(0)
    else:
        print(f"❌ {target_file} validation failed with {len(errors)} error(s):")
        for e in errors[:20]:
            print(f"  - {e}")
        if len(errors) > 20:
            print(f"  ... ({len(errors) - 20} more errors)")
        sys.exit(1)
