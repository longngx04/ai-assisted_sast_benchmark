#!/usr/bin/env python3
"""CLI script to validate findings JSONL files against the Finding contract schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.schemas import Finding, FindingSchemaError


def validate_findings_file(filepath: str | Path) -> tuple[bool, list[str]]:
    path = Path(filepath)
    if not path.exists():
        return False, [f"File not found: {path}"]

    lines = path.read_text(encoding="utf-8").splitlines()
    errors: list[str] = []
    seen_ids: set[str] = set()

    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            finding = Finding.from_dict(raw)

            if finding.finding_id in seen_ids:
                errors.append(f"Line {idx}: duplicate finding_id '{finding.finding_id}'")
            seen_ids.add(finding.finding_id)

        except FindingSchemaError as exc:
            errors.append(f"Line {idx}: schema error: {exc}")
        except json.JSONDecodeError as exc:
            errors.append(f"Line {idx}: invalid JSON: {exc}")

    return len(errors) == 0, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate findings JSONL against Finding schema contract")
    parser.add_argument("file", help="Path to findings JSONL file")

    args = parser.parse_args()
    is_valid, errors = validate_findings_file(args.file)

    if is_valid:
        print(f"✅ {args.file} passed findings schema validation.")
        sys.exit(0)
    else:
        print(f"❌ {args.file} failed validation with {len(errors)} error(s):")
        for e in errors[:20]:
            print(f"  - {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
