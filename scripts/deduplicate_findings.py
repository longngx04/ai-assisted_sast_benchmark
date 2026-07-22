#!/usr/bin/env python3
"""CLI script to deduplicate raw findings JSONL files (Micro-task 8.3)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness.deduplicator import Deduplicator
from harness.schemas import Finding


def main() -> None:
    parser = argparse.ArgumentParser(description="Deduplicate raw findings JSONL file (Micro-task 8.3)")
    parser.add_argument("--input", "-i", required=True, help="Input raw findings JSONL file")
    parser.add_argument("--output", "-o", required=True, help="Output deduplicated findings JSONL file")

    args = parser.parse_args()
    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        print(f"Error: input file '{in_path}' does not exist", file=sys.stderr)
        sys.exit(1)

    lines = in_path.read_text(encoding="utf-8").splitlines()
    findings: list[Finding] = []

    for idx, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            findings.append(Finding.from_dict(raw))
        except Exception as exc:
            print(f"Warning: skipped invalid line {idx}: {exc}", file=sys.stderr)

    dedup = Deduplicator()
    canonical, duplicates = dedup.deduplicate(findings)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_lines = [json.dumps(f.to_dict(), ensure_ascii=False) for f in canonical]
    out_path.write_text("\n".join(out_lines) + ("\n" if out_lines else ""), encoding="utf-8")

    print(f"✅ Deduplication complete:")
    print(f"  Input findings:  {len(findings)}")
    print(f"  Canonical/Unique: {len(canonical)}")
    print(f"  Duplicates:       {len(duplicates)}")
    print(f"  Output saved to:  {out_path}")


if __name__ == "__main__":
    main()
