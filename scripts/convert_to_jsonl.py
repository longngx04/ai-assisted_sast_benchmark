#!/usr/bin/env python3
"""SARIF and JSON to benchmark findings JSONL converter (Micro-task 8.1)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from harness.normalizer import normalize_raw_finding
from harness.schemas import Finding, FindingSchemaError


def convert_sarif_to_findings(
    payload: dict[str, Any],
    experiment_id: str = "exp-converted",
    webgoat_root: str = "webgoat/WebGoat-2025.3",
    tool_name: str = "sarif-tool",
    model_name: str = "gemini-2.5-flash",
) -> list[Finding]:
    """Convert SARIF 2.1.0 object into normalized Finding instances."""
    findings: list[Finding] = []
    runs = payload.get("runs", [])

    for run in runs:
        rules_map: dict[str, dict[str, Any]] = {}
        driver = run.get("tool", {}).get("driver", {})
        rule_list = driver.get("rules", [])
        for r in rule_list:
            rules_map[r.get("id", "")] = r

        results = run.get("results", [])
        for res in results:
            rule_id = res.get("ruleId", "")
            rule_meta = rules_map.get(rule_id, {})
            msg = res.get("message", {}).get("text", "") or rule_meta.get("shortDescription", {}).get("text", "")

            # Location extraction
            locs = res.get("locations", [])
            file_path = ""
            start_line = None
            end_line = None
            if locs:
                phys = locs[0].get("physicalLocation", {})
                file_path = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                start_line = region.get("startLine")
                end_line = region.get("endLine", start_line)

            # Severity mapping
            level = res.get("level", "warning").lower()
            severity = "high" if level in ("error", "critical") else ("medium" if level in ("warning", "warn") else "low")

            # CWE extraction
            cwe = None
            for tag in rule_meta.get("properties", {}).get("tags", []):
                if "cwe" in tag.lower():
                    cwe = tag
                    break

            raw = {
                "finding_id": res.get("id"),
                "vulnerability_type": rule_meta.get("name", rule_id) or "Vulnerability",
                "cwe": cwe or rule_id,
                "severity": severity,
                "confidence": 0.85,
                "file": file_path,
                "start_line": start_line,
                "end_line": end_line,
                "description": msg or "SARIF vulnerability detection",
                "evidence": msg,
                "attack_scenario": "Potentially exploitable security flaw",
                "recommendation": "Review and remediate according to security guidelines",
            }

            try:
                finding = normalize_raw_finding(
                    raw=raw,
                    experiment_id=experiment_id,
                    webgoat_root=webgoat_root,
                    tool=driver.get("name", tool_name),
                    harness_version="v1.0",
                    model=model_name,
                    prompt_version="sarif-import-v1.0",
                )
                findings.append(finding)
            except FindingSchemaError as exc:
                print(f"Warning: failed to normalize SARIF result: {exc}", file=sys.stderr)

    return findings


def convert_generic_json_to_findings(
    payload: list[dict[str, Any]] | dict[str, Any],
    experiment_id: str = "exp-converted",
    webgoat_root: str = "webgoat/WebGoat-2025.3",
) -> list[Finding]:
    """Convert generic JSON array or object containing findings into Finding instances."""
    items = payload if isinstance(payload, list) else payload.get("findings", [payload])
    findings: list[Finding] = []

    for raw in items:
        if not isinstance(raw, dict):
            continue
        try:
            finding = normalize_raw_finding(
                raw=raw,
                experiment_id=experiment_id,
                webgoat_root=webgoat_root,
                tool=raw.get("tool", "json-tool"),
                harness_version="v1.0",
                model=raw.get("model", "gemini-2.5-flash"),
                prompt_version=raw.get("prompt_version", "json-import-v1.0"),
            )
            findings.append(finding)
        except FindingSchemaError as exc:
            print(f"Warning: failed to normalize JSON item: {exc}", file=sys.stderr)

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert SARIF/JSON into canonical findings JSONL (Micro-task 8.1)")
    parser.add_argument("--input", "-i", required=True, help="Input SARIF or JSON file path")
    parser.add_argument("--format", "-f", choices=["sarif", "json"], default="sarif", help="Input format")
    parser.add_argument("--output", "-o", required=True, help="Output findings JSONL file path")
    parser.add_argument("--experiment-id", "-e", default="exp-converted", help="Experiment ID")
    parser.add_argument("--webgoat-root", default="webgoat/WebGoat-2025.3", help="WebGoat root directory")

    args = parser.parse_args()
    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        print(f"Error: input file '{in_path}' does not exist", file=sys.stderr)
        sys.exit(1)

    content = in_path.read_text(encoding="utf-8")
    payload = json.loads(content)

    if args.format == "sarif":
        findings = convert_sarif_to_findings(payload, args.experiment_id, args.webgoat_root)
    else:
        findings = convert_generic_json_to_findings(payload, args.experiment_id, args.webgoat_root)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(f.to_dict(), ensure_ascii=False) for f in findings]
    out_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    print(f"✅ Converted {len(findings)} finding(s) from {in_path} -> {out_path}")


if __name__ == "__main__":
    main()
