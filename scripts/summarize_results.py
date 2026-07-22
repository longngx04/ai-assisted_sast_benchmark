#!/usr/bin/env python3
"""CLI script to summarize metrics for one or all experiment directories."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def summarize_experiment(exp_dir: Path) -> dict | None:
    metrics_file = exp_dir / "metrics.json"
    if not metrics_file.exists():
        return None
    try:
        return json.loads(metrics_file.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> None:
    target_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    exp_dirs: list[Path] = []

    if target_path.is_file():
        target_path = target_path.parent

    if (target_path / "metrics.json").exists():
        exp_dirs = [target_path]
    else:
        exp_dirs = [d for d in target_path.iterdir() if d.is_dir() and (d / "metrics.json").exists()]

    if not exp_dirs:
        print(f"No experiment metrics found in '{target_path}'")
        sys.exit(0)

    print("=========================================================================================")
    print(f"{'Experiment':<20} | {'Harness':<18} | {'Unique':<6} | {'Validated':<9} | {'TP':<4} | {'FP':<4} | {'Precision':<9} | {'Time(s)':<7}")
    print("=========================================================================================")

    for exp_dir in sorted(exp_dirs):
        m = summarize_experiment(exp_dir)
        if not m:
            continue
        exp_id = m.get("experiment_id", exp_dir.name)
        harness = m.get("harness", "unknown")
        unique = m.get("unique_findings", 0)
        val = m.get("validated_findings", 0)
        tp = m.get("true_positives", 0)
        fp = m.get("false_positives", 0)
        prec = m.get("estimated_precision", 0.0)
        t_sec = m.get("runtime_seconds", 0.0)

        print(f"{exp_id:<20} | {harness:<18} | {unique:<6} | {val:<9} | {tp:<4} | {fp:<4} | {prec:<9.3f} | {t_sec:<7.1f}")

    print("=========================================================================================")


if __name__ == "__main__":
    main()
