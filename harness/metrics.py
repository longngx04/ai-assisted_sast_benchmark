"""Metrics collector and benchmark metrics calculator (Phase 11).

Micro-tasks 11.1 & 11.2:
  * 11.1: Phase timing using monotonic clock.
  * 11.2: Metrics aggregation and calculation exported to results/<experiment-id>/metrics.json.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.schemas import Finding, ValidationStatus

logger = logging.getLogger(__name__)


@dataclass
class PhaseTimer:
    """Monotonic timer tracking phase execution durations."""
    phase_durations: dict[str, float] = field(default_factory=dict)
    _start_times: dict[str, float] = field(default_factory=dict)
    _total_start: float = field(default_factory=time.monotonic)

    def start_phase(self, phase_name: str) -> None:
        self._start_times[phase_name] = time.monotonic()

    def end_phase(self, phase_name: str) -> float:
        if phase_name in self._start_times:
            elapsed = round(time.monotonic() - self._start_times[phase_name], 3)
            self.phase_durations[phase_name] = elapsed
            return elapsed
        return 0.0

    def total_duration(self) -> float:
        return round(time.monotonic() - self._total_start, 3)


class MetricsCalculator:
    """Calculates quantitative benchmark metrics for an experiment."""

    def __init__(self, experiment_dir: str | Path) -> None:
        self.exp_dir = Path(experiment_dir).resolve()

    def calculate_metrics(
        self,
        experiment_id: str,
        model: str,
        harness_name: str,
        timer: PhaseTimer,
        findings: list[Finding],
        duplicates: list[Finding],
        gt_eval: dict[str, Any] | None = None,
        revision: str | None = None,
    ) -> dict[str, Any]:
        """Aggregate usage logs and calculate complete metrics dictionary."""
        # Load LLM usage log
        usage_file = self.exp_dir / "llm_usage.jsonl"
        llm_calls = 0
        input_tokens = 0
        output_tokens = 0
        total_tokens = 0
        cached_calls = 0
        retries_total = 0
        latencies: list[float] = []
        meas_types: set[str] = set()

        if usage_file.exists():
            for line in usage_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    llm_calls += 1
                    input_tokens += entry.get("input_tokens", 0)
                    output_tokens += entry.get("output_tokens", 0)
                    total_tokens += entry.get("total_tokens", 0)
                    if entry.get("is_cached"):
                        cached_calls += 1
                    retries_total += entry.get("retry_count", 0)
                    latencies.append(entry.get("latency_seconds", 0.0))
                    meas_types.add(entry.get("token_measurement", "character_estimate"))
                except Exception:
                    pass

        raw_count = len(findings) + len(duplicates)
        dup_count = len(duplicates)
        unique_count = len(findings)

        val_count = sum(1 for f in findings if f.validation_status == ValidationStatus.VALIDATED)
        rej_count = sum(1 for f in findings if f.validation_status == ValidationStatus.REJECTED)
        unc_count = sum(1 for f in findings if f.validation_status == ValidationStatus.UNCERTAIN)

        tp_count = gt_eval.get("true_positives", val_count) if gt_eval else val_count
        fp_count = gt_eval.get("false_positives", rej_count) if gt_eval else rej_count

        precision = gt_eval.get("estimated_precision") if gt_eval else (
            round(tp_count / (tp_count + fp_count), 4) if (tp_count + fp_count) > 0 else 0.0
        )

        total_runtime = timer.total_duration()
        findings_per_min = round(unique_count / (total_runtime / 60.0), 2) if total_runtime > 0 else 0.0
        val_per_100k = round((val_count / total_tokens) * 100_000, 2) if total_tokens > 0 else 0.0
        tp_per_100k = round((tp_count / total_tokens) * 100_000, 2) if total_tokens > 0 else 0.0

        dup_rate = round(dup_count / raw_count, 4) if raw_count > 0 else 0.0
        rej_rate = round(rej_count / unique_count, 4) if unique_count > 0 else 0.0
        retry_rate = round(retries_total / llm_calls, 4) if llm_calls > 0 else 0.0
        avg_latency = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
        cache_hit_rate = round(cached_calls / llm_calls, 4) if llm_calls > 0 else 0.0

        measurement_str = ", ".join(sorted(meas_types)) if meas_types else "character_estimate"

        metrics = {
            "repository": "WebGoat",
            "repository_commit": revision or "2025.3",
            "experiment_id": experiment_id,
            "model": model,
            "harness": harness_name,
            "runtime_seconds": total_runtime,
            "phase_durations": timer.phase_durations,
            "llm_calls": llm_calls,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "token_measurement": measurement_str,
            "raw_findings": raw_count,
            "duplicates": dup_count,
            "unique_findings": unique_count,
            "validated_findings": val_count,
            "true_positives": tp_count,
            "false_positives": fp_count,
            "uncertain": unc_count,
            "estimated_precision": precision,
            "precision_type": gt_eval.get("precision_type", "validator_estimate") if gt_eval else "validator_estimate",
            "ground_truth_complete": gt_eval.get("ground_truth_complete", False) if gt_eval else False,
            "reviewed_ground_truth_entries": gt_eval.get("reviewed_ground_truth_entries", 0) if gt_eval else 0,
            "findings_per_minute": findings_per_min,
            "validated_findings_per_100k_tokens": val_per_100k,
            "true_positives_per_100k_tokens": tp_per_100k,
            "duplicate_rate": dup_rate,
            "rejection_rate": rej_rate,
            "retry_rate": retry_rate,
            "average_latency_seconds": avg_latency,
            "cache_hit_rate": cache_hit_rate,
        }

        # Save metrics.json
        out_file = self.exp_dir / "metrics.json"
        out_file.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return metrics
