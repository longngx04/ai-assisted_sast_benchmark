"""End-to-end SAST Benchmark Harness Runner (Phase 12).

Orchestrates all pipeline phases from reconnaissance to metrics summary.
Supports both real Gemini model API execution and offline mock execution.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import yaml
from dataclasses import asdict
from pathlib import Path
from typing import Any

from harness.candidate_finder import CandidateFinder, run_candidate_discovery
from harness.context_builder import ContextBuilder
from harness.deduplicator import Deduplicator
from harness.exclusions import ExclusionPolicy
from harness.ground_truth import GroundTruthManager
from harness.indexer import JavaIndexer, run_indexing
from harness.investigator import InvestigationAgent
from harness.metrics import MetricsCalculator, PhaseTimer
from harness.model_client import ModelClient
from harness.repository import RepositoryScanner
from harness.validator import IndependentValidator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("harness.runner")


class BenchmarkRunner:
    """End-to-end SAST Benchmark Orchestrator."""

    def __init__(
        self,
        config_path: str | Path | None = None,
        source_root: str | Path = "webgoat/WebGoat-2025.3",
        results_dir: str | Path = "results",
        experiment_id: str = "exp-d-optimized",
        model: str = "mock",
        exclusions_config: str | Path = "configs/exclusions.json",
    ) -> None:
        self.config = self._load_config(config_path) if config_path else {}
        self.source_root = Path(source_root if source_root != "webgoat/WebGoat-2025.3" else self.config.get("source_root", source_root)).resolve()
        self.results_dir = Path(results_dir if results_dir != "results" else self.config.get("results_dir", results_dir)).resolve()
        self.experiment_id = experiment_id if experiment_id != "exp-d-optimized" else self.config.get("experiment_id", experiment_id)
        self.model = model or self.config.get("model", "mock")
        self.exclusions_config = Path(exclusions_config if exclusions_config != "configs/exclusions.json" else self.config.get("exclusions_config", exclusions_config)).resolve()
        self.harness_name = self.config.get("harness_name", "agentic-harness")

        self.policy = ExclusionPolicy.from_file(self.exclusions_config) if self.exclusions_config.exists() else None
        self.timer = PhaseTimer()

    def run(self) -> dict[str, Any]:
        """Execute all benchmark pipeline phases."""
        logger.info(f"Starting SAST Benchmark experiment '{self.experiment_id}' on {self.source_root}")
        exp_dir = self.results_dir / self.experiment_id
        exp_dir.mkdir(parents=True, exist_ok=True)

        # 1. Reconnaissance
        self.timer.start_phase("reconnaissance")
        logger.info("Phase 1: Repository Reconnaissance...")
        repo_scanner = RepositoryScanner(self.source_root, exclusion_policy=self.policy)
        recon_result = repo_scanner.scan()
        repo_scanner.save(recon_result, exp_dir)
        self.timer.end_phase("reconnaissance")

        # 2. Indexing
        self.timer.start_phase("indexing")
        logger.info("Phase 2: Java Symbol Indexing...")
        indexer = JavaIndexer(self.source_root, exclusion_policy=self.policy)
        index = indexer.build()
        indexer.save(index, exp_dir)
        self.timer.end_phase("indexing")

        # 3. Candidate Discovery
        self.timer.start_phase("candidate_discovery")
        logger.info("Phase 3: Candidate Discovery...")
        cand_finder = CandidateFinder(self.source_root, index=index, exclusion_policy=self.policy)
        cands = cand_finder.scan()
        cand_dicts = [c.to_dict() for c in cands]
        cands_file = exp_dir / "candidates.jsonl"
        cands_file.write_text("\n".join(json.dumps(cd, ensure_ascii=False) for cd in cand_dicts) + "\n", encoding="utf-8")
        self.timer.end_phase("candidate_discovery")

        # 4. LLM Investigation
        self.timer.start_phase("investigation")
        logger.info("Phase 4: LLM Investigation...")
        client = ModelClient(default_model=self.model, results_dir=self.results_dir)
        recon_dict = asdict(recon_result)
        investigator = InvestigationAgent(
            webgoat_root=self.source_root,
            index=index,
            client=client,
            recon=recon_dict,
        )

        raw_findings = investigator.investigate_batch(
            candidates=cand_dicts,
            experiment_id=self.experiment_id,
            model=self.model,
            use_specific_prompts=self.config.get("use_vulnerability_prompts", True),
        )
        raw_file = exp_dir / "raw_findings.jsonl"
        raw_file.write_text("\n".join(json.dumps(f.to_dict(), ensure_ascii=False) for f in raw_findings) + "\n", encoding="utf-8")
        self.timer.end_phase("investigation")

        # 5. Independent Validation
        self.timer.start_phase("validation")
        logger.info("Phase 5: Independent Validation...")
        validator = IndependentValidator(
            webgoat_root=self.source_root,
            index=index,
            client=client,
        )
        if self.config.get("use_independent_validation", True):
            validated_findings = validator.validate_batch(
                findings=raw_findings,
                experiment_id=self.experiment_id,
                model=self.model,
            )
        else:
            validated_findings = raw_findings

        validator.partition_and_save_findings(validated_findings, self.results_dir, self.experiment_id)
        self.timer.end_phase("validation")

        # 6. Deduplication
        self.timer.start_phase("deduplication")
        logger.info("Phase 6: Deduplication...")
        dedup = Deduplicator()
        canonical_findings, duplicate_findings = dedup.deduplicate(validated_findings)
        dedup.process_and_save(validated_findings, self.results_dir, self.experiment_id)
        self.timer.end_phase("deduplication")

        # 7. Ground Truth Evaluation
        self.timer.start_phase("ground_truth_eval")
        gt_manager = GroundTruthManager()
        if not gt_manager.entries:
            gt_manager.build_webgoat_ground_truth(self.source_root)
        gt_eval = gt_manager.evaluate_findings(canonical_findings)
        self.timer.end_phase("ground_truth_eval")

        # 8. Metrics & Reporting
        self.timer.start_phase("reporting")
        logger.info("Phase 7: Calculating Metrics...")
        calc = MetricsCalculator(exp_dir)
        metrics = calc.calculate_metrics(
            experiment_id=self.experiment_id,
            model=self.model,
            harness_name=self.harness_name,
            timer=self.timer,
            findings=canonical_findings,
            duplicates=duplicate_findings,
            gt_eval=gt_eval,
            revision=recon_result.revision,
        )
        self.timer.end_phase("reporting")

        logger.info(f"Experiment '{self.experiment_id}' completed in {metrics['runtime_seconds']}s")
        logger.info(f"Unique Findings: {metrics['unique_findings']} | Validated: {metrics['validated_findings']} | Precision: {metrics['estimated_precision']}")

        return metrics

    def _load_config(self, path: str | Path) -> dict[str, Any]:
        p = Path(path)
        if not p.exists():
            return {}
        try:
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.warning(f"Error loading config yaml {p}: {exc}")
            return {}


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-End SAST Benchmark Harness Runner (Phase 12)")
    parser.add_argument("--config", "-c", help="Path to config YAML")
    parser.add_argument("--source", "-s", default="webgoat/WebGoat-2025.3", help="WebGoat source root")
    parser.add_argument("--output", "-o", default="results", help="Output results directory")
    parser.add_argument("--experiment-id", "-e", default="exp-d-optimized", help="Experiment ID")
    parser.add_argument("--model", "-m", default="mock", help="Model name (gemini-2.5-flash or mock)")

    args = parser.parse_args()
    runner = BenchmarkRunner(
        config_path=args.config,
        source_root=args.source,
        results_dir=args.output,
        experiment_id=args.experiment_id,
        model=args.model,
    )
    runner.run()


if __name__ == "__main__":
    main()
