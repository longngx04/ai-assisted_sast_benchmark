"""Vulnerability investigation workflow (Micro-task 6.1).

Coordinates candidate processing:
  candidate -> context retrieval -> vulnerability-specific prompt -> model response -> schema normalization -> unvalidated finding
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from harness.context_builder import ContextBuilder, ContextConfig
from harness.indexer import JavaSymbolIndex
from harness.model_client import ModelClient
from harness.normalizer import normalize_raw_finding
from harness.schemas import Finding, ValidationStatus

logger = logging.getLogger(__name__)


class InvestigationAgent:
    """Coordinates context retrieval, prompt selection, model calls, and finding normalization for candidates.

    Parameters
    ----------
    webgoat_root : str | Path
        Path to WebGoat source root.
    index : JavaSymbolIndex
        Symbol index instance.
    client : ModelClient
        Model client instance.
    recon : dict | None
        Reconnaissance result dict.
    prompts_dir : str | Path
        Path to prompts directory.
    """

    def __init__(
        self,
        webgoat_root: str | Path,
        index: JavaSymbolIndex,
        client: ModelClient,
        recon: dict[str, Any] | None = None,
        prompts_dir: str | Path = "prompts",
        context_config: ContextConfig | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        use_cache: bool = True,
    ) -> None:
        self.webgoat_root = Path(webgoat_root).resolve()
        self.index = index
        self.client = client
        self.recon = recon or {}
        self.prompts_dir = Path(prompts_dir).resolve()
        self.context_builder = ContextBuilder(
            webgoat_root, index, recon=recon, config=context_config
        )
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.use_cache = use_cache
        self._prompt_cache: dict[str, str] = {}

    def investigate_candidate(
        self,
        candidate: dict[str, Any],
        experiment_id: str = "exp-d-optimized",
        model: str | None = None,
        use_specific_prompts: bool = True,
    ) -> list[Finding]:
        """Investigate a candidate and return normalized findings."""
        cand_id = candidate.get("candidate_id", "CAND-000")
        file_path = candidate.get("file", "")
        line_num = candidate.get("line")
        symbol = candidate.get("symbol")
        category = candidate.get("category", "")

        # Skip candidates marked as rejected by prefilter
        if candidate.get("is_rejected"):
            logger.info(f"Skipping candidate {cand_id}: marked as rejected by prefilter")
            return []

        # 1. Context retrieval
        ctx = self.context_builder.build_context(
            candidate_id=cand_id,
            file=file_path,
            line=line_num,
            symbol=symbol,
            category=category,
        )

        # 2. Select prompt
        prompt_name = "sqli" if category == "database" else category
        prompt_template = self._load_prompt(prompt_name if use_specific_prompts else "baseline")
        prompt_version = f"{prompt_name}-v1.0"

        full_prompt = (
            f"{prompt_template}\n\n"
            f"Candidate ID: {cand_id}\n"
            f"Target File: {file_path}:{line_num}\n\n"
            f"=== CODE CONTEXT ===\n"
            f"{ctx.to_prompt_text()}\n"
        )

        # 3. Model call
        meta = {
            "candidate_id": cand_id,
            "category": category,
            "prompt_version": prompt_version,
            "analysis_type": "investigation",
            "context_hash": str(ctx.total_chars),
        }
        res = self.client.analyze(
            prompt=full_prompt,
            model=model,
            experiment_id=experiment_id,
            phase="investigation",
            agent="investigator",
            metadata=meta,
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            use_cache=self.use_cache,
        )

        # 4. Schema normalization
        if res.error or res.parsed_json is None:
            logger.warning(f"Malformed or errored model response for candidate {cand_id}: {res.error}")
            return []

        raw_findings = res.parsed_json if isinstance(res.parsed_json, list) else [res.parsed_json]
        findings: list[Finding] = []

        for raw_item in raw_findings:
            if not isinstance(raw_item, dict):
                continue
            # Check if model marked as not vulnerable
            if raw_item.get("is_vulnerable") is False:
                continue

            try:
                if "file" not in raw_item or not raw_item["file"]:
                    raw_item["file"] = file_path
                if "start_line" not in raw_item or raw_item["start_line"] is None:
                    raw_item["start_line"] = line_num
                finding = normalize_raw_finding(
                    raw=raw_item,
                    experiment_id=experiment_id,
                    webgoat_root=str(self.webgoat_root),
                    tool="ai-assisted-sast",
                    harness_version="v1.0",
                    model=res.model,
                    prompt_version=prompt_version,
                )
                findings.append(finding)
            except Exception as exc:
                logger.error(f"Normalization failed for candidate {cand_id}: {exc}")

        return findings

    def investigate_batch(
        self,
        candidates: list[dict[str, Any]],
        experiment_id: str = "exp-d-optimized",
        model: str | None = None,
        use_specific_prompts: bool = True,
        concurrency: int = 1,
    ) -> list[Finding]:
        """Investigate a batch of candidates."""
        all_findings: list[Finding] = []
        def investigate(cand: dict[str, Any]) -> list[Finding]:
            return self.investigate_candidate(
                candidate=cand,
                experiment_id=experiment_id,
                model=model,
                use_specific_prompts=use_specific_prompts,
            )

        worker_count = max(1, int(concurrency))
        if worker_count == 1:
            batches = map(investigate, candidates)
        else:
            executor = ThreadPoolExecutor(max_workers=worker_count)
            batches = executor.map(investigate, candidates)
        try:
            for findings in batches:
                all_findings.extend(findings)
        finally:
            if worker_count > 1:
                executor.shutdown(wait=True)
        return all_findings

    def _load_prompt(self, name: str) -> str:
        if name in self._prompt_cache:
            return self._prompt_cache[name]
        p_path = self.prompts_dir / f"{name}.md"
        if not p_path.exists():
            p_path = self.prompts_dir / "baseline.md"
        content = p_path.read_text(encoding="utf-8") if p_path.exists() else "Audit this code for security vulnerabilities."
        self._prompt_cache[name] = content
        return content
