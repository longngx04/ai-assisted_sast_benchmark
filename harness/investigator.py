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


_CATEGORY_RESOURCES: dict[str, tuple[str, tuple[str, ...]]] = {
    "database": ("sqli", ("sqli",)),
    "html_template": ("xss", ("xss",)),
    "command_execution": ("command-injection", ("command-injection",)),
    "file_handling": ("path-traversal", ("path-traversal",)),
    "xml_parsing": ("xxe", ("xxe",)),
    "deserialization": ("deserialization", ("deserialization",)),
    "http_client": ("ssrf", ("ssrf",)),
    "authorization": ("access-control", ("access-control",)),
    "authentication": ("baseline", ("authentication",)),
    "session": ("baseline", ("authentication",)),
    "business_logic": ("baseline", ("business-logic",)),
}


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
        skills_dir: str | Path = "skills",
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
        self.skills_dir = Path(skills_dir).resolve()
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
        prompt_template, prompt_version = self._load_analysis_resources(
            category, use_specific_prompts
        )

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
            "file": file_path,
            "line": line_num,
            "snippet": candidate.get("snippet", ""),
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
                raw_item = dict(raw_item)
                raw_item.setdefault("file", file_path)
                raw_item.setdefault("start_line", line_num)
                checked = self._verify_evidence(raw_item)
                if checked is None:
                    logger.warning(
                        "Discarding model finding for %s: required fields or source evidence do not match",
                        cand_id,
                    )
                    continue
                finding = normalize_raw_finding(
                    raw=checked,
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

    def _load_analysis_resources(
        self, category: str, use_specific_prompts: bool
    ) -> tuple[str, str]:
        if not use_specific_prompts:
            return self._load_prompt("baseline"), "baseline-audit-v1.0"

        prompt_name, skill_names = _CATEGORY_RESOURCES.get(
            category, ("baseline", ())
        )
        sections = [self._load_prompt(prompt_name)]
        for skill_name in skill_names:
            skill_path = self.skills_dir / skill_name / "SKILL.md"
            if skill_path.is_file():
                sections.append(
                    f"\n=== SECURITY SKILL: {skill_name} ===\n"
                    + skill_path.read_text(encoding="utf-8")
                )
        return "\n".join(sections), f"{prompt_name}-v1.0"

    def _verify_evidence(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        required_text = ("description", "evidence", "attack_scenario", "recommendation")
        if any(not str(raw.get(field, "")).strip() for field in required_text):
            return None
        if not str(raw.get("sink", "")).strip():
            return None
        cwe = str(raw.get("cwe", "")).upper()
        access_control = cwe in {"CWE-284", "CWE-639", "CWE-862"}
        if not access_control and not str(raw.get("source", "")).strip():
            return None
        data_flow = raw.get("data_flow")
        if not access_control and not (
            isinstance(data_flow, list) and any(str(step).strip() for step in data_flow)
        ):
            return None

        relative = Path(str(raw.get("file", "")))
        if relative.is_absolute() or ".." in relative.parts:
            return None
        source_file = (self.webgoat_root / relative).resolve()
        try:
            source_file.relative_to(self.webgoat_root)
        except ValueError:
            return None
        if not source_file.is_file():
            return None

        content = source_file.read_text(encoding="utf-8", errors="replace")
        evidence = str(raw["evidence"]).strip()
        offset = content.find(evidence)
        if offset < 0:
            return None
        evidence_line = content.count("\n", 0, offset) + 1
        checked = dict(raw)
        checked["file"] = relative.as_posix()
        checked["start_line"] = evidence_line
        checked["end_line"] = evidence_line + evidence.count("\n")
        return checked
