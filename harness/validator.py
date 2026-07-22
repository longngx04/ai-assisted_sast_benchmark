"""Independent finding validator engine and validation output partitioning.

Micro-tasks 6.2 & 6.3:
  * 6.2: Independent validator re-evaluating findings against source context, caller/callee chains, and attack scenarios.
  * 6.3: Partition findings into validated_findings.jsonl, rejected_findings.jsonl, and uncertain_findings.jsonl.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from harness.context_builder import ContextBuilder
from harness.indexer import JavaIndexer, JavaSymbolIndex
from harness.model_client import ModelClient
from harness.schemas import (
    Finding,
    ValidationContext,
    ValidationDecision,
    ValidationResult,
    ValidationStatus,
)

logger = logging.getLogger(__name__)


class IndependentValidator:
    """Independent validator engine re-evaluating findings.

    Parameters
    ----------
    webgoat_root : str | Path
        Path to WebGoat source root.
    index : JavaSymbolIndex
        Symbol index instance.
    client : ModelClient
        Model client instance.
    prompts_dir : str | Path
        Path to prompts directory.
    """

    def __init__(
        self,
        webgoat_root: str | Path,
        index: JavaSymbolIndex,
        client: ModelClient,
        prompts_dir: str | Path = "prompts",
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        use_cache: bool = True,
    ) -> None:
        self.webgoat_root = Path(webgoat_root).resolve()
        self.index = index
        self.client = client
        self.prompts_dir = Path(prompts_dir).resolve()
        self.context_builder = ContextBuilder(webgoat_root, index)
        self.validator_prompt = self._load_prompt("validation.md")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.use_cache = use_cache

    def validate_finding(
        self,
        finding: Finding,
        experiment_id: str = "exp-d-optimized",
        validator_name: str = "independent-judge",
        model: str | None = None,
    ) -> tuple[Finding, ValidationResult]:
        """Validate a single finding and return (updated_finding, validation_result)."""
        # Build context for validation
        ctx = self.context_builder.build_context(
            candidate_id=finding.finding_id,
            file=finding.file,
            line=finding.start_line,
            symbol=finding.function,
            category=finding.vulnerability_type,
        )

        val_context = ValidationContext(
            finding=finding,
            code_context=ctx.to_prompt_text(),
            caller_callee_info=finding.data_flow,
            security_assumptions=["Application accepts untrusted HTTP input"],
            attack_scenario=finding.attack_scenario,
        )

        full_prompt = (
            f"{self.validator_prompt}\n\n"
            f"=== FINDING TO VALIDATE ===\n"
            f"{json.dumps(finding.to_dict(), indent=2)}\n\n"
            f"=== CODE CONTEXT ===\n"
            f"{val_context.code_context}\n"
        )

        meta = {
            "finding_id": finding.finding_id,
            "prompt_version": "validation-v1.0",
            "analysis_type": "validation",
        }

        res = self.client.analyze(
            prompt=full_prompt,
            model=model,
            experiment_id=experiment_id,
            phase="validation",
            agent="validator",
            metadata=meta,
            timeout_seconds=self.timeout_seconds,
            max_retries=self.max_retries,
            use_cache=self.use_cache,
        )

        val_result = self._parse_validation_result(res.parsed_json, res.raw_response)
        updated_finding = val_result.apply_to_finding(finding, validator_name)
        return updated_finding, val_result

    def validate_batch(
        self,
        findings: list[Finding],
        experiment_id: str = "exp-d-optimized",
        validator_name: str = "independent-judge",
        model: str | None = None,
        concurrency: int = 1,
    ) -> list[Finding]:
        """Validate a list of findings and return updated findings."""
        updated: list[Finding] = []
        def validate(f: Finding) -> Finding:
            upd_finding, _ = self.validate_finding(
                finding=f,
                experiment_id=experiment_id,
                validator_name=validator_name,
                model=model,
            )
            return upd_finding

        worker_count = max(1, int(concurrency))
        if worker_count == 1:
            return [validate(f) for f in findings]
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            updated.extend(executor.map(validate, findings))
        return updated

    def partition_and_save_findings(
        self,
        findings: list[Finding],
        output_dir: str | Path,
        experiment_id: str = "exp-d-optimized",
    ) -> dict[str, Path]:
        """Save findings partitioned by validation status into JSONL files (Task 6.3).

        Generates:
          * results/<experiment-id>/validated_findings.jsonl
          * results/<experiment-id>/rejected_findings.jsonl
          * results/<experiment-id>/uncertain_findings.jsonl
        """
        exp_dir = Path(output_dir) / experiment_id
        exp_dir.mkdir(parents=True, exist_ok=True)

        validated: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        uncertain: list[dict[str, Any]] = []

        for f in findings:
            d = f.to_dict()
            if f.validation_status == ValidationStatus.VALIDATED:
                validated.append(d)
            elif f.validation_status == ValidationStatus.REJECTED:
                rejected.append(d)
            else:
                uncertain.append(d)

        paths = {
            "validated": exp_dir / "validated_findings.jsonl",
            "rejected": exp_dir / "rejected_findings.jsonl",
            "uncertain": exp_dir / "uncertain_findings.jsonl",
        }

        for key, p in paths.items():
            records = validated if key == "validated" else (rejected if key == "rejected" else uncertain)
            lines = [json.dumps(r, ensure_ascii=False) for r in records]
            p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

        return paths

    def _parse_validation_result(self, parsed_json: Any, raw_response: str) -> ValidationResult:
        if isinstance(parsed_json, dict) and "status" in parsed_json:
            try:
                status_str = str(parsed_json.get("status", "uncertain")).lower()
                if status_str not in ("validated", "rejected", "uncertain"):
                    status_str = "uncertain"
                return ValidationResult(
                    status=ValidationDecision(status_str),
                    confidence=float(parsed_json.get("confidence", 0.5)),
                    reason=str(parsed_json.get("reason", "Validation parsed successfully")),
                    missing_evidence=parsed_json.get("missing_evidence", []),
                    recommended_manual_check=str(parsed_json.get("recommended_manual_check", "")),
                )
            except Exception as exc:
                logger.warning(f"Error parsing validation JSON: {exc}")

        # Fallback heuristic if JSON parsing fails
        if "validated" in raw_response.lower() and "rejected" not in raw_response.lower():
            return ValidationResult(
                status=ValidationDecision.VALIDATED,
                confidence=0.8,
                reason="Validator text indicates validation",
                missing_evidence=[],
                recommended_manual_check="",
            )
        elif "rejected" in raw_response.lower():
            return ValidationResult(
                status=ValidationDecision.REJECTED,
                confidence=0.8,
                reason="Validator text indicates rejection",
                missing_evidence=[],
                recommended_manual_check="",
            )
        else:
            return ValidationResult(
                status=ValidationDecision.UNCERTAIN,
                confidence=0.5,
                reason="Validator response unparseable or uncertain",
                missing_evidence=["Clear validation rationale"],
                recommended_manual_check="Manual security review required",
            )

    def _load_prompt(self, filename: str) -> str:
        p_path = self.prompts_dir / filename
        if p_path.exists():
            return p_path.read_text(encoding="utf-8")
        return "Re-evaluate the security finding based on provided code context."
