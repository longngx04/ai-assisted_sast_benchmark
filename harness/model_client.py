"""Provider adapter and usage instrumentation for Gemini and Mock models.

Micro-tasks 5.1 & 5.2:
  * 5.1: Configurable model client (Gemini 2.5 Flash / Mock) with retry, backoff, and raw output storage.
  * 5.2: Instrumentation logging token counts and latency to results/<experiment-id>/llm_usage.jsonl.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import threading
import uuid
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from harness.cache import ModelCache


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class TokenUsage:
    """Usage stats for a single LLM invocation."""
    input_tokens: int
    output_tokens: int
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    total_tokens: int = 0
    measurement_type: str = "character_estimate"  # provider | tokenizer_estimate | character_estimate | mock

    def __post_init__(self) -> None:
        if self.total_tokens == 0:
            self.total_tokens = self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelResponse:
    """Standardized response from the model client."""
    request_id: str
    model: str
    experiment_id: str
    phase: str
    agent: str
    raw_response: str
    parsed_json: dict[str, Any] | list[Any] | None
    usage: TokenUsage
    latency_seconds: float
    retry_count: int
    is_cached: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["usage"] = self.usage.to_dict()
        return d


# ---------------------------------------------------------------------------
# Model Client Implementation
# ---------------------------------------------------------------------------

class ModelClient:
    """Unified Model Client supporting Gemini and Mock providers with caching and instrumentation.

    Parameters
    ----------
    default_model : str
        Default model identifier (e.g. "gemini-2.5-flash", "mock").
    results_dir : str | Path
        Root directory for results and instrumentation logs.
    cache_dir : str | Path | None
        Directory for file-based response caching.
    """

    def __init__(
        self,
        default_model: str = "gemini-2.5-flash",
        results_dir: str | Path = "results",
        cache_dir: str | Path | None = ".cache/model_cache",
    ) -> None:
        self.default_model = default_model
        self.results_dir = Path(results_dir).resolve()
        self.cache = ModelCache(cache_dir) if cache_dir else None
        self._usage_lock = threading.Lock()

    # -- Public API ----------------------------------------------------------

    def analyze(
        self,
        prompt: str,
        model: str | None = None,
        experiment_id: str = "exp-d-optimized",
        phase: str = "investigation",
        agent: str = "primary",
        metadata: dict[str, Any] | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        use_cache: bool = True,
    ) -> ModelResponse:
        """Execute a model analysis request.

        Parameters
        ----------
        prompt : str
            Full rendered prompt string.
        model : str | None
            Model name. Defaults to self.default_model.
        experiment_id : str
            Experiment ID for log scoping.
        phase : str
            Pipeline phase (e.g. "reconnaissance", "investigation", "validation").
        agent : str
            Agent identifier.
        metadata : dict | None
            Arbitrary metadata attached to the request.
        timeout_seconds : float
            Timeout cap per call.
        max_retries : int
            Maximum retry attempts.
        use_cache : bool
            Whether to consult/populate response cache.

        Returns
        -------
        ModelResponse
        """
        model_name = model or self.default_model
        meta = metadata or {}
        req_id = f"req-{uuid.uuid4().hex[:8]}"

        # 1. Cache lookup
        prompt_version = meta.get("prompt_version", "v1.0")
        analysis_type = meta.get("analysis_type", phase)
        source_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        cache_key = ModelCache.generate_cache_key(
            source_hash=source_hash,
            prompt_version=prompt_version,
            model=model_name,
            analysis_type=analysis_type,
            context_hash=meta.get("context_hash", ""),
        )

        if use_cache and self.cache:
            cached_entry = self.cache.get(cache_key)
            if cached_entry:
                usage = TokenUsage(
                    input_tokens=self._estimate_tokens(prompt),
                    output_tokens=self._estimate_tokens(cached_entry.raw_response),
                    cached_tokens=self._estimate_tokens(prompt),
                    measurement_type="tokenizer_estimate",
                )
                res = ModelResponse(
                    request_id=req_id,
                    model=model_name,
                    experiment_id=experiment_id,
                    phase=phase,
                    agent=agent,
                    raw_response=cached_entry.raw_response,
                    parsed_json=cached_entry.parsed_response,
                    usage=usage,
                    latency_seconds=0.001,
                    retry_count=0,
                    is_cached=True,
                )
                self._record_llm_usage(experiment_id, res)
                return res

        # 2. Execution with retry
        start_time = time.monotonic()
        raw_text = ""
        parsed_json = None
        provider_usage: TokenUsage | None = None
        error_msg = None
        retries = 0

        for attempt in range(max_retries + 1):
            retries = attempt
            try:
                if model_name.startswith("mock"):
                    raw_text, parsed_json = self._mock_call(prompt, meta)
                else:
                    raw_text, parsed_json, provider_usage = self._gemini_call(
                        prompt, model_name, timeout_seconds
                    )
                error_msg = None
                break
            except Exception as exc:
                error_msg = str(exc)
                if attempt < max_retries:
                    time.sleep(0.2 * (2 ** attempt))  # Exponential backoff

        latency = round(time.monotonic() - start_time, 3)

        # 3. Token estimation
        if provider_usage is not None:
            usage = provider_usage
        else:
            meas_type = "mock" if model_name.startswith("mock") else "character_estimate"
            usage = TokenUsage(
                input_tokens=self._estimate_tokens(prompt),
                output_tokens=self._estimate_tokens(raw_text),
                measurement_type=meas_type,
            )

        response = ModelResponse(
            request_id=req_id,
            model=model_name,
            experiment_id=experiment_id,
            phase=phase,
            agent=agent,
            raw_response=raw_text,
            parsed_json=parsed_json,
            usage=usage,
            latency_seconds=latency,
            retry_count=retries,
            is_cached=False,
            error=error_msg,
        )

        # 4. Save raw response artifact & record usage log
        self._save_raw_response(experiment_id, req_id, response)
        self._record_llm_usage(experiment_id, response)

        # 5. Populate cache if successful
        if use_cache and self.cache and not error_msg and raw_text:
            self.cache.put(
                cache_key=cache_key,
                model=model_name,
                prompt_version=prompt_version,
                raw_response=raw_text,
                parsed_response=parsed_json,
                metadata=meta,
            )

        return response

    # -- Internal Providers --------------------------------------------------

    def _mock_call(self, prompt: str, meta: dict[str, Any]) -> tuple[str, Any]:
        """Mock provider for offline testing and fixture validation."""
        category = meta.get("category", "")
        analysis_type = meta.get("analysis_type", "")

        if analysis_type == "validation" or "validated|rejected|uncertain" in prompt.lower():
            decision = {
                "status": "validated",
                "confidence": 0.95,
                "reason": "Clear unparameterized SQL concatenation.",
                "missing_evidence": [],
                "recommended_manual_check": "None",
            }
            return json.dumps(decision, indent=2), decision

        if "sqli" in prompt.lower() or category == "database":
            snippet = str(meta.get("snippet", "")).strip()
            finding = [{
                "vulnerability_type": "SQL Injection",
                "cwe": "CWE-89",
                "severity": "high",
                "confidence": 0.92,
                "source": "username parameter",
                "sink": "Statement.executeQuery",
                "data_flow": ["parameter received", "concatenated into SQL"],
                "description": "Untrusted input concatenated into SQL query.",
                "file": meta.get("file"),
                "start_line": meta.get("line"),
                "evidence": snippet,
                "attack_scenario": "Attacker passes `' OR '1'='1`.",
                "security_control": "None",
                "recommendation": "Use PreparedStatement",
            }]
            return json.dumps(finding, indent=2), finding
        else:
            return "[]", []

    def _gemini_call(
        self, prompt: str, model_name: str, timeout: float
    ) -> tuple[str, Any, TokenUsage]:
        """Call the Google Gemini REST API without requiring a provider SDK.

        The API key is sent in the ``x-goog-api-key`` header so it never appears
        in URLs, logs, cache keys, or exception messages.  ``GEMINI_API_BASE_URL``
        may point at an approved proxy; otherwise Google's v1beta endpoint is
        used.
        """
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("Set GEMINI_API_KEY (or GOOGLE_API_KEY) before using Gemini")

        api_base = os.getenv(
            "GEMINI_API_BASE_URL",
            "https://generativelanguage.googleapis.com/v1beta",
        ).rstrip("/")
        encoded_model = urllib.parse.quote(model_name, safe="-._")
        url = f"{api_base}/models/{encoded_model}:generateContent"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.0,
                "responseMimeType": "application/json",
            },
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": api_key,
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                response_payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Gemini API returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Gemini API request failed: {exc.reason}") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Gemini API returned an invalid JSON response") from exc

        text_parts: list[str] = []
        for candidate in response_payload.get("candidates", []):
            for part in candidate.get("content", {}).get("parts", []):
                if isinstance(part.get("text"), str):
                    text_parts.append(part["text"])
        raw = "\n".join(text_parts).strip()
        if not raw:
            raise RuntimeError("Gemini API returned no text candidate")

        usage_meta = response_payload.get("usageMetadata", {})
        usage = TokenUsage(
            input_tokens=int(usage_meta.get("promptTokenCount", 0) or 0),
            output_tokens=int(usage_meta.get("candidatesTokenCount", 0) or 0),
            cached_tokens=int(usage_meta.get("cachedContentTokenCount", 0) or 0),
            reasoning_tokens=int(usage_meta.get("thoughtsTokenCount", 0) or 0),
            total_tokens=int(usage_meta.get("totalTokenCount", 0) or 0),
            measurement_type="provider",
        )
        return raw, self._try_parse_json(raw), usage

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Character-based token estimation (~4 chars/token)."""
        return max(1, len(text) // 4)

    @staticmethod
    def _try_parse_json(text: str) -> Any:
        """Extract and parse JSON object or array from markdown code blocks or text."""
        cleaned = text.strip()
        if "```json" in cleaned:
            parts = cleaned.split("```json")
            if len(parts) > 1:
                cleaned = parts[1].split("```")[0].strip()
        elif "```" in cleaned:
            parts = cleaned.split("```")
            if len(parts) > 1:
                cleaned = parts[1].split("```")[0].strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None

    def _save_raw_response(self, experiment_id: str, req_id: str, response: ModelResponse) -> None:
        raw_dir = self.results_dir / experiment_id / "raw_responses"
        raw_dir.mkdir(parents=True, exist_ok=True)
        out_file = raw_dir / f"{req_id}.json"
        out_file.write_text(json.dumps(response.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    def _record_llm_usage(self, experiment_id: str, response: ModelResponse) -> None:
        exp_dir = self.results_dir / experiment_id
        exp_dir.mkdir(parents=True, exist_ok=True)
        usage_file = exp_dir / "llm_usage.jsonl"

        entry = {
            "request_id": response.request_id,
            "model": response.model,
            "phase": response.phase,
            "agent": response.agent,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "cached_tokens": response.usage.cached_tokens,
            "reasoning_tokens": response.usage.reasoning_tokens,
            "total_tokens": response.usage.total_tokens,
            "latency_seconds": response.latency_seconds,
            "retry_count": response.retry_count,
            "token_measurement": response.usage.measurement_type,
            "is_cached": response.is_cached,
            "error": response.error,
        }

        with self._usage_lock:
            with open(usage_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
