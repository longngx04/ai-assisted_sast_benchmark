# Task 5.1–5.3 — Model Adapter, Instrumentation & Response Cache

| Attribute | Details |
| :--- | :--- |
| **Task ID** | Task 5.1, Task 5.2, Task 5.3 |
| **Title** | Model Adapter, Token/Latency Instrumentation & Response Cache |
| **Status** | ✅ Complete |
| **Phase** | Phase 5: Model Adapter and Instrumentation |
| **Date** | 2026-07-22 |

---

## 1. Objective

The objective of Phase 5 is to implement [harness/model_client.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/model_client.py) and [harness/cache.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/cache.py) — providing a unified, decoupled LLM provider adapter supporting `gemini-2.5-flash` and `mock` modes, raw output persistence, retry/backoff, automatic token & latency instrumentation logging, and SHA-256 response caching.

---

## 2. Implementation Details

### 2.1 Model Adapter (`ModelClient`)
[harness/model_client.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/model_client.py) implements the provider adapter contract:

```python
analyze(
    prompt: str,
    model: str = "gemini-2.5-flash",
    experiment_id: str = "exp-d-optimized",
    phase: str = "investigation",
    agent: str = "primary",
    metadata: dict | None = None,
    timeout_seconds: float = 30.0,
    max_retries: int = 2,
    use_cache: bool = True,
) -> ModelResponse
```

Features:
- **Configurable Provider**: Defaults to `gemini-2.5-flash`. Supports `mock` mode for offline testing and fixture validation.
- **Retry & Exponential Backoff**: Retries failed model API calls up to `max_retries` with exponential backoff delays.
- **Raw Response Persistence**: Every model response is saved to `results/<experiment-id>/raw_responses/<request_id>.json`.
- **Safe JSON Extraction**: Automatically parses JSON code blocks (` ```json ... ``` `) into native dicts/lists without losing raw string text.

### 2.2 Token & Latency Instrumentation
Every model invocation appends an instrumentation record to `results/<experiment-id>/llm_usage.jsonl` matching schema:

```json
{
  "request_id": "req-a1b2c3d4",
  "model": "gemini-2.5-flash",
  "phase": "investigation",
  "agent": "primary",
  "input_tokens": 1250,
  "output_tokens": 210,
  "cached_tokens": 0,
  "reasoning_tokens": 0,
  "total_tokens": 1460,
  "latency_seconds": 1.45,
  "retry_count": 0,
  "token_measurement": "character_estimate",
  "is_cached": false,
  "error": null
}
```

Supported `token_measurement` enum values: `"provider"`, `"tokenizer_estimate"`, `"character_estimate"`, `"mock"`.

### 2.3 File-Based Response Cache (`ModelCache`)
[harness/cache.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/cache.py) implements deterministic caching:
- **Cache Key**: `SHA-256(source_hash : prompt_version : model : analysis_type : context_hash)`.
- **Cache Storage**: Stored as JSON files in `.cache/model_cache/`.
- **Cache Hit**: Reuses previously generated raw & parsed model responses, setting `is_cached = True` and latency to `0.001s`.

---

## 3. Files Created / Modified

- **[harness/model_client.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/model_client.py)** — Provider adapter and usage instrumentation (~240 lines).
- **[harness/cache.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/harness/cache.py)** — Deterministic response caching engine (~85 lines).
- **[tests/test_model_client.py](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/tests/test_model_client.py)** — Unit test suite for caching, mock mode, and instrumentation logging.
- **[reports/phase-5/task-5.1-model-adapter.md](file:///home/longngx04/VinSOC/week%202/AI-assisted_SAST_Bechmark/repo/reports/phase-5/task-5.1-model-adapter.md)** — Phase 5 report (this file).

---

## 4. Test Results

- **Total Test Suite**: 155 tests across all modules
- **Pass Rate**: 100% (155/155 passed)
- **Phase 5 Tests**: `TestModelCache` (cache put/get/clear) and `TestModelClientUnit` (mock invocation, raw output saving, usage logging, cache hit validation).

---

## 5. How to Verify / Test

To run Phase 5 unit tests:

```bash
python3 -m unittest tests.test_model_client -v
```

---

## 6. Status & Conclusion

- **Status**: ✅ Complete
- **Conclusion**: Phase 5 is complete. `ModelClient` and `ModelCache` provide robust LLM orchestration with offline mock fallback, cache reuse, raw response persistence, and token/latency instrumentation logging.
