"""Unit tests for harness.model_client and harness.cache (Phase 5)."""

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from harness.cache import ModelCache
from harness.model_client import ModelClient, ModelResponse, TokenUsage


class TestModelCache(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_cache_put_get_clear(self) -> None:
        cache = ModelCache(cache_dir=self.cache_dir)
        key = cache.generate_cache_key("src_hash", "v1.0", "mock", "investigation", "ctx_hash")

        entry = cache.put(
            cache_key=key,
            model="mock",
            prompt_version="v1.0",
            raw_response="[{\"test\": 1}]",
            parsed_response=[{"test": 1}],
        )
        self.assertEqual(entry.cache_key, key)

        retrieved = cache.get(key)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.raw_response, "[{\"test\": 1}]")

        cleared = cache.clear()
        self.assertEqual(cleared, 1)
        self.assertIsNone(cache.get(key))


class TestModelClientUnit(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.results_dir = Path(self.tmp_dir.name) / "results"
        self.cache_dir = Path(self.tmp_dir.name) / "cache"

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_mock_analyze_call(self) -> None:
        client = ModelClient(
            default_model="mock",
            results_dir=self.results_dir,
            cache_dir=self.cache_dir,
        )

        res = client.analyze(
            prompt="Analyze this SQLi code",
            model="mock",
            experiment_id="exp-test-5",
            phase="investigation",
            metadata={"category": "database", "prompt_version": "v1.0"},
        )

        self.assertIsInstance(res, ModelResponse)
        self.assertFalse(res.is_cached)
        self.assertGreater(res.usage.total_tokens, 0)
        self.assertEqual(res.usage.measurement_type, "mock")
        self.assertIsInstance(res.parsed_json, list)

        # Check raw response file saved
        raw_file = self.results_dir / "exp-test-5" / "raw_responses" / f"{res.request_id}.json"
        self.assertTrue(raw_file.exists())

        # Check llm_usage.jsonl saved
        usage_file = self.results_dir / "exp-test-5" / "llm_usage.jsonl"
        self.assertTrue(usage_file.exists())
        usage_line = json.loads(usage_file.read_text(encoding="utf-8").strip())
        self.assertEqual(usage_line["request_id"], res.request_id)
        self.assertEqual(usage_line["token_measurement"], "mock")

    def test_caching_behavior(self) -> None:
        client = ModelClient(
            default_model="mock",
            results_dir=self.results_dir,
            cache_dir=self.cache_dir,
        )

        prompt = "Identical prompt for cache testing"
        meta = {"prompt_version": "v1.0", "analysis_type": "investigation"}

        res1 = client.analyze(prompt, experiment_id="exp-cache-test", metadata=meta, use_cache=True)
        self.assertFalse(res1.is_cached)

        res2 = client.analyze(prompt, experiment_id="exp-cache-test", metadata=meta, use_cache=True)
        self.assertTrue(res2.is_cached)
        self.assertEqual(res1.raw_response, res2.raw_response)

    def test_gemini_rest_call_uses_provider_usage_and_header_key(self) -> None:
        client = ModelClient(
            default_model="gemini-2.5-flash",
            results_dir=self.results_dir,
            cache_dir=None,
        )
        response_payload = {
            "candidates": [{"content": {"parts": [{"text": '[{"is_vulnerable": false}]'}]}}],
            "usageMetadata": {
                "promptTokenCount": 11,
                "candidatesTokenCount": 4,
                "totalTokenCount": 15,
            },
        }

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(response_payload).encode("utf-8")

        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse()

        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"}, clear=False), patch(
            "urllib.request.urlopen", side_effect=fake_urlopen
        ):
            result = client.analyze(
                "Review this code",
                experiment_id="exp-gemini-test",
                timeout_seconds=17,
                use_cache=False,
            )

        self.assertEqual(result.model, "gemini-2.5-flash")
        self.assertEqual(result.usage.measurement_type, "provider")
        self.assertEqual(result.usage.total_tokens, 15)
        self.assertEqual(captured["timeout"], 17)
        self.assertNotIn("test-key", captured["request"].full_url)
        self.assertEqual(captured["request"].headers["X-goog-api-key"], "test-key")


if __name__ == "__main__":
    unittest.main()
