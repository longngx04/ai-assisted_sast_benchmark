"""Response caching mechanism for model calls (Micro-task 5.3)."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass
class CacheEntry:
    cache_key: str
    model: str
    prompt_version: str
    raw_response: str
    parsed_response: dict[str, Any] | list[Any] | None
    created_at: str
    metadata: dict[str, Any]


class ModelCache:
    """File-based cache for model outputs.

    Parameters
    ----------
    cache_dir : str | Path
        Directory where cached entries are stored.
    """

    def __init__(self, cache_dir: str | Path = ".cache/model_cache") -> None:
        self.cache_dir = Path(cache_dir).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def generate_cache_key(
        source_hash: str,
        prompt_version: str,
        model: str,
        analysis_type: str,
        context_hash: str,
    ) -> str:
        """Construct a deterministic SHA-256 cache key."""
        raw = f"{source_hash}:{prompt_version}:{model}:{analysis_type}:{context_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> CacheEntry | None:
        """Retrieve a cached entry if it exists."""
        filepath = self.cache_dir / f"{cache_key}.json"
        if not filepath.exists():
            return None
        try:
            payload = json.loads(filepath.read_text(encoding="utf-8"))
            return CacheEntry(**payload)
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def put(
        self,
        cache_key: str,
        model: str,
        prompt_version: str,
        raw_response: str,
        parsed_response: dict[str, Any] | list[Any] | None,
        metadata: dict[str, Any] | None = None,
    ) -> CacheEntry:
        """Store a response in the cache."""
        entry = CacheEntry(
            cache_key=cache_key,
            model=model,
            prompt_version=prompt_version,
            raw_response=raw_response,
            parsed_response=parsed_response,
            created_at=os.getenv("CURRENT_TIME", ""),
            metadata=metadata or {},
        )
        filepath = self.cache_dir / f"{cache_key}.json"
        filepath.write_text(json.dumps(asdict(entry), indent=2, ensure_ascii=False), encoding="utf-8")
        return entry

    def clear(self) -> int:
        """Clear all entries in cache directory. Returns count of deleted files."""
        count = 0
        for f in self.cache_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except OSError:
                pass
        return count
