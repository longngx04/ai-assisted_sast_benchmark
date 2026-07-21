"""Shared scan-exclusion policy.

Tests remain in scope deliberately: WebGoat tests can provide local evidence for
reachability and expected vulnerable behavior.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class ExclusionRule:
    pattern: str
    match: str
    value: str
    category: str
    reason: str


class ExclusionPolicy:
    def __init__(self, rules: list[ExclusionRule], included_paths: list[dict[str, str]] | None = None):
        self.rules = rules
        self.included_paths = included_paths or []

    @classmethod
    def from_file(cls, path: Path) -> "ExclusionPolicy":
        payload = json.loads(path.read_text(encoding="utf-8"))
        rules = [ExclusionRule(**rule) for rule in payload["rules"]]
        return cls(rules, payload.get("included_paths", []))

    def matching_rule(self, path: str | Path) -> ExclusionRule | None:
        normalized = str(path).replace("\\", "/")
        while normalized.startswith("./"):
            normalized = normalized[2:]
        normalized = normalized.lstrip("/")
        pure = PurePosixPath(normalized)
        for rule in self.rules:
            if rule.match == "directory_segment" and rule.value in pure.parts:
                return rule
            if rule.match == "suffix" and normalized.endswith(rule.value):
                return rule
            if rule.match == "path_prefix" and (
                normalized == rule.value.rstrip("/")
                or normalized.startswith(rule.value.rstrip("/") + "/")
            ):
                return rule
        return None

    def should_exclude(self, path: str | Path) -> bool:
        return self.matching_rule(path) is not None

    def manifest_rules(self) -> list[dict[str, str]]:
        return [
            {
                "pattern": rule.pattern,
                "category": rule.category,
                "reason": rule.reason,
            }
            for rule in self.rules
        ]
