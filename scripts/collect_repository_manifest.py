#!/usr/bin/env python3
"""Collect reproducible, local metadata for the WebGoat source tree.

The collector is deliberately dependency-free and never contacts the network.  It
uses the local Git checkout (when available) and inspects Maven POMs as text/XML.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

try:
    from harness.exclusions import ExclusionPolicy
except ModuleNotFoundError:  # Support direct execution from outside the project root.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from harness.exclusions import ExclusionPolicy

SOURCE_EXTENSIONS = {".java", ".kt", ".kts", ".groovy", ".xml", ".js", ".ts", ".html", ".css"}
FRAMEWORK_HINTS = {
    "spring": "Spring",
    "spring-boot": "Spring Boot",
    "spring-security": "Spring Security",
    "thymeleaf": "Thymeleaf",
    "hibernate": "Hibernate",
    "junit": "JUnit",
    "selenium": "Selenium",
    "webjars": "WebJars",
}


def _git(root: Path, *args: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True, capture_output=True, text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _line_count(path: Path) -> int:
    try:
        with path.open("rb") as handle:
            return sum(1 for _ in handle)
    except (OSError, UnicodeError):
        return 0


def _pom_metadata(poms: list[Path], root: Path) -> tuple[list[str], list[str], list[dict[str, str]]]:
    modules: list[str] = []
    framework_names: set[str] = set()
    maven_modules: list[dict[str, str]] = []
    for pom in poms:
        try:
            tree = ET.parse(pom)
        except (ET.ParseError, OSError):
            continue
        artifact_ids = []
        # The first direct child artifactId is the project's artifact.  Parent
        # artifactIds are intentionally excluded from the module identity.
        root_tag = tree.getroot()
        direct_artifact = next(
            (child.text.strip() for child in root_tag
             if child.tag.rsplit("}", 1)[-1] == "artifactId" and child.text and child.text.strip()),
            None,
        )
        for element in tree.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            value = (element.text or "").strip()
            if tag == "module" and value:
                module = _relative((pom.parent / value).resolve(), root) if (pom.parent / value).exists() else value
                if module not in modules:
                    modules.append(module)
            if tag == "artifactId" and value:
                artifact_ids.append(value)
            if tag in {"artifactId", "groupId", "name"}:
                lowered = value.lower()
                for hint, name in FRAMEWORK_HINTS.items():
                    if hint in lowered:
                        framework_names.add(name)
        if direct_artifact:
            maven_modules.append({"path": _relative(pom.parent, root), "artifact_id": direct_artifact})
    return sorted(modules), sorted(framework_names), maven_modules


def collect_manifest(root: Path, policy: ExclusionPolicy | None = None) -> dict:
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"source root does not exist or is not a directory: {root}")
    if policy is None:
        policy_path = Path(__file__).resolve().parents[1] / "configs/exclusions.json"
        policy = ExclusionPolicy.from_file(policy_path)

    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and not policy.should_exclude(_relative(path, root)):
            files.append(path)
    files.sort()
    java_files = [p for p in files if p.suffix == ".java"]
    source_files = [p for p in files if p.suffix in SOURCE_EXTENSIONS]
    poms = [p for p in files if p.name == "pom.xml"]
    modules, frameworks, maven_modules = _pom_metadata(poms, root)

    def tree_roots(marker: str) -> list[str]:
        roots: set[str] = set()
        for path in files:
            relative = _relative(path, root)
            marker_index = relative.find(marker)
            if marker_index >= 0:
                prefix = relative[:marker_index].rstrip("/")
                roots.add((prefix + "/" + marker.rstrip("/")) if prefix else marker.rstrip("/"))
        return sorted(roots)

    source_dirs = tree_roots("src/main/")
    test_dirs = tree_roots("src/test/")
    dependency_dirs = sorted({
        _relative(p, root) for p in root.iterdir()
        if p.is_dir() and p.name in {"vendor", "lib", "libs", "dependencies"}
    })
    generated_dirs = sorted({
        _relative(p, root) for p in root.rglob("*")
        if p.is_dir() and p.name in {"generated", "target", "build", "out"}
    })

    extension_counts: dict[str, int] = {}
    for path in source_files:
        extension_counts[path.suffix.lower()] = extension_counts.get(path.suffix.lower(), 0) + 1

    manifest = {
        "manifest_version": "1.0",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repository_name": root.name,
        "repository_root": str(root),
        "revision": _git(root, "rev-parse", "HEAD"),
        "branch": _git(root, "branch", "--show-current"),
        "git_available": _git(root, "rev-parse", "--is-inside-work-tree") == "true",
        "language": {"primary": "Java" if java_files else None, "file_counts": extension_counts},
        "source": {
            "file_count": len(source_files),
            "java_file_count": len(java_files),
            "line_count": sum(_line_count(p) for p in source_files),
        },
        "modules": modules,
        "maven_modules": maven_modules,
        "frameworks": frameworks,
        "paths": {
            "source": source_dirs,
            "tests": test_dirs,
            "dependency": dependency_dirs,
            "generated_or_build": generated_dirs,
        },
        "exclusions": policy.manifest_rules(),
        "explicit_inclusions": policy.included_paths,
        "pom_files": [_relative(p, root) for p in poms],
        "warnings": [] if java_files else ["No Java source files were found under the source root."],
    }
    if manifest["revision"] is None:
        manifest["warnings"].append("Source root is not a Git checkout; revision and branch are null.")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=os.environ.get("WEBGOAT_ROOT", "webgoat/WebGoat-2025.3"), type=Path)
    parser.add_argument("--output", default="results/repository_manifest.json", type=Path)
    parser.add_argument(
        "--exclusions-config",
        default=Path(__file__).resolve().parents[1] / "configs/exclusions.json",
        type=Path,
    )
    args = parser.parse_args()
    try:
        manifest = collect_manifest(args.root, ExclusionPolicy.from_file(args.exclusions_config))
    except (FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.output} ({manifest['source']['java_file_count']} Java files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
